package access

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
)

var (
	menuFile = core.AbsPath("./public/access/.menu.json")
	//go:embed .menu.json
	menuText       []byte
	MenuManager    = &Menu{}
	WebsiteManager = &Website{}
)

func init() {
	if err := MenuManager.init(); err != nil {
		logging.Info("初始化菜单资产失败：", err)
	}
	if err := WebsiteManager.init(); err != nil {
		logging.Info("初始化网站资产失败：", err)
	}
}

type MenuItem struct {
	Id     int        `json:"id"`
	Name   string     `json:"name"`
	Uri    string     `json:"uri"`
	Child  []MenuItem `json:"child"`
	parent *MenuItem
}

type MenuItemForUser struct {
	Id     int                `json:"id"`
	Name   string             `json:"name"`
	Uri    string             `json:"uri"`
	Child  []*MenuItemForUser `json:"child"`
	Pid    int                `json:"pid"`
	Sort   int                `json:"sort"`
	Status int                `json:"status"`
}

type Menu struct{}

type Website struct{}

type WebsiteItem struct {
	Id     int    `json:"id"`
	IdText string `json:"id_text"`
	Name   string `json:"name"`
}

func (m *Menu) init() error {
	menuList := make([]MenuItem, 0)

	if err := json.Unmarshal(menuText, &menuList); err != nil {
		return err
	}
	menuLength := len(menuList)
	maxId := menuList[menuLength-1].Id

	oldMaxId := maxId
	m.walk(menuList[:menuLength-1], func(item *MenuItem) {
		if item.Id == 0 {
			maxId++
			item.Id = maxId
		}
	}, nil)

	menuList[menuLength-1].Id = maxId
	defer m.updateDatabase(menuList)
	if maxId == oldMaxId {
		return nil
	}
	if _, err := os.Stat(menuFile); err == nil {
		bs, err := json.MarshalIndent(menuList, "", "    ")

		if err != nil {
			return err
		}

		if err := os.WriteFile(menuFile, bs, 0644); err != nil {
			return err
		}
	}

	return nil
}

func (m *Menu) walk(menu []MenuItem, handler func(item *MenuItem), parentNode *MenuItem) {
	for i := range menu {
		v := &menu[i]
		v.parent = parentNode
		handler(v)
		if len(v.Child) > 0 {
			m.walk(v.Child, handler, v)
		}
	}
}

func (m *Menu) updateDatabase(menu []MenuItem) {
	public.SqliteWithClose(func(conn *db.Sqlite) (res interface{}, err error) {
		if _, err = conn.Begin(); err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
		}()
		_, err = conn.Exec(`
create table if not exists bt_menu (
    id integer primary key autoincrement, -- 主键
    pid	integer not null default 0, -- 上级ID
    name text not null default '', -- 菜单名称
    uri text not null default '', -- URI
    sort integer not null default 0, -- 排序
    status integer not null default 1 -- 菜单状态 0-隐藏 1-显示
);
`, false)

		if err != nil {
			return nil, err
		}

		type menuItem struct {
			MenuItem
			Sort   int `json:"sort"`
			Status int `json:"status"`
		}

		menus := make([]menuItem, 0)
		err = conn.NewQuery().
			Table("menu").
			Field([]string{"id", "pid", "sort", "status"}).
			SelectAs(&menus)

		if err != nil {
			return nil, err
		}

		dict := make(map[int]menuItem)

		for _, v := range menus {
			dict[v.Id] = v
		}

		sql := make([]string, 0)

		m.walk(menu[:len(menu)-1], func(item *MenuItem) {
			pid := 0

			if item.parent != nil {
				pid = item.parent.Id
			}

			sort := 0
			status := 1

			if v, ok := dict[item.Id]; ok {
				sort = v.Sort
				status = v.Status
			}

			tmp := []string{
				strconv.Itoa(item.Id),
				strconv.Itoa(pid),
				"'" + item.Name + "'",
				"'" + item.Uri + "'",
				strconv.Itoa(sort),
				strconv.Itoa(status),
			}

			sql = append(sql, "("+strings.Join(tmp, ", ")+")")
		}, nil)
		_, err = conn.Exec("REPLACE INTO `bt_menu` (`id`, `pid`, `name`, `uri`, `sort`, `status`) VALUES "+strings.Join(sql, ", "), false)
		if err != nil {
			return nil, err
		}
		return nil, conn.Commit()
	})
}

func (m *Menu) List(uid int) (res []MenuItemForUser) {
	queryResult := make([]MenuItemForUser, 0)
	query := public.S("menu").
		Field([]string{"id", "pid", "name", "uri", "sort", "status"}).
		Order("sort", "desc").
		Order("id", "asc")

	if uid > 1 {
		query.Where("status", []any{1})

		menuIds := make([]string, 0)

		err := public.S("role_menu m").
			Join("left", "user_role r", "r.role_id=m.role_id", []any{}).
			Where("r.uid = ?", []any{uid}).
			Field([]string{"distinct m.menu_id"}).
			ColumnAs("menu_id", &menuIds)

		if err != nil {
			return res
		}

		allMenu := false

		for _, menuId := range menuIds {
			if menuId == "0" {
				allMenu = true
				break
			}
		}

		if !allMenu {
			query.WhereNest(func(q *db.Query) {
				q.WhereIn("id", menuIds).
					WhereInOr("pid", menuIds)
			})

		}
	}

	err := query.SelectAs(&queryResult)

	if err != nil {
		return res
	}

	d := make(map[int]*MenuItemForUser)
	rk := make([]int, 0)

	for i := range queryResult {
		item := &queryResult[i]
		d[item.Id] = item

		if item.Pid == 0 {
			rk = append(rk, item.Id)
		}
	}

	for i := range queryResult {
		item := &queryResult[i]
		if v, ok := d[item.Pid]; item.Pid > 0 && ok {
			v.Child = append(v.Child, item)
		}
	}

	for _, k := range rk {
		res = append(res, *d[k])
	}

	return res
}

func (m *Menu) Update(roleId int, menuIdList []int) error {
	if roleId < 1 {
		return errors.New("用户组ID错误")
	}

	d := make(map[int]struct{})

	for _, v := range menuIdList {
		d[v] = struct{}{}
	}

	_, err := public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		if _, err = conn.Begin(); err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().
			Table("role_menu").
			Where("role_id = ?", []any{roleId}).
			Delete()

		if err != nil {
			return nil, err
		}

		insertData := make([]map[string]any, 0)

		for k := range d {
			insertData = append(insertData, map[string]any{
				"role_id": roleId,
				"menu_id": k,
			})
		}

		_, err = conn.NewQuery().
			Table("role_menu").
			InsertAll(insertData)

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}

func (w *Website) init() error {
	return nil
}

func (w *Website) AvailableSiteIdText(uid int) map[string]struct{} {
	res := make(map[string]struct{})

	bs, err := os.ReadFile(public.SiteIdPath)

	if err != nil {
		return res
	}

	data := make(map[string]string)

	if err = json.Unmarshal(bs, &data); err != nil {
		return res
	}

	if uid > 1 {
		queryResult := make([]string, 0)

		err = public.S("role_website w").
			Join("left", "user_role r", "r.role_id=w.role_id", []any{}).
			Where("r.uid = ?", []any{uid}).
			Field([]string{"distinct w.site_id_text"}).
			ColumnAs("site_id_text", &queryResult)

		if err != nil {
			return res
		}

		m := make(map[string]string)

		for _, v := range queryResult {
			if _, ok := data[v]; ok {
				m[v] = v
			}
		}

		data = m
	}

	for k := range data {
		res[k] = struct{}{}
	}

	return res
}

func (w *Website) List(uid int) (res []WebsiteItem) {
	siteIdTextList := w.AvailableSiteIdText(uid)
	for k := range siteIdTextList {
		siteName, err := public.GetSiteNameBySiteId(k)

		if err != nil {
			continue
		}

		res = append(res, WebsiteItem{
			IdText: k,
			Name:   siteName,
		})
	}

	return res
}

func (w *Website) Update(roleId int, websiteList []WebsiteItem) error {
	if roleId < 1 {
		return errors.New("用户组ID错误")
	}

	m := make(map[string]struct{})

	for _, v := range websiteList {
		m[v.IdText] = struct{}{}
	}

	_, err := public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		if _, err = conn.Begin(); err != nil {
			return nil, err
		}

		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().
			Table("role_website").
			Where("role_id = ?", []any{roleId}).
			Delete()

		if err != nil {
			return nil, err
		}

		insertData := make([]map[string]any, 0)

		for k := range m {
			insertData = append(insertData, map[string]any{
				"role_id":      roleId,
				"site_id_text": k,
			})
		}

		_, err = conn.NewQuery().
			Table("role_website").
			InsertAll(insertData)

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}
