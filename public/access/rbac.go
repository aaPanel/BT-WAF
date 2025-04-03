package access

import (
	"CloudWaf/core"
	"CloudWaf/core/common"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	accessNodeFile = core.AbsPath("./public/access/.access-node.json")
	//go:embed .access-node.json
	accessNodeText []byte
	RbacManager    = &Rbac{}
)

func init() {
	RbacManager.init()
}

type NodeItem struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Uri  string `json:"uri"`
}

type Node struct {
	Id     int        `json:"id"`
	Name   string     `json:"name"`
	Module string     `json:"module"`
	Read   []NodeItem `json:"read"`
	Write  []NodeItem `json:"write"`
}

type Rbac struct{}

type RoleItem struct {
	Id         int    `json:"id"`
	Name       string `json:"name"`
	CreateTime int    `json:"create_time"`
}

type UserItem struct {
	Id            int    `json:"id"`
	Username      string `json:"username"`
	CreateTime    int    `json:"create_time"`
	PwdUpdateTime int    `json:"pwd_update_time"`
}

type UserSecretItem struct {
	Id            int    `json:"id"`
	Password      string `json:"password"`
	Salt          string `json:"salt"`
	Md5Password   string `json:"md5_password"`
	PwdUpdateTime int64  `json:"pwd_update_time"`
}

func (acc *Rbac) init() error {
	nodeList := make([]Node, 0)

	if err := json.Unmarshal(accessNodeText, &nodeList); err != nil {
		return err
	}

	nodeLength := len(nodeList)
	maxId := nodeList[nodeLength-1].Id
	oldMaxId := maxId
	for i := range nodeList[:nodeLength-1] {
		node := &nodeList[i]

		if node.Id == 0 {
			maxId++
			node.Id = maxId
		}
		for j := range node.Read {
			nodeItem := &node.Read[j]

			if nodeItem.Id == 0 {
				maxId++
				nodeItem.Id = maxId
			}
		}
		for j := range node.Write {
			nodeItem := &node.Write[j]

			if nodeItem.Id == 0 {
				maxId++
				nodeItem.Id = maxId
			}
		}
	}

	nodeList[nodeLength-1].Id = maxId
	defer acc.updateDatabase(nodeList)

	if maxId == oldMaxId {
		return nil
	}
	if _, err := os.Stat(accessNodeFile); err == nil {
		bs, err := json.MarshalIndent(nodeList, "", "    ")

		if err != nil {
			return err
		}

		if err := os.WriteFile(accessNodeFile, bs, 0644); err != nil {
			return err
		}
	}

	return nil
}

func (acc *Rbac) updateDatabase(nodeList []Node) {
	public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
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
create table if not exists bt_access_node (
    id integer primary key autoincrement, -- 主键
    pid	integer not null default 0, -- 上级ID
    type integer not null default 0, -- 节点类型 0-模块 1-查看权限 2-编辑权限
    name text not null default '', -- 节点名称
    uri text not null default '' -- URI
);
`, false)

		if err != nil {
			return nil, err
		}
		nodeLength := len(nodeList)
		sql := make([]string, 0)
		for i := range nodeList[:nodeLength-1] {
			node := &nodeList[i]

			tmp := []string{
				strconv.Itoa(node.Id),
				"0",
				"0",
				"'" + node.Name + "'",
				"'/api/" + common.SnakeCase(strings.TrimLeft(node.Module, "/")) + "'",
			}

			sql = append(sql, "("+strings.Join(tmp, ", ")+")")
			for j := range node.Read {
				nodeItem := &node.Read[j]

				tmp = []string{
					strconv.Itoa(nodeItem.Id),
					strconv.Itoa(node.Id),
					"1",
					"'" + nodeItem.Name + "'",
					"'/api/" + common.SnakeCase(strings.TrimLeft(nodeItem.Uri, "/")) + "'",
				}

				sql = append(sql, "("+strings.Join(tmp, ", ")+")")
			}
			for j := range node.Write {
				nodeItem := &node.Write[j]

				tmp = []string{
					strconv.Itoa(nodeItem.Id),
					strconv.Itoa(node.Id),
					"2",
					"'" + nodeItem.Name + "'",
					"'/api/" + common.SnakeCase(strings.TrimLeft(nodeItem.Uri, "/")) + "'",
				}

				sql = append(sql, "("+strings.Join(tmp, ", ")+")")
			}
		}
		_, err = conn.Exec("REPLACE INTO `bt_access_node` (`id`, `pid`, `type`, `name`, `uri`) VALUES "+strings.Join(sql, ", "), false)
		if err != nil {
			return nil, err
		}
		return nil, conn.Commit()
	})
}

func (acc *Rbac) IsAllowed(uid int, uri string) bool {
	uri = strings.TrimSpace(uri)
	if len(uri) < 5 || !strings.EqualFold(uri[:5], "/api/") {
		return true
	}
	if uid < 2 {
		return true
	}
	uri = common.SnakeCase(uri)
	res := struct {
		Id int `json:"id"`
	}{}

	err := public.S("access_node").
		Where("uri like ?", []any{uri + "%"}).
		Field([]string{"id"}).
		FindAs(&res)

	if err != nil || res.Id == 0 {
		return true
	}

	err = public.S("access_node a").
		Join("left", "role_node b", "a.id=b.node_id", []any{}).
		Join("left", "user_role c", "c.role_id=b.role_id", []any{}).
		Where("c.uid = ?", []any{uid}).
		Where("a.uri like ?", []any{uri + "%"}).
		Field([]string{"a.id"}).
		FindAs(&res)

	if err != nil || res.Id == 0 {
		return false
	}

	return true
}

func (acc *Rbac) List(uid int) []Node {
	res := make([]Node, 0)

	queryResult := make([]struct {
		Id   int    `json:"id"`
		Pid  int    `json:"pid"`
		Name string `json:"name"`
		Type int    `json:"type"`
		Uri  string `json:"uri"`
	}, 0)

	query := public.S("access_node").
		Field([]string{"id", "pid", "name", "type", "uri"}).
		Order("id", "asc")

	if uid > 1 {
		nodeIds := make([]string, 0)

		err := public.S("role_node m").
			Join("left", "user_role r", "r.role_id=m.role_id", []any{}).
			Where("r.uid = ?", []any{uid}).
			Field([]string{"distinct m.node_id"}).
			ColumnAs("node_id", &nodeIds)

		if err != nil {
			return res
		}

		allNode := false

		for _, nodeId := range nodeIds {
			if nodeId == "0" {
				allNode = true
				break
			}
		}

		if !allNode {
			query.WhereNest(func(q *db.Query) {
				q.WhereIn("id", nodeIds).
					WhereInOr("pid", nodeIds)
			})
		}
	}

	err := query.SelectAs(&queryResult)

	if err != nil {
		return res
	}

	d := make(map[int]*Node)
	rk := make([]int, 0)

	for i := range queryResult {
		item := &queryResult[i]

		if item.Pid == 0 {
			d[item.Id] = &Node{
				Id:   item.Id,
				Name: item.Name,
			}
			rk = append(rk, item.Id)
			continue
		}

		if v, ok := d[item.Pid]; ok {
			nodeItem := NodeItem{
				Id:   item.Id,
				Name: item.Name,
			}
			switch item.Type {
			case 1:
				v.Read = append(v.Read, nodeItem)
			case 2:
				v.Write = append(v.Write, nodeItem)
			}
		}
	}

	for _, k := range rk {
		res = append(res, *d[k])
	}

	return res
}

func (acc *Rbac) CreateUser(username, passwd string) error {
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
		salt := public.RandomStr(20)
		md5Passwd, err := public.StringMd5WithSalt(passwd, salt)
		if err != nil {
			return nil, err
		}
		id, err := conn.NewQuery().
			Table("users").
			Insert(map[string]interface{}{
				"username":    username,
				"md5_passwd":  md5Passwd,
				"salt":        salt,
				"create_time": time.Now().Unix(),
			})

		if err != nil {
			return nil, err
		}

		if id == 0 {
			return nil, errors.New("创建用户失败: 用户已存在")
		}

		return nil, nil
	})

	return err
}

func (acc *Rbac) UserList(uid int) (res []UserItem) {
	query := public.S("users u").
		Field([]string{"u.id", "u.username", "u.create_time", "u.pwd_update_time"})

	if uid > 1 {
		query.Where("u.id = ?", []any{uid})
	}
	if err := query.SelectAs(&res); err != nil {
		logging.Info("获取用户列表失败: ", err)
	}

	return res
}

func (acc *Rbac) UpdateUser(userItem UserItem) error {
	if userItem.Id < 1 {
		return errors.New("缺少UID")
	}
	updateData := common.StructToMap(userItem)
	delete(updateData, "pwd_update_time")
	_, err := public.S("users").
		Where("id", []any{userItem.Id}).
		Update(updateData)

	return err
}

func (acc *Rbac) UpdatePassword(userItem UserSecretItem) (err error) {
	if userItem.Id < 1 {
		return errors.New("缺少UID")
	}
	userItem.Password = strings.TrimSpace(userItem.Password)
	if userItem.Password == "" {
		return errors.New("密码不能为空")
	}
	if !public.IsComplexPassword(userItem.Password) {
		return errors.New("密码强度不够，请保证密码长度大于8位、包含大小写字母、特殊字符")
	}
	err = public.S("users").
		Where("id", []any{userItem.Id}).
		Field([]string{"salt"}).
		FindAs(&userItem)

	if err != nil {
		return err
	}
	userItem.Md5Password, err = public.StringMd5WithSalt(userItem.Password, userItem.Salt)
	if err != nil {
		return err
	}

	userItem.PwdUpdateTime = time.Now().Unix()

	_, err = public.S("users").
		Where("id", []any{userItem.Id}).
		Update(userItem)

	return err
}

func (acc *Rbac) RemoveUser(uids ...int) error {
	public.S("users").
		WhereIn("id", uids).
		Delete()

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
			Table("users").
			WhereIn("id", uids).
			Delete()

		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().
			Table("logs").
			WhereIn("uid", uids).
			Delete()

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}

func (acc *Rbac) RoleList(uid int) (res []RoleItem) {
	if uid > 1 {
		return res
	}

	err := public.S("role").
		Field([]string{"id", "name", "create_time"}).
		SelectAs(&res)

	if err != nil {
		logging.Info("获取用户组列表失败: ", err)
	}

	return res
}

func (acc *Rbac) CreateRole(roleName string) error {
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
		roleExists := conn.NewQuery().
			Table("role").
			Where("name = ?", []any{roleName}).
			Exists()

		if roleExists {
			return nil, errors.New("创建用户失败: 用户组【" + roleName + "】已存在")
		}
		_, err = conn.NewQuery().
			Table("role").
			Insert(map[string]interface{}{
				"name":        roleName,
				"create_time": time.Now().Unix(),
			})

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}

func (acc *Rbac) UpdateRole(roleItem RoleItem) error {
	if roleItem.Id == 0 {
		return errors.New("用户组不存在")
	}
	_, err := public.S("role").
		Where("id = ?", []any{roleItem.Id}).
		Update(roleItem)

	return err
}

func (acc *Rbac) RemoveRole(roleIds ...int) error {
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
		_, err = public.S("role").
			WhereIn("id", roleIds).
			Delete()

		if err != nil {
			return nil, err
		}
		_, err = public.S("role_node").
			WhereIn("role_id", roleIds).
			Delete()

		if err != nil {
			return nil, err
		}
		_, err = public.S("user_role").
			WhereIn("role_id", roleIds).
			Delete()

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}

func (acc *Rbac) UpdateUserRole(uid int, roleIds []int) error {
	if uid < 2 {
		return nil
	}

	if len(roleIds) == 0 {
		return errors.New("用户组不能为空")
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
			Table("user_role").
			Where("uid", []any{uid}).
			Delete()

		if err != nil {
			return nil, err
		}

		insertData := make([]map[string]any, 0)

		for _, v := range roleIds {
			insertData = append(insertData, map[string]any{
				"uid":     uid,
				"role_id": v,
			})
		}

		_, err = conn.NewQuery().
			Table("user_role").
			InsertAll(insertData, db.EXTRA_IGNORE)

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}

func (acc *Rbac) UpdateRoleNode(roleId int, nodeIds []int) error {
	if roleId < 1 {
		return errors.New("用户组ID错误")
	}

	if len(nodeIds) == 0 {
		return errors.New("权限不能为空")
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
			Table("role_node").
			Where("role_id", []any{roleId}).
			Delete()

		if err != nil {
			return nil, err
		}

		insertData := make([]map[string]any, 0)

		for _, v := range nodeIds {
			insertData = append(insertData, map[string]any{
				"role_id": roleId,
				"node_id": v,
			})
		}

		_, err = conn.NewQuery().
			Table("role_node").
			InsertAll(insertData, db.EXTRA_IGNORE)

		if err != nil {
			return nil, err
		}

		return nil, nil
	})

	return err
}
