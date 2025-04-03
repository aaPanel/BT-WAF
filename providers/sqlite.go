package providers

import (
	"CloudWaf/public"
	"CloudWaf/public/db"
	"bytes"
	"embed"
	"errors"
	"fmt"
)

var (
	//go:embed sqlite_scripts
	sqliteScriptFs embed.FS
)

func init() {
	sp := &sqliteProvider{}
	sp.CreateDatabases()
}

type sqliteProvider struct{}

func (sp *sqliteProvider) executeScript(conn *db.Sqlite, filename string) error {
	bs, err := sqliteScriptFs.ReadFile("sqlite_scripts/" + filename)

	if err != nil {
		return err
	}
	if _, err = conn.Exec(string(bs), false); err != nil {
		return err
	}

	return nil
}

func (sp *sqliteProvider) runScripts(conn *db.Sqlite) error {
	files, err := sqliteScriptFs.ReadDir("sqlite_scripts")

	if err != nil {
		return err
	}

	buf := &bytes.Buffer{}

	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		if err := sp.executeScript(conn, fi.Name()); err != nil {
			_, _ = fmt.Fprintln(buf, "sqlite_scripts/"+fi.Name(), err)
		}
	}

	if buf.Len() > 0 {
		return errors.New(buf.String())
	}

	return nil
}

func (sp *sqliteProvider) createTableLogs(db *db.Sqlite) error {
	if err := sp.executeScript(db, "create_table_logs.sql"); err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createTableUsers(db *db.Sqlite) error {

	_, err := db.Exec(`create table if not exists bt_users (
    id integer primary key autoincrement, -- 主键ID
	username text not null default 'admin', -- 用户名
    salt text not null default '', -- 盐
	md5_passwd text not null default '', -- 加盐的md5密码
    create_time integer not null default (strftime('%s')), -- 创建时间
    pwd_update_time integer not null default (strftime('%s')) -- 密码更新时间
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec("create index if not exists `users_userName_salt_md5Passwd` on `bt_users` (`username`, `salt`, `md5_passwd`)", false)

	if err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createExclusiveConfig(db *db.Sqlite) error {

	_, err := db.Exec(`create table if not exists bt_exclusive_config (
   	id integer primary key autoincrement, -- 主键ID
	site_id integer not null default 0, -- 网站ID  唯一
	status integer not null default 1, -- 规则状态
   	rule_name text default '' -- 规则名称
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec("create unique index if not exists `ExclusiveConfig_siteId_ruleName` on `bt_exclusive_config` (`site_id`, `rule_name`)", false)
	if err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createRegionFreeTables(db *db.Sqlite) (err error) {
	_, err = db.Exec(`
create table if not exists bt_region_free (
    id integer primary key autoincrement, -- 表自增ID
    site_id text not null default '', -- 网站id
	label text not null default '', -- 标记  overseas:海外 
	create_time integer not null default (strftime('%s')) -- 添加时间
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`create index if not exists regionInfo_regionSiteId_regionLabel on bt_region_free (site_id, label)`, false)

	if err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createTableCCLog(db *db.Sqlite) error {

	_, err := db.Exec(`create table if not exists bt_cc_log (
   	id integer primary key autoincrement, -- 主键ID
   	servername text not null default '', -- 被攻击的域名
   	uri text not null default '', -- 不带参数的的url
   	host text not null default '', -- 被攻击的host
	create_time integer not null default (strftime('%s')), -- 开始时间戳
	update_time integer not null default (strftime('%s')), -- 结束时间戳
	max_id integer not null default 0, -- 上次记录最大id
	status integer not null default 1 -- 状态(0-已结束   1-cc记录中)

)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec("create index if not exists `CCLog_status_servername_uri_maxId` on `bt_cc_log` (`status`, `servername`, `uri`, `max_id`)", false)

	if err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createTableCCIpLog(db *db.Sqlite) error {
	_, err := db.Exec(`create table if not exists bt_cc_ip_log (
   	id integer primary key autoincrement, -- 主键ID
   	cc_id integer not null default 0, -- cc事件id
   	request integer not null default 0, -- 攻击次数
   	ip_type integer not null default 0, -- 攻击类型  0-ipv4  1-ipv6
   	create_time integer not null default (strftime('%s')), -- ip 记录时间
   	ip text not null default '', -- 攻击ip
   	country text not null default '', -- 国家
   	province text not null default '', -- 省份
   	city text not null default '' -- 城市
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE 'bt_cc_ip_log' ADD 'ip_type' integer default 0", false)
	if err != nil {
	}
	_, err = db.Exec("ALTER TABLE 'bt_cc_ip_log' ADD 'create_time' integer not null default 0", false)
	if err != nil {
	}

	_, err = db.Exec("create index if not exists `CCIpLog_ccId_ip` on `bt_cc_ip_log` (`cc_id`, `ip`)", false)

	if err != nil {
		return err
	}
	return nil
}

func (sp *sqliteProvider) createRbacTables(db *db.Sqlite) (err error) {
	_, err = db.Exec(`
create table if not exists bt_role (
    id integer primary key autoincrement, -- 用户组ID
    name text not null default '', -- 用户组名称
    create_time integer not null default (strftime('%s')) -- 添加时间
)
`, false)

	if err != nil {
		return err
	}

	_, err = db.Exec(`create index if not exists role_name_createTime on bt_role (name, create_time)`, false)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
create table if not exists bt_user_role (
    uid integer not null default 0, -- 用户ID
    role_id integer not null default 0 -- 用户组ID
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`
create table if not exists bt_role_node (
    role_id integer not null default 0, -- 用户组ID
    node_id integer not null default 0 -- 权限节点ID
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`create unique index if not exists roleNode_roleId_nodeId on bt_role_node (role_id, node_id)`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`
create table if not exists bt_role_menu (
    role_id integer not null default 0, -- 用户组ID
    menu_id integer not null default 0 -- 菜单ID 0-表示全部菜单
)
`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`create unique index if not exists roleMenu_roleId_menuId on bt_role_menu (role_id, menu_id)`, false)

	if err != nil {
		return err
	}
	_, err = db.Exec(`
create table if not exists bt_role_website (
    role_id integer not null default 0, -- 用户组ID
    site_id integer not null default 0, -- 网站ID(冗余) 0-表示所有网站
    site_id_text text not null default '' -- 网站ID ''-表示所有网站
)
`, false)

	if err != nil {
		return err
	}

	_, err = db.Exec(`create unique index if not exists roleWebsite_roleId_siteId on bt_role_website (role_id, site_id)`, false)

	if err != nil {
		return err
	}

	_, err = db.Exec(`create unique index if not exists roleWebsite_roleId_siteIdText on bt_role_website (role_id, site_id_text)`, false)

	if err != nil {
		return err
	}

	return nil
}

func (sp *sqliteProvider) createCustomizeTables(db *db.Sqlite) (err error) {
	if err = sp.executeScript(db, "create_table_customize.sql"); err != nil {
		return err
	}
	_, _ = db.Exec("alter table `bt_customize_rules` add column `src` integer not null default 0", false)

	return nil
}

func (sp *sqliteProvider) CreateDatabases() {
	public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
		_, err = conn.Exec("PRAGMA journal_mode=wal", false)

		if err != nil {
			return nil, err
		}
		_, err = conn.Exec("PRAGMA synchronous=0", false)
		if err != nil {
			return nil, err
		}
		if _, err = conn.Begin(); err != nil {
			return nil, err
		}

		defer func() {
			if err != nil {
				_ = conn.Rollback()
				return
			}
			_ = conn.Commit()
		}()
		err = sp.createTableLogs(conn)
		if err != nil {
			return nil, err
		}
		err = sp.createTableUsers(conn)
		if err != nil {
			return nil, err
		}
		err = sp.createExclusiveConfig(conn)
		if err != nil {
			return nil, err
		}
		err = sp.createTableCCLog(conn)
		if err != nil {
			return nil, err
		}
		err = sp.createTableCCIpLog(conn)
		if err != nil {
			return nil, err
		}
		if err = sp.createCustomizeTables(conn); err != nil {
			return nil, err
		}
		if err = sp.createRegionFreeTables(conn); err != nil {
			return nil, err
		}
		if err := sp.runScripts(conn); err != nil {
			return res, err
		}

		return nil, nil
	})
}
