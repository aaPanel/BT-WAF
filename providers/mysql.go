package providers

import (
	"CloudWaf/public"
	"CloudWaf/public/db"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"time"
)

var (
	//go:embed mysql_scripts
	mysqlScriptFs embed.FS
)

func init() {
	mp := &mysqlProvider{}
	registerProvider(mp.CreateDatabases)
	registerProviderCluster(mp.CreateDatabasesForCluster)
}

type mysqlProvider struct{}

func (mp *mysqlProvider) executeScript(conn *db.MySql, filename string) error {
	bs, err := mysqlScriptFs.ReadFile("mysql_scripts/" + filename)
	if err != nil {
		return err
	}
	if _, err = conn.Exec(string(bs), false); err != nil {
		return err
	}

	return nil
}

func (mp *mysqlProvider) runScripts(conn *db.MySql, subPath string) error {
	basePath := ""
	path := "mysql_scripts"
	if subPath != "" {
		basePath = subPath + "/"
		path += "/" + subPath
	}
	files, err := mysqlScriptFs.ReadDir(path)

	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}

		if err := mp.executeScript(conn, basePath+fi.Name()); err != nil {
			_, _ = fmt.Fprintln(buf, "mysql_scripts/"+basePath+fi.Name(), err)
		}
	}
	if buf.Len() > 0 {
		return errors.New(buf.String())
	}
	return nil
}

func (mp *mysqlProvider) CreateDatabases() {
	_, _ = public.MySqlWithClose(func(conn *db.MySql) (res interface{}, err error) {
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

		if err = mp.runScripts(conn, "single"); err != nil {
			return res, err
		}
		if err = mp.CreateChartHelpTable(conn); err != nil {
			return res, err
		}
		files := []string{"create_table_cluster_ssl_email.sql", "create_table_cluster_ssl_info.sql", "create_table_cluster_site_info.sql", "create_table_cluster_site_check.sql"}
		buf := &bytes.Buffer{}
		for _, file := range files {
			if err := mp.executeScript(conn, file); err != nil {
				_, _ = fmt.Fprintln(buf, "mysql_scripts/"+file, err)
			}
			if buf.Len() > 0 {
				return nil, errors.New(buf.String())
			}
		}

		return res, nil

	})
}

func (mp *mysqlProvider) CreateChartHelpTable(conn *db.MySql) error {
	_, err := conn.Exec(`create table if not exists cluster_chart_help (
time_minute int unsigned not null default 0 comment 'Unix时间戳（精确到分钟级别）',
time_ten_minute int unsigned not null default 0 comment 'Unix时间戳（精确到10分钟级别）',
time_half_hour int unsigned not null default 0 comment 'Unix时间戳（精确到半小时级别）',
time_hour int unsigned not null default 0 comment 'Unix时间戳（精确到小时级别）',
time_day int unsigned not null default 0 comment 'Unix时间戳（精确到天级别）',
primary key (time_minute),
index idx_tenMinute (time_ten_minute),
index idx_halfHour (time_half_hour),
index idx_hour (time_hour),
index idx_day (time_day)
) charset=utf8mb4`, false)

	if err != nil {
		return err
	}
	if cnt, err := conn.NewQuery().Table("cluster_chart_help").Count(); err == nil && cnt <= (1440*7) {
		_ = public.AddTaskOnce(func() {

			_, _ = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
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

				size := 1576800 - (1440 * 7)

				chunkSize := 2000
				insertData := make([]map[string]int64, 0, chunkSize*2)
				t, err := public.ParseDateStrToTime("2006-01-02", "2024-01-01")
				if err != nil {
					return
				}
				t = t.Add(7 * 24 * time.Hour)
				query := conn.NewQuery().Table("cluster_chart_help")
				for i := 0; i < size; i++ {
					insertData = append(insertData, map[string]int64{
						"time_minute":     t.Truncate(time.Minute).Unix(),
						"time_ten_minute": t.Truncate(10 * time.Minute).Unix(),
						"time_half_hour":  t.Truncate(30 * time.Minute).Unix(),
						"time_hour":       t.Truncate(time.Hour).Unix(),
						"time_day":        public.ZeroTimestamp(t),
					})
					t = t.Add(time.Minute)
					if i > 0 && i%chunkSize == 0 {
						_, err = query.InsertAll(insertData, db.EXTRA_IGNORE)

						if err != nil {
							return
						}
						insertData = insertData[:0]
					}
				}
				_, err = query.InsertAll(insertData, db.EXTRA_IGNORE)

				if err != nil {
					return
				}

				return nil, nil
			})
		}, 5*time.Minute)
	}
	if !conn.NewQuery().Table("cluster_chart_help").Limit([]int64{1}).Exists() {
		size := 1440 * 7
		chunkSize := 2000
		insertData := make([]map[string]int64, 0, chunkSize*2)
		t := time.Now()
		if err != nil {
			return err
		}
		query := conn.NewQuery().Table("cluster_chart_help")

		for i := 0; i < size; i++ {
			insertData = append(insertData, map[string]int64{
				"time_minute":     t.Truncate(time.Minute).Unix(),
				"time_ten_minute": t.Truncate(10 * time.Minute).Unix(),
				"time_half_hour":  t.Truncate(30 * time.Minute).Unix(),
				"time_hour":       t.Truncate(time.Hour).Unix(),
				"time_day":        public.ZeroTimestamp(t),
			})
			t = t.Add(time.Minute)
			if i > 0 && i%chunkSize == 0 {
				_, err = query.InsertAll(insertData, db.EXTRA_IGNORE)

				if err != nil {
					return err
				}
				insertData = insertData[:0]
			}
		}
		_, err = query.InsertAll(insertData, db.EXTRA_IGNORE)

		if err != nil {
			return err
		}
	}

	return nil
}

func (mp *mysqlProvider) CreateDatabasesForCluster() {
	_, _ = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
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

		if err := mp.runScripts(conn, ""); err != nil {
			return res, err
		}
		if err := mp.CreateChartHelpTable(conn); err != nil {
			return nil, err
		}
		return nil, nil
	})
}
