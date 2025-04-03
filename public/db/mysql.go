package db

import (
	"CloudWaf/core/logging"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type MySql struct {
	Host       string
	Port       int
	UserName   string
	Password   string
	DbName     string
	PreFix     string
	Conn       *sql.DB
	Tx         *sql.Tx
	TxErr      error
	UnixSocket string
}

type MySqlConfig struct {
	Host       string
	Port       int
	UserName   string
	Password   string
	DbName     string
	PreFix     string
	UnixSocket string
}

func NewMySql(mysqlConfig MySqlConfig) (*MySql, error) {
	m := MySql{}
	m.Host = mysqlConfig.Host
	m.Port = mysqlConfig.Port
	m.UserName = mysqlConfig.UserName
	m.Password = mysqlConfig.Password
	m.DbName = mysqlConfig.DbName
	m.PreFix = mysqlConfig.PreFix
	m.UnixSocket = mysqlConfig.UnixSocket
	err := m.Connect()
	if err != nil {
		return nil, err
	}

	_, offset := time.Now().Zone()
	preamble := "+"
	if offset < 0 {
		preamble = "-"
		offset *= -1
	}

	hour := offset / 3600
	minute := (offset % 3600) / 60
	if _, err = m.Exec("SET time_zone = '"+fmt.Sprintf("%s%02d:%02d", preamble, hour, minute)+"'", false); err != nil {
		logging.Error("设置MySQL本地时区失败：", err)
	}

	return &m, nil
}

func (m *MySql) NewQuery() *Query {
	return &Query{
		Conn:   m,
		PreFix: m.PreFix,
	}
}

func (m *MySql) Connect() (err error) {
	var (
		conn *sql.DB
	)
	if m.UnixSocket != "" {
		conn, err = sql.Open("mysql", m.UserName+":"+m.Password+"@unix("+m.UnixSocket+")/"+m.DbName+"?charset=utf8mb4,utf8&collation=utf8mb4_general_ci&multiStatements=true")
	} else {
		conn, err = sql.Open("mysql", m.UserName+":"+m.Password+"@tcp("+m.Host+":"+strconv.Itoa(m.Port)+")/"+m.DbName+"?charset=utf8mb4,utf8&collation=utf8mb4_general_ci&multiStatements=true")
	}
	if err == nil {
		m.Conn = conn
	}

	return err
}

func (m *MySql) Close() {
	m.Conn.Close()
}

func (m *MySql) SetHost(host string, port int) {
	m.Host = host
	m.Port = port
}

func (m *MySql) Begin() (*sql.Tx, error) {
	if m.Tx != nil {
		return m.Tx, errors.New("当前事务未结束")
	}
	m.Tx, m.TxErr = m.Conn.Begin()
	return m.Tx, m.TxErr
}

func (m *MySql) Rollback() error {
	if m.Tx == nil {
		return errors.New("事务未开启")
	}

	err := m.Tx.Rollback()
	m.Tx = nil
	m.TxErr = nil
	return err
}

func (m *MySql) Commit() error {
	if m.Tx == nil {
		return errors.New("事务未开启")
	}

	err := m.Tx.Commit()
	m.Tx = nil
	m.TxErr = nil
	return err
}

func (m *MySql) Query(rawSql string, param ...interface{}) ([]map[string]interface{}, error) {

	err := m.checkParam(rawSql, param)
	if err != nil {
		return nil, err
	}

	var rows *sql.Rows
	if m.Tx != nil {
		rows, err = m.Tx.Query(rawSql, param...)
	} else {
		rows, err = m.Conn.Query(rawSql, param...)
	}

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	count := len(columns)
	values := make([]interface{}, count)
	valuePtrs := make([]interface{}, count)
	valueTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		valuePtrs[i] = &values[i]
	}
	result := make([]map[string]interface{}, 0, 256)
	for rows.Next() {
		if err = rows.Scan(valuePtrs...); err != nil {
			continue
		}
		row := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]

			b, ok := val.([]byte)
			if ok {
				v = string(b)

				switch valueTypes[i].DatabaseTypeName() {
				case "INT", "TINYINT", "SMALLINT", "MEDIUMINT", "BIGINT", "UNSIGNED INT", "UNSIGNED TINYINT", "UNSIGNED SMALLINT", "UNSIGNED MEDIUMINT", "UNSIGNED BIGINT":
					v, err = strconv.Atoi(string(b))
					if err != nil {
						v = string(b)
					}
				case "DECIMAL":
					_, bitSize, ok := valueTypes[i].DecimalSize()
					if ok {
						v, err = strconv.ParseFloat(string(b), int(bitSize))
						if err != nil {
							v = string(b)
						}
					}
				case "BOOL":
					switch v {
					case "\x00":
						v = false
					case "\x01":
						v = true
					default:
						v = false
					}
				}
			} else {
				v = val
			}

			row[col] = v
		}

		result = append(result, row)
	}
	return result, nil
}

func (m *MySql) Exec(rawSql string, getRowId bool, param ...interface{}) (int64, error) {

	err := m.checkParam(rawSql, param)
	if err != nil {
		return 0, err
	}

	var res sql.Result
	if m.Tx != nil {
		res, err = m.Tx.Exec(rawSql, param...)
	} else {
		res, err = m.Conn.Exec(rawSql, param...)
	}

	if err != nil {
		return 0, err
	}
	if getRowId {
		return res.LastInsertId()
	}
	return res.RowsAffected()
}

func (m *MySql) checkParam(sql string, param []interface{}) error {
	sqlCount := strings.Count(sql, "?")
	paramCount := len(param)

	if sqlCount != paramCount {
		return errors.New("参数数量不匹配，要求绑定" + strconv.Itoa(sqlCount) + "个参数，实际绑定" + strconv.Itoa(paramCount) + "个参数")
	}
	return nil
}
