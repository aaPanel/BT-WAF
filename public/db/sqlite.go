package db

import (
	"database/sql"
	"errors"
	"os"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

type Sqlite struct {
	DbFile string
	PreFix string
	Conn   *sql.DB
	Tx     *sql.Tx
	TxErr  error
}

func NewSqlite(DbFile string, PreFix string) (*Sqlite, error) {
	s := &Sqlite{}
	s.DbFile = DbFile
	s.PreFix = PreFix
	err := s.Connect()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Sqlite) NewQuery() *Query {
	return &Query{
		Conn:   s,
		PreFix: s.PreFix,
	}
}

func (s *Sqlite) Connect() error {
	conn, err := sql.Open("sqlite", s.DbFile)
	if err == nil {
		s.Conn = conn
	}
	return err
}

func (s *Sqlite) Close() {
	s.Conn.Close()
}

func (s *Sqlite) SetDbFile(DbFile string) error {
	_, err := os.Stat(DbFile)

	if err != nil {
		return errors.New("错误：指定数据库文件 " + DbFile + " 不存在")
	}

	s.DbFile = DbFile

	return nil
}

func (s *Sqlite) Begin() (*sql.Tx, error) {
	if s.Tx != nil {
		return s.Tx, errors.New("当前事务未结束")
	}

	s.Tx, s.TxErr = s.Conn.Begin()
	return s.Tx, s.TxErr
}

func (s *Sqlite) Rollback() error {
	if s.Tx == nil {
		return errors.New("事务未开启")
	}

	err := s.Tx.Rollback()
	s.Tx = nil
	s.TxErr = nil
	return err
}

func (s *Sqlite) Commit() error {
	if s.Tx == nil {
		return errors.New("事务未开启")
	}

	err := s.Tx.Commit()
	s.Tx = nil
	s.TxErr = nil
	return err
}

func (s *Sqlite) Query(rawSql string, param ...interface{}) ([]map[string]interface{}, error) {

	err := s.checkParam(rawSql, param)
	if err != nil {
		return nil, err
	}

	var rows *sql.Rows

	if s.Tx != nil {
		rows, err = s.Tx.Query(rawSql, param...)
	} else {
		rows, err = s.Conn.Query(rawSql, param...)
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

	for i := 0; i < count; i++ {
		valuePtrs[i] = &values[i]
	}

	result := make([]map[string]interface{}, 0)

	for rows.Next() {
		rows.Scan(valuePtrs...)

		row := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]

			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}

			row[col] = v
		}

		result = append(result, row)
	}

	return result, nil
}

func (s *Sqlite) Exec(rawSql string, getRowId bool, param ...interface{}) (int64, error) {

	err := s.checkParam(rawSql, param)
	if err != nil {
		return 0, err
	}

	var res sql.Result

	if s.Tx != nil {
		res, err = s.Tx.Exec(rawSql, param...)
	} else {
		res, err = s.Conn.Exec(rawSql, param...)
	}

	if err != nil {
		return 0, err
	}

	if getRowId {
		return res.LastInsertId()
	}
	return res.RowsAffected()
}

func (s *Sqlite) checkParam(sql string, param []interface{}) error {
	sqlCount := strings.Count(sql, "?")
	paramCount := len(param)

	if sqlCount != paramCount {
		return errors.New("参数数量不匹配，要求绑定" + strconv.Itoa(sqlCount) + "个参数，实际绑定" + strconv.Itoa(paramCount) + "个参数")
	}
	return nil
}
