package db

import (
	"CloudWaf/core/common"
	"CloudWaf/public/validate"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	EXTRA_IGNORE  = "IGNORE"
	EXTRA_REPLACE = "REPLACE"
)

type Connection interface {
	Connect() error
	Close()
	Begin() (*sql.Tx, error)
	Rollback() error
	Commit() error
	Query(sql string, param ...interface{}) ([]map[string]interface{}, error)
	Exec(sql string, getRowId bool, param ...interface{}) (int64, error)
	NewQuery() *Query
}

type Raw string

type Query struct {
	Conn          Connection
	PreFix        string
	TableName     string
	JoinTable     []string
	JoinOn        []string
	JoinType      []string
	JoinParam     []interface{}
	OptField      []string
	OptLimit      string
	OptWhere      string
	OptOrder      []string
	OptParam      []interface{}
	OptGroup      []string
	OptHaving     []string
	OptDuplicate  string
	OptForceIndex string
}

func (q *Query) Table(tableName string) *Query {
	q.TableName = q.PreFix + tableName
	q.OptWhere = "1"
	return q
}

func (q *Query) TableWithoutPrefix(tableName string) *Query {
	q.TableName = tableName
	q.OptWhere = "1"
	return q
}

func (q *Query) FromSubQuery(subQuery *Query) *Query {
	q.TableName = "(" + subQuery.BuildSql() + ") AS `BT__SUB_TABLE__0`"
	q.OptWhere = "1"
	return q
}

func (q *Query) Field(field []string) *Query {

	for i, v := range field {
		if validate.IsBase63(v) {
			field[i] = "`" + v + "`"
		}
	}

	q.OptField = field
	return q
}

func (q *Query) AddField(fields []string) *Query {

	set := make(map[string]struct{}, len(q.OptField))

	for _, v := range q.OptField {
		set[v] = struct{}{}
	}

	for i := len(fields) - 1; i > -1; i-- {
		v := fields[i]
		if validate.IsBase63(v) {
			fields[i] = "`" + v + "`"
		}

		if _, ok := set[fields[i]]; ok {
			fields = append(fields[:i], fields[i+1:]...)
		}
	}

	if len(fields) > 0 {
		q.OptField = append(q.OptField, fields...)
	}

	return q
}

func (q *Query) Limit(limit []int64) *Query {
	last_limit := " LIMIT "
	limit_len := len(limit)
	if limit_len == 0 {
		q.OptLimit = ""
	} else if limit_len == 1 {
		q.OptLimit = last_limit + strconv.FormatInt(limit[0], 10)
	} else if limit_len >= 2 {
		q.OptLimit = last_limit + strconv.FormatInt(limit[0], 10) + "," + strconv.FormatInt(limit[1], 10)
	} else {
		q.OptLimit = ""
	}

	return q
}

func (q *Query) Order(fieldName string, sortOrder string) *Query {
	sortOrder = strings.ToUpper(sortOrder)
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "ASC"
	}
	q.OptOrder = append(q.OptOrder, fieldName+" "+sortOrder)
	return q
}

func (q *Query) Sort(fieldName string, sortOrder string) *Query {
	return q.Order(fieldName, sortOrder)
}

func (q *Query) Where(where string, params ...any) *Query {
	if len(params) == 1 {
		if v, ok := params[0].([]any); ok {
			params = v
		}
	}

	q.addWhere(where, params, "AND")
	return q
}

func (q *Query) WhereOr(where string, params ...any) *Query {
	if len(params) == 1 {
		if v, ok := params[0].([]any); ok {
			params = v
		}
	}

	q.addWhere(where, params, "OR")
	return q
}

func (q *Query) WhereIn(field string, data any) *Query {
	q.addWhereIn(field, data, "AND", false)
	return q
}

func (q *Query) WhereNotIn(field string, data any) *Query {
	q.addWhereIn(field, data, "AND", true)
	return q
}

func (q *Query) WhereInOr(field string, data any) *Query {
	q.addWhereIn(field, data, "OR", false)
	return q
}

func (q *Query) WhereNotInOr(field string, data any) *Query {
	q.addWhereIn(field, data, "OR", true)
	return q
}

func (q *Query) WhereBetween(field string, param []interface{}) *Query {
	q.addWhereBetween(field, param, "AND")
	return q
}

func (q *Query) WhereBetweenOr(field string, param []interface{}) *Query {
	q.addWhereBetween(field, param, "OR")
	return q
}

func (q *Query) addWhere(where string, params []interface{}, logic string) {
	logic = strings.ToUpper(strings.TrimSpace(logic))

	if logic != "AND" && logic != "OR" {
		return
	}
	templateStr := " %s %s"

	if q.containsOpt(where) {
		templateStr = " %s (%s)"
	}
	paramLen := len(params)
	if !strings.Contains(where, "?") && paramLen == 1 {
		if validate.IsBase63(where) {
			where = "`" + where + "` = ?"
		} else {
			where += " = ?"
		}
	}
	q.OptWhere += fmt.Sprintf(templateStr, logic, where)
	if paramLen > 0 {
		q.OptParam = append(q.OptParam, params...)
	}
}

func (q *Query) addWhereIn(field string, data any, logic string, notIn bool) {
	logic = strings.TrimSpace(strings.ToUpper(logic))

	if logic != "AND" && logic != "OR" {
		return
	}
	lst := make([]any, 0, 256)
	if err := common.MapToStruct(data, &lst); err != nil {
		panic(err)
	}
	if len(lst) == 0 {
		d := 0
		if notIn {
			d = 1
		}
		q.OptWhere += fmt.Sprintf(" %s %d", logic, d)
		return
	}

	opt := "IN"

	if notIn {
		opt = "NOT IN"
	}

	lstSize := len(lst)
	if lstSize < 64000 {
		placeholders := make([]string, 0, lstSize)
		for _, v := range lst {
			placeholders = append(placeholders, "?")
			q.OptParam = append(q.OptParam, v)
		}
		q.OptWhere += fmt.Sprintf(" %s %s %s (%s)", logic, field, opt, strings.Join(placeholders, ","))
		return
	}

	values := make([]string, 0, lstSize)
	for _, val := range lst {
		p := ""

		switch v := val.(type) {
		case string:
			p = `'` + strings.ReplaceAll(strings.ReplaceAll(v, `'`, `\'`), `"`, `\"`) + `'`
		case int:
			p = strconv.Itoa(v)
		case int16:
			p = strconv.Itoa(int(v))
		case int32:
			p = strconv.Itoa(int(v))
		case int64:
			p = strconv.Itoa(int(v))
		case uint:
			p = strconv.Itoa(int(v))
		case uint16:
			p = strconv.Itoa(int(v))
		case uint32:
			p = strconv.Itoa(int(v))
		case uint64:
			p = strconv.Itoa(int(v))
		case float32:
			p = strconv.FormatFloat(float64(v), 'f', -1, 32)
		case float64:
			p = strconv.FormatFloat(v, 'f', -1, 64)
		}
		values = append(values, p)
	}

	q.OptWhere += fmt.Sprintf(" %s %s %s (%s)", logic, field, opt, strings.Join(values, ","))
}

func (q *Query) addWhereBetween(field string, params []interface{}, logic string) {
	logic = strings.TrimSpace(strings.ToUpper(logic))

	if logic != "AND" && logic != "OR" {
		return
	}

	if len(params) != 2 {
		panic(fmt.Sprintf("addWhereBetween() 需要绑定2个参数，当前绑定%d个参数", len(params)))
	}
	if validate.IsBase63(field) {
		field = "`" + field + "`"
	}

	q.OptWhere += fmt.Sprintf(" %s (%s >= ? AND %s <= ?)", logic, field, field)
	q.OptParam = append(q.OptParam, params...)
}

func (q *Query) WhereNest(handler func(query *Query)) *Query {
	q.OptWhere += " AND (1"
	handler(q)
	q.OptWhere += ")"
	return q
}

func (q *Query) containsOpt(str string) bool {
	str = strings.ToUpper(str)
	for _, v := range []string{
		"AND",
		"OR",
	} {
		if strings.Contains(str, v) {
			return true
		}
	}

	return false
}

func (q *Query) getField() string {
	field := "*"
	if len(q.OptField) > 0 {
		field = strings.Join(q.OptField, ", ")
	}
	return field
}

func (q *Query) getJoinOn() (sql string) {

	for i := 0; i < len(q.JoinTable); i++ {
		if q.JoinTable[i] == "" {
			continue
		}
		sql += " " + q.JoinType[i] + " JOIN " + q.JoinTable[i] + " ON " + q.JoinOn[i]
	}
	if q.JoinParam != nil {
		joinParamLen := len(q.JoinParam)
		optParamLen := len(q.OptParam)
		params := make([]any, 0, 256)
		if joinParamLen > 0 {
			params = append(params, q.JoinParam...)
		}
		if optParamLen > 0 {
			params = append(params, q.OptParam...)
		}

		q.OptParam = params
	}
	return sql
}

func (q *Query) getWhere() (sql string) {
	return " WHERE " + q.OptWhere
}

func (q *Query) getGroup() string {
	if len(q.OptGroup) == 0 {
		return ""
	}

	return " GROUP BY " + strings.Join(q.OptGroup, ", ")
}

func (q *Query) getHaving() string {
	if len(q.OptHaving) == 0 {
		return ""
	}

	return " HAVING " + strings.Join(q.OptHaving, ", ")
}

func (q *Query) getOrder() string {
	if len(q.OptOrder) == 0 {
		return ""
	}

	return " ORDER BY " + strings.Join(q.OptOrder, ", ")
}

func (q *Query) getLimit() string {
	return q.OptLimit
}

func (q *Query) Duplicate(update map[string]string) *Query {
	if update == nil {
		return q
	}

	l := len(update)

	if l == 0 {
		return q
	}

	buf := make([]string, 0, l)

	for k, v := range update {
		buf = append(buf, "`"+k+"`"+" = "+v)
	}

	s := strings.Join(buf, ", ")

	switch q.Conn.(type) {
	case *Sqlite:
		q.OptDuplicate = " ON CONFLICT DO UPDATE SET " + s
	case *MySql:
		q.OptDuplicate = " ON DUPLICATE KEY UPDATE " + s
	default:
		panic("not support Duplicate()")
	}

	return q
}

func (q *Query) ForceIndex(indexName string) *Query {
	if indexName == "" {
		return q
	}

	switch q.Conn.(type) {
	case *Sqlite:
		q.OptForceIndex = " INDEXED BY `" + indexName + "`"
	case *MySql:
		q.OptForceIndex = " FORCE INDEX (`" + indexName + "`)"
	default:
		panic("not support ForceIndex()")
	}

	return q
}

func (q *Query) Select() ([]map[string]interface{}, error) {
	str := "SELECT " + q.getField() + " FROM " + q.TableName
	str += q.OptForceIndex
	str += q.getJoinOn()
	str += q.getWhere()
	str += q.getGroup()
	str += q.getHaving()
	str += q.getOrder()
	str += q.getLimit()

	defer q.clearOpt()
	return q.Conn.Query(str, q.OptParam...)
}

func (q *Query) SelectAs(result any) error {
	rawResult, err := q.Select()

	if err != nil {
		return err
	}

	return common.MapToStruct(rawResult, result)
}

func (q *Query) Insert(data any, extra ...string) (int64, error) {

	m := common.StructToMap(data)

	keys := make([]string, 0, 256)
	values := make([]any, 0, 256)
	placeholders := make([]string, 0, 256)

	for k, v := range m {
		keys = append(keys, "`"+k+"`")
		values = append(values, v)
		placeholders = append(placeholders, "?")
	}

	defer q.clearOpt()

	str := q.buildInsertLeading(extra...) + q.TableName + " (" + strings.Join(keys, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")" + q.OptDuplicate

	return q.Conn.Exec(str, true, values...)
}

func (q *Query) InsertAll(data any, extra ...string) (int64, error) {

	lst := make([]map[string]any, 0, 256)

	if err := common.MapToStruct(data, &lst); err != nil {
		return 0, err
	}

	rows := len(lst)
	if rows == 0 {
		return 0, nil
	}

	keys := make([]string, 0, 256)
	values := make([][]any, 0, 256)
	valuesTmp := make([]any, 0, 256)

	for k, v := range lst[0] {
		keys = append(keys, k)
		valuesTmp = append(valuesTmp, v)
	}

	values = append(values, valuesTmp)
	keySize := len(keys)

	for i := 1; i < rows; i++ {
		valuesTmp = make([]any, 0, keySize)
		for _, k := range keys {
			valuesTmp = append(valuesTmp, lst[i][k])
		}
		values = append(values, valuesTmp)
	}

	for i, v := range keys {
		keys[i] = "`" + v + "`"
	}

	defer q.clearOpt()
	str := q.buildInsertLeading(extra...) + q.TableName + " (" + strings.Join(keys, ", ") + ")"

	effectTotal := int64(0)

	chunkSize := 2000
	size := len(values)
	flag := false
	for i := 0; ; i++ {
		end := (i + 1) * chunkSize

		if end >= size {
			end = size
			flag = true
		}

		effects, err := q.insertAllHelp(str, values[i*chunkSize:end])
		effectTotal += effects
		if err != nil {
			return effectTotal, err
		}

		if flag {
			break
		}
	}

	return effectTotal, nil
}

func (q *Query) insertAllHelp(str string, values [][]any) (int64, error) {
	valueSize := len(values)
	placeholders := make([]string, 0, valueSize*32)
	placeholderTmp := make([]string, 0, valueSize*32)
	binds := make([]any, 0, valueSize*32)

	for _, v := range values {
		size := len(v)
		placeholderTmp = placeholderTmp[:0]
		for i := 0; i < size; i++ {
			placeholderTmp = append(placeholderTmp, "?")
		}
		placeholders = append(placeholders, "("+strings.Join(placeholderTmp, ",")+")")
		binds = append(binds, v...)
	}

	str += " VALUES " + strings.Join(placeholders, ", ") + q.OptDuplicate

	return q.Conn.Exec(str, false, binds...)
}

func (q *Query) buildInsertLeading(extraParam ...string) string {
	if len(extraParam) == 0 {
		return "INSERT INTO "
	}

	extra := strings.ToUpper(strings.TrimSpace(extraParam[0]))

	if extra != EXTRA_IGNORE && extra != EXTRA_REPLACE {
		return "INSERT INTO "
	}

	switch q.Conn.(type) {
	case *Sqlite:
		return "INSERT OR " + extra + " INTO "
	case *MySql:
		switch extra {
		case EXTRA_IGNORE:
			return "INSERT IGNORE INTO "
		case EXTRA_REPLACE:
			return "REPLACE INTO "
		default:
			return "INSERT INTO "
		}
	default:
		return "INSERT INTO "
	}
}

func (q *Query) Update(data any) (int64, error) {

	m := common.StructToMap(data)

	exps := make([]string, 0, 256)
	values := make([]any, 0, 256)

	for k, v := range m {
		if raw, ok := v.(Raw); ok {
			exps = append(exps, "`"+k+"` = "+string(raw))
			continue
		}
		exps = append(exps, "`"+k+"` = ?")
		values = append(values, v)
	}

	for _, v := range q.OptParam {
		values = append(values, v)
	}

	str := "UPDATE " + q.TableName + " SET " + strings.Join(exps, ", ") + q.getWhere()
	switch q.Conn.(type) {
	case *MySql:
		str += q.getLimit()
	}
	defer q.clearOpt()

	return q.Conn.Exec(str, false, values...)
}

func (q *Query) Delete() (int64, error) {
	str := "DELETE FROM " + q.TableName + q.getWhere()
	switch q.Conn.(type) {
	case *MySql:
		str += q.getLimit()
	}
	defer q.clearOpt()

	return q.Conn.Exec(str, false, q.OptParam...)
}

func (q *Query) Truncate() (int64, error) {
	str := ""

	switch q.Conn.(type) {
	case *MySql:
		str += "TRUNCATE TABLE "
	case *Sqlite:
		str += "DELETE FROM "
	}

	str += q.TableName

	defer q.clearOpt()

	return q.Conn.Exec(str, false)
}

func (q *Query) Find() (map[string]interface{}, error) {
	q.Limit([]int64{1})
	result, err := q.Select()

	if err != nil {
		return nil, err
	}

	if len(result) > 0 {
		return result[0], nil
	}

	return nil, nil
}

func (q *Query) FindAs(result any) error {
	rawResult, err := q.Find()

	if err != nil {
		return err
	}

	if rawResult == nil {
		return errors.New("FindAs(): empty result")
	}

	return common.MapToStruct(rawResult, result)
}

func (q *Query) Count(args ...any) (int64, error) {
	clearOpt := false

	if len(args) > 0 {
		if v, ok := args[0].(bool); ok {
			clearOpt = v
		}
	}
	str := "SELECT COUNT(*) AS `__BT_COUNT__` FROM "
	str += q.TableName
	str += q.OptForceIndex
	str += q.getJoinOn()
	str += q.getWhere()
	if clearOpt {
		defer q.clearOpt()
	}
	result, err := q.Conn.Query(str, q.OptParam...)
	if err != nil {
		return 0, err
	}
	if len(result) == 0 {
		return 0, nil
	}
	row := struct {
		BtCount int64 `json:"__BT_COUNT__"`
	}{}
	if err := common.MapToStruct(result[0], &row); err == nil {
		return row.BtCount, nil
	}

	return 0, nil
}

func (q *Query) Value(field string) (interface{}, error) {
	q.Field([]string{field})
	q.Limit([]int64{1})
	result, err := q.Select()
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		return result[0][field], nil
	}
	return nil, errors.New("not found")
}

func (q *Query) ValueAs(field string, result any) error {
	rawRes, err := q.Value(field)

	if err != nil {
		return err
	}

	return common.MapToStruct(rawRes, result)
}

func (q *Query) SetValue(field string, value interface{}) (int64, error) {
	data := make(map[string]any)
	data[field] = value
	return q.Update(data)
}

func (q *Query) Join(joinType string, table string, on string, params ...any) *Query {
	joinType = strings.ToUpper(strings.TrimSpace(joinType))
	if joinType != "LEFT" && joinType != "RIGHT" && joinType != "INNER" && joinType != "OUTER" {
		joinType = "LEFT"
	}

	if q.JoinTable == nil {
		q.JoinTable = make([]string, 0, 256)
	}

	q.JoinTable = append(q.JoinTable, q.PreFix+table)

	if q.JoinOn == nil {
		q.JoinOn = make([]string, 0, 256)
	}

	q.JoinOn = append(q.JoinOn, on)

	if q.JoinType == nil {
		q.JoinType = make([]string, 0, 256)
	}

	q.JoinType = append(q.JoinType, joinType)

	if q.JoinParam == nil {
		q.JoinParam = make([]interface{}, 0, 256)
	}

	for _, v := range params {
		if v == nil {
			continue
		}
		switch vv := v.(type) {
		case []any:
			q.JoinParam = append(q.JoinParam, vv...)
		default:
			q.JoinParam = append(q.JoinParam, vv)
		}
	}

	return q
}

func (q *Query) Having(having string) *Query {
	q.OptHaving = append(q.OptHaving, having)
	return q
}

func (q *Query) Group(group string) *Query {
	q.OptGroup = append(q.OptGroup, group)
	return q
}

func (q *Query) BuildSql() string {
	str := "SELECT " + q.getField() + " FROM " + q.TableName
	str += q.getJoinOn()
	str += q.getWhere()
	str += q.getGroup()
	str += q.getHaving()
	str += q.getOrder()
	str += q.getLimit()

	for _, param := range q.OptParam {
		p := ""

		switch v := param.(type) {
		case string:
			p = "'" + v + "'"
		case int:
			p = strconv.Itoa(v)
		case int16:
			p = strconv.Itoa(int(v))
		case int32:
			p = strconv.Itoa(int(v))
		case int64:
			p = strconv.Itoa(int(v))
		case uint:
			p = strconv.Itoa(int(v))
		case uint16:
			p = strconv.Itoa(int(v))
		case uint32:
			p = strconv.Itoa(int(v))
		case uint64:
			p = strconv.Itoa(int(v))
		case float32:
			p = strconv.FormatFloat(float64(v), 'f', -1, 32)
		case float64:
			p = strconv.FormatFloat(v, 'f', -1, 64)
		}

		str = strings.Replace(str, "?", p, 1)
	}

	return str
}

func (q *Query) clearOpt() {
	q.OptField = q.OptField[:0]
	q.OptWhere = "1"
	q.OptOrder = q.OptOrder[:0]
	q.OptGroup = q.OptGroup[:0]
	q.OptHaving = q.OptHaving[:0]
	q.OptLimit = ""
	q.OptParam = q.OptParam[:0]
	q.JoinOn = q.JoinOn[:0]
	q.JoinTable = q.JoinTable[:0]
	q.JoinType = q.JoinType[:0]
	q.JoinParam = q.JoinParam[:0]
	q.OptDuplicate = ""
	q.OptForceIndex = ""
}

func (q *Query) Query(rawSql string, params ...any) ([]map[string]any, error) {
	return q.Conn.Query(rawSql, params...)
}

func (q *Query) Exec(rawSql string, params ...any) (int64, error) {
	return q.Conn.Exec(rawSql, false, params...)
}

func (q *Query) QueryAs(result any, rawSql string, params ...any) error {
	rawResult, err := q.Query(rawSql, params...)

	if err != nil {
		return err
	}

	return common.MapToStruct(rawResult, result)
}

func (q *Query) ColumnAs(field string, result any) error {

	if len(q.OptField) == 0 {
		q.Field([]string{field})
	}

	rawResult, err := q.Select()

	if err != nil {
		return err
	}

	lst := make([]any, 0, len(rawResult))

	for i := range rawResult {
		if v, ok := rawResult[i][field]; ok {
			lst = append(lst, v)
		}
	}

	return common.MapToStruct(lst, result)
}

func (q *Query) DictAs(keyField string, result any) error {
	rawResult, err := q.Select()

	if err != nil {
		return err
	}

	m := make(map[any]any, len(rawResult))

	for i := range rawResult {
		if v, ok := rawResult[i][keyField]; ok {
			m[v] = rawResult[i]
		}
	}

	return common.MapToStruct(m, result)
}

func (q *Query) Exists() bool {
	q.Limit([]int64{1})
	str := "SELECT EXISTS("
	str += "SELECT " + q.getField() + " FROM " + q.TableName
	str += q.getJoinOn()
	str += q.getWhere()
	str += q.getGroup()
	str += q.getHaving()
	str += q.getOrder()
	str += q.getLimit()
	str += ") AS `__BT_EXISTS__`"

	defer q.clearOpt()

	res := struct {
		BtExists int `json:"__BT_EXISTS__"`
	}{}

	rawResult, err := q.Conn.Query(str, q.OptParam...)

	if err != nil || len(rawResult) == 0 {
		return false
	}

	if err := common.MapToStruct(rawResult[0], &res); err != nil {
		return false
	}

	if res.BtExists == 0 {
		return false
	}

	return true
}
