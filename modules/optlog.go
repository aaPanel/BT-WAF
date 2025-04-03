package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"net/http"
)

func init() {
	core.RegisterModule(&OptLog{})
}

type OptLog struct{}

func (o *OptLog) List(request *http.Request) core.Response {
	res, err := public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		params, err := core.GetParamsFromRequest(request)
		if err != nil {
			return core.Fail(err), nil
		}
		query := conn.NewQuery()
		query.Table("logs l").
			Join("left", "users u", "l.uid=u.id").
			Order("l.create_time", "desc").
			Order("l.id", "asc").
			Field([]string{"l.id", "uid", "ifnull(username, 'system') operator", "log_type", "content", "l.create_time"})
		public.AddQueryWithKeyword(params, func(keyword string) {
			query.Where("content like ?", public.GetSqlParams("%"+keyword+"%"))
		})
		if v, ok := params["log_type"]; ok {
			query.Where("log_type = ?", public.GetSqlParams(v))
		}
		return public.SimplePage(query, params)
	})

	if err != nil {
		return core.Fail("获取操作日志失败")
	}

	return core.Success(res)
}
