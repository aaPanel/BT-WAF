package cluster_core

import (
	"CloudWaf/public"
	"CloudWaf/public/cluster_core/models"
	"CloudWaf/public/db"
	"encoding/json"
	"errors"

	"sync"
)

var (
	toolsObj   *Tools
	toolsMutex sync.RWMutex
)

func ToolsSingleton() *Tools {
	toolsMutex.RLock()
	if toolsObj != nil {
		toolsMutex.RUnlock()
		return toolsObj
	}
	toolsMutex.RUnlock()
	toolsMutex.Lock()
	defer toolsMutex.Unlock()
	if toolsObj != nil {
		return toolsObj
	}
	toolsObj = &Tools{}
	return toolsObj
}

type Tools struct{}

func (tools *Tools) RealtimeSelf() models.ClusterNodeRealtime {

	realtime := models.ClusterNodeRealtime{}

	sysInfo := public.GetSystemInfo()

	realtime.CPU = sysInfo.CPU
	realtime.Mem = sysInfo.Mem
	realtime.DiskList = sysInfo.DiskList
	realtime.NetIOList = sysInfo.NetIOList
	realtime.Loadavg = sysInfo.Loadavg

	result := struct {
		Status bool `json:"status"`
		Msg    struct {
			Qps       uint64 `json:"qps"`
			ProxyTime uint64 `json:"proxy_time"`
			RecvBytes uint64 `json:"recv_bytes"`
			SendBytes uint64 `json:"send_bytes"`
			Today     struct {
				Req uint64 `json:"req"`
			} `json:"today"`
		} `json:"msg"`
	}{}

	if res, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15); err == nil {
		_ = json.Unmarshal([]byte(res), &result)
	}

	if result.Status {
		realtime.Qps = result.Msg.Qps
		realtime.ResourceTime = result.Msg.ProxyTime
		realtime.Download = result.Msg.RecvBytes
		realtime.Upload = result.Msg.SendBytes
	}

	return realtime
}

func (tools *Tools) QueryChartData(query *db.Query, timeSection []int64, res any, fields []string, seriesKey, foreignKey string) error {
	if len(timeSection) != 2 {
		return errors.New("incorrect length of timeSection")
	}

	subSqlOne := public.M("cluster_chart_help").
		WhereBetween(seriesKey, []any{timeSection[0], timeSection[1]}).
		Field([]string{"`" + seriesKey + "` as `bt__series__key`"}).
		Order(seriesKey, "asc").
		BuildSql()

	subSqlTwo := query.Order(foreignKey, "asc").BuildSql()

	fieldSet := make(map[string]struct{})
	fieldSet["`bt__sub`.`bt__series__key` as `"+foreignKey+"`"] = struct{}{}

	for _, v := range fields {
		fieldSet[v] = struct{}{}
	}

	fields = fields[:0]
	for k := range fieldSet {
		fields = append(fields, k)
	}

	return public.M("").
		Table("("+subSqlOne+") as `bt__sub`").
		Join("left", "("+subSqlTwo+") as `bt__main`", "`bt__series__key`=`bt__main`.`"+foreignKey+"`").
		Field(fields).
		SelectAs(res)
}
