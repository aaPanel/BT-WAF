package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/cluster_core"
	"fmt"
	"net/http"
	"time"
)

func init() {
	core.RegisterModule(&Monitor{})
}

type Monitor struct{}

func (mo *Monitor) History(request *http.Request) core.Response {
	params := struct {
		ShowType   int    `json:"show_type"`
		Mountpoint string `json:"mountpoint"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	if params.ShowType == 0 {
		return core.Fail("缺少参数：show_type")
	}

	if params.Mountpoint == "" {
		return core.Fail("缺少参数：mountpoint")
	}

	size := 0
	sec := int64(3600)
	switch params.ShowType {
	case 1:
		size = 60
		sec = 3600
	case 2:
		size = 1440
		sec = 86400
	case 3:
		size = 1440 * 7
		sec = 86400 * 7
	default:
		return core.Fail(fmt.Sprintf("获取图表数据失败：无效的show_type %d", params.ShowType))
	}
	curTime := time.Now().Truncate(1 * time.Minute)
	timeSection := []int64{curTime.Unix() - sec, curTime.Unix() - 60}
	size = int((timeSection[1] - timeSection[0]) / 60)
	t1 := time.Unix(timeSection[0], 0)
	t2 := time.Unix(timeSection[1], 0)
	var err error
	res := make([]struct {
		Cpu          float64 `json:"cpu"`
		Mem          float64 `json:"mem"`
		TotalRequest int     `json:"total_request"`
		Qps          uint64  `json:"qps"`
		ResourceTime uint64  `json:"resource_time"`
		Upload       uint64  `json:"upload"`
		Download     uint64  `json:"download"`
		Err40x       int     `json:"err_40x"`
		Err499       int     `json:"err_499"`
		Err500       int     `json:"err_500"`
		Err502       int     `json:"err_502"`
		Err503       int     `json:"err_503"`
		Err504       int     `json:"err_504"`
		DiskRead     float64 `json:"disk_read"`
		DiskWrite    float64 `json:"disk_write"`
		DiskUsed     uint64  `json:"disk_used"`
		CreateTime   int64   `json:"create_time"`
	}, size)

	err = cluster_core.ToolsSingleton().QueryChartData(public.M("btwaf_disk_realtime_history").
		Where("mountpoint", params.Mountpoint).
		WhereBetween("create_time", []any{timeSection[0], timeSection[1]}), timeSection, &res, []string{
		"ifnull(`read`, 0) as `disk_read`",
		"ifnull(`write`, 0) as `disk_write`",
		"ifnull(`used`, 0) as `disk_used`",
	}, "time_minute", "create_time")

	if err != nil {
		return core.Fail(fmt.Errorf("获取图表数据失败：%w", err))
	}

	err = cluster_core.ToolsSingleton().QueryChartData(public.M("request_total").
		ForceIndex("date_hour_minute").
		WhereBetween("date", []any{t1.Format("2006-01-02"), t2.Format("2006-01-02")}).
		WhereBetween("str_to_date(concat(`date`, ' ', `hour`, ':', `minute`), '%Y-%m-%d %H:%i')", []any{t1.Format("2006-01-02 15:04:05"), t2.Format("2006-01-02 15:04:05")}).
		Group("date").
		Group("hour").
		Group("minute").
		Order("date", "asc").
		Order("hour", "asc").
		Order("minute", "asc").Field([]string{
		"sum(`request`) as `total_request`",
		"sum(`sec_request`) as `qps`",
		"sum(`avg_proxy_time`) as `resource_time`",
		"sum(`sec_send_bytes`) as `upload`",
		"sum(`sec_receive_bytes`) as `download`",
		"sum(`err_40x`) as `err_40x`",
		"sum(`err_499`) as `err_499`",
		"sum(`err_500`) as `err_500`",
		"sum(`err_502`) as `err_502`",
		"sum(`err_503`) as `err_503`",
		"sum(`err_504`) as `err_504`",
		"unix_timestamp(str_to_date(concat(`date`, ' ', `hour`, ':', `minute`), '%Y-%m-%d %H:%i')) as `create_time`",
	}), timeSection, &res, []string{
		"ifnull(`total_request`, 0) as `total_request`",
		"ifnull(`qps`, 0) as `qps`",
		"ifnull(`resource_time`, 0) as `resource_time`",
		"ifnull(`upload`, 0) as `upload`",
		"ifnull(`download`, 0) as `download`",
		"ifnull(`err_40x`, 0) as `err_40x`",
		"ifnull(`err_499`, 0) as `err_499`",
		"ifnull(`err_500`, 0) as `err_500`",
		"ifnull(`err_502`, 0) as `err_502`",
		"ifnull(`err_503`, 0) as `err_503`",
		"ifnull(`err_504`, 0) as `err_504`",
	}, "time_minute", "create_time")

	if err != nil {
		return core.Fail(fmt.Errorf("获取图表数据失败：%w", err))
	}
	err = cluster_core.ToolsSingleton().QueryChartData(public.M("btwaf_realtime_history").
		WhereBetween("create_time", []any{timeSection[0], timeSection[1]}), timeSection, &res, []string{
		"ifnull(`cpu`, 0) as `cpu`",
		"ifnull(`mem`, 0) as `mem`",
		"ifnull(`qps`, 0) as `qps`",
		"ifnull(`download`, 0) as `download`",
		"ifnull(`upload`, 0) as `upload`",
	}, "time_minute", "create_time")

	if err != nil {
		return core.Fail(fmt.Errorf("获取图表数据失败：%w", err))
	}

	return core.Success(res)
}
