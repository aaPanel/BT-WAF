package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/cache"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Overview{
		ip_path: core.AbsPath("./config/ip_info.json"),
	})
}

type Overview struct {
	ip_path string
}

func (o *Overview) SetStatusMap(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	open := params["open"]
	if open == "" {
		return core.Fail("参数错误")
	}
	open2 := public.InterfaceToInt(open)
	if open2 == 1 {
		public.WriteFile("/www/cloud_waf/console/data/3d.txt", "1")
		return core.Success("开启成功")
	}
	if open2 == 0 {
		public.WriteFile("/www/cloud_waf/console/data/3d.txt", "0")
		return core.Success("关闭成功")
	}
	return core.Fail("参数错误")
}

func (o *Overview) GetStatusMap(request *http.Request) core.Response {
	status := make(map[string]interface{}, 1)
	if !public.FileExists("/www/cloud_waf/console/data/3d.txt") {
		status["open"] = true
		public.WriteFile("/www/cloud_waf/console/data/3d.txt", "1")
	} else {
		data, err := public.ReadFile("/www/cloud_waf/console/data/3d.txt")
		if err != nil {
			status["open"] = false
			public.WriteFile("/www/cloud_waf/console/data/3d.txt", "1")
		}
		if data == "1" {
			status["open"] = true
		} else {
			status["open"] = false
		}
	}

	return core.Success(status)
}

func (o *Overview) GetMap(request *http.Request) core.Response {
	is_acc := make(map[string]interface{}, 500)
	status := make(map[string]interface{}, 500)
	result_map := []map[string]interface{}{}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("totla_log").
			Field([]string{"id", "ip", "ip_country", "ip_latitude", "ip_longitude"}).
			Order("id", "desc").
			Limit([]int64{0, 1000})

		result, err := query.Select()
		for _, v := range result {
			ip_country := v["ip_country"].(string)
			ip := v["ip"].(string)
			ip_longitude := v["ip_longitude"].(string)
			ip_latitude := v["ip_latitude"].(string)
			if ip == "" {
				continue
			}
			if ip_country == "" {
				continue
			}
			if ip_country == "内网地址" {
				continue
			}
			if ip_longitude == "" || ip_latitude == "" {
				continue
			}

			if _, ok := is_acc[ip_longitude+ip_latitude]; ok {
				continue
			}
			is_acc[ip_longitude+ip_latitude] = 1
			if len(result_map) >= 100 {
				break
			}
			result_map = append(result_map, map[string]interface{}{
				"ip":           ip,
				"ip_country":   ip_country,
				"ip_longitude": ip_longitude,
				"ip_latitude":  ip_latitude,
			})
		}
		return result_map, err
	})
	if err != nil {
		core.Success(res)
	}
	cacheKey_address := "InterceptPage__IPAddress"
	if cache.Has(cacheKey_address) {
		status["xyz"] = cache.Get(cacheKey_address)
	} else {
		data := map[string]interface{}{}
		publicIpInfo, err := public.Rconfigfile(o.ip_path)
		if err == nil && publicIpInfo != nil && publicIpInfo["ip_longitude"] != "" && publicIpInfo["ip_latitude"] != "" {
			data = publicIpInfo
		} else {
			serverIp, _ := core.GetServerIp()
			ipInfo := public.GetIPAreaIpInfo(serverIp)
			data = map[string]interface{}{
				"ip_address":   serverIp,
				"ip_longitude": ipInfo.Longitude,
				"ip_latitude":  ipInfo.Latitude,
			}
		}
		status["xyz"] = data
		cache.Set(cacheKey_address, data, 60*60*24)
	}
	status["list"] = res
	return core.Success(status)

}

func (o *Overview) AttackMap(request *http.Request) core.Response {
	cacheKey := "OverView__GetAttackMap"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	date_n := o.the_other_day(30)
	var res interface{}
	var top interface{}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query1 := conn.NewQuery()

		query.Table("ip_intercept").
			Where("date >= ?", []interface{}{date_n}).
			Field([]string{
				"any_value(date) as date",
				"any_value(ip) as ip",
				"any_value(country) as country",
				"any_value(city) as city",
				"any_value(province) as province",
				"request  as visits"}).
			Sort("visits", "desc").
			Limit([]int64{0, 500})
		query1.Table("ip_intercept").
			Where("date >= ?", []interface{}{date_n}).
			Field([]string{
				"any_value(date) as date",
				"any_value(country) as country",
				"sum(request) as visits",
			}).
			Group("country").
			Sort("visits", "desc").
			Limit([]int64{0, 5000})
		result, err := query1.Select()
		top, err = query.Select()
		top = o.aggregateData(top.([]map[string]interface{}))

		return result, err
	})
	if err != nil {
		return core.Fail("获取攻击地图失败")
	}
	if len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}
	}
	if len(top.([]map[string]interface{})) == 0 {
		top = []map[string]interface{}{}
	}
	ress := map[string]interface{}{
		"top": top,
		"map": res,
	}
	cache.Set(cacheKey, ress, 60)
	return core.Success(ress)
}

func (o *Overview) MaliciousInfo(request *http.Request) core.Response {
	cacheKey := "OverView__MaliciousInfo"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("totla_log").
			Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "action",
				"ip_province", "request_uri", "host", "risk_type",
			}).
			Order("time", "desc").
			Limit([]int64{0, 20})
		result, err := query.Select()
		return result, err
	})
	if err != nil {
		return core.Fail("获取恶意访问详情失败")
	}
	if len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}
	}
	cache.Set(cacheKey, res, 60)
	return core.Success(res)
}

func (o *Overview) Count(request *http.Request) core.Response {
	cacheKey := "OverView__Count"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}

	var request_total float64
	startDate, _ := o.day_range()
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query1 := conn.NewQuery()
		query3 := conn.NewQuery()

		query.Table("ip_intercept").
			Where("date = ?", []interface{}{startDate}).
			Field([]string{"sum(request) as `total`"})
		query1.Table("request_total").
			Where("date = ?", []interface{}{startDate}).
			Field([]string{
				"ifnull(SUM(proxy_count), 0) as `proxy_total`",
				"ifnull(SUM(request), 0) as `request_total`",
			})
		query3.Table("request_total").
			Where("date = ?", []interface{}{startDate}).
			Field([]string{"avg_proxy_time"}).
			Order("id", "desc")
		result, err := query.Find()
		result1, err := query1.Find()
		servers, err := public.GetAllDomain()
		result3, err := query3.Find()
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"request_total":   public.InterfaceToInt(result1["request_total"]),
			"proxy_total":     public.InterfaceToInt(result1["proxy_total"]),
			"server_total":    len(servers),
			"malicious_total": public.InterfaceToInt(result["total"]),
			"avg_proxy_time":  public.InterfaceToInt(result3["avg_proxy_time"]),
		}, nil
	})
	if err != nil {
		return core.Fail("获取统计数据失败")
	}
	ress, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15)

	if err == nil {
		file_data := make(map[string]interface{}, 0)
		err = json.Unmarshal([]byte(ress), &file_data)
		if err != nil {
			return core.Fail(err)
		}
		if y, ok := file_data["status"]; ok && y.(bool) == true {

			if v, ok := file_data["msg"]; ok {
				if c, ok := v.(map[string]interface{})["today"].(map[string]interface{}); ok {
					request_total = c["req"].(float64)
				}
			}
			if res != nil {
				if c, ok := res.(map[string]interface{})["request_total"]; ok {
					if c.(int) < int(request_total) {
						res.(map[string]interface{})["request_total"] = request_total
					}
				}
			}

		}
	}
	cache.Set(cacheKey, res, 3)
	return core.Success(res)

}

func (o *Overview) ErrorRequest(request *http.Request) core.Response {
	cacheKey := "OverView__ErrorRequest"

	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}

	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		startDate, startHour := o.day_range()
		yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		query_yesterday := conn.NewQuery()
		query_today := conn.NewQuery()
		query_yesterday.Table("request_total").
			Where("date = ?", []interface{}{yesterday}).
			Where("hour >= ?", []interface{}{startHour}).
			Field([]string{
				"any_value(id) as id",
				"any_value(date) as date",
				"any_value(request) as request",
				"any_value(err_499) as err_499",
				"any_value(err_502) as err_502",
				"any_value(err_504) as err_504",
				"any_value(hour) as hour",
				"any_value(minute) as minute",
				"(`hour`*60+ `minute`) AS `data_m`"})
		query_today.Table("request_total").
			Where("date = ?", []interface{}{startDate}).
			Field([]string{
				"any_value(id) as id",
				"any_value(date) as date",
				"any_value(request) as request",
				"any_value(err_499) as err_499",
				"any_value(err_502) as err_502",
				"any_value(err_504) as err_504",
				"any_value(hour) as hour",
				"any_value(minute) as minute",
				"(`hour`*60+ `minute`) AS `data_m`"})
		result_t, err := query_today.Select()
		result_y, err := query_yesterday.Select()
		var result_ya []types.OverViewRequest
		for _, v := range result_y {
			result_ya = append(result_ya, types.OverViewRequest{
				Id:      v["id"].(int64),
				Date:    v["date"].(string),
				Err499:  v["err_499"].(int64),
				Err502:  v["err_502"].(int64),
				Err504:  v["err_504"].(int64),
				Request: v["request"].(int64),
				Hour:    v["hour"].(int64),
				Minute:  v["minute"].(int64),
				Datam:   v["data_m"].(int64),
			})
		}
		resulty := o.aggregateData1(result_ya)
		if len(resulty) > 2 {
			resulty = o.completeMissingDataStruct(resulty, 2, []string{"request", "err_499", "err_502", "err_504"})
		}
		var result_ta []types.OverViewRequest
		for _, v := range result_t {
			result_ta = append(result_ta, types.OverViewRequest{
				Id:      v["id"].(int64),
				Date:    v["date"].(string),
				Err499:  v["err_499"].(int64),
				Err502:  v["err_502"].(int64),
				Err504:  v["err_504"].(int64),
				Request: v["request"].(int64),
				Hour:    v["hour"].(int64),
				Minute:  v["minute"].(int64),
				Datam:   v["data_m"].(int64),
			})
		}
		resulta := o.aggregateData1(result_ta)
		if len(resulta) > 2 {
			resulta = o.completeMissingDataStruct(resulta, 1, []string{"request", "err_499", "err_502", "err_504"})
		}
		result_all := append(resulta, resulty...)

		return result_all, err
	})
	if err != nil {
		return core.Fail("获取错误请求趋势失败")
	}
	if len(res.([]types.OverViewRequest)) == 0 {
		res = []types.OverViewRequest{}
	} else {

	}
	cache.Set(cacheKey, res, 60)
	return core.Success(res)
}

func (o *Overview) WebsiteFlow(request *http.Request) core.Response {
	cacheKey := "OverView__WebsiteFlow"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		startDate, startHour := o.day_range()
		query_all := conn.NewQuery()
		query_all.Table("request_total").
			Where("date = ?", []interface{}{startDate}).
			Where("hour = ?", []interface{}{startHour}).
			Field([]string{
				"any_value(id) as id",
				"any_value(sec_request) as request",
				"any_value(sec_send_bytes) as sec_send_bytes",
				"any_value(sec_receive_bytes) as sec_receive_bytes",
				"any_value(date) as date",
				"(`hour`*60+ `minute`) AS `data_m`", "any_value(hour) as hour",
				"any_value(minute) as minute"}).
			Group("data_m").
			Order("id", "desc").
			Limit([]int64{0, 60})
		result, err := query_all.Select()

		return result, err
	})

	if err != nil {
		return core.Fail("获取数据失败")
	}
	if len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}
	} else {
		res = o.completeMissingData(res.([]map[string]interface{}), []string{"request", "sec_send_bytes", "sec_receive_bytes"})
	}
	cache.Set(cacheKey, res, 60)
	return core.Success(res)
}

func (o *Overview) BackToSource(request *http.Request) core.Response {
	cacheKey := "OverView__BackToSource"
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	var proxy_time float64
	ress, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15)
	if err != nil {
		proxy_time = 0
	}
	file_data := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(ress), &file_data)
	if err != nil {
		proxy_time = 0
	}

	if v, ok := file_data["msg"]; ok {
		if c, ok := v.(map[string]interface{}); ok {
			proxy_time = c["proxy_time"].(float64)
		}
	}

	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		startDate, startHour := o.day_range()
		query_all := conn.NewQuery()

		query_all.Table("request_total").
			Where("date = ?", []interface{}{startDate}).
			Where("hour = ?", []interface{}{startHour}).
			Field([]string{"any_value(request) as request",
				"any_value(avg_proxy_time) as avg_proxy_time",
				"any_value(proxy_count) as proxy_count",
				"any_value(date) as date",
				"(`hour`*60+ `minute`) AS `data_m`",
				"any_value(hour) as hour",
				"any_value(minute) as minute"}).
			Group("data_m").
			Order("data_m", "desc").
			Limit([]int64{0, 60})
		result, err := query_all.Select()

		return result, err
	})

	if err != nil {
		return core.Fail("获取数据失败")
	}
	if len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}

	} else {
		res = o.completeMissingData(res.([]map[string]interface{}), []string{"avg_proxy_time", "proxy_count", "request"})
	}
	cache.Set(cacheKey, res, 60)
	return core.Success(map[string]interface{}{
		"proxy_time": proxy_time,
		"list":       res,
	})
}

func (o *Overview) NginxCount(request *http.Request) core.Response {
	res, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15)
	if err != nil {
		return core.Success(map[string]interface{}{
			"proxy_time": 0,
			"recv_bytes": 0,
			"send_bytes": 0,
			"qps":        0,
		})
	}
	file_data := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(res), &file_data)
	if err != nil {
		return core.Fail(err)
	}

	var proxy_time float64
	var recv_bytes float64
	var send_bytes float64
	var qps float64
	if v, ok := file_data["msg"]; ok {
		if c, ok := v.(map[string]interface{}); ok {
			proxy_time = c["proxy_time"].(float64)
			recv_bytes = c["recv_bytes"].(float64)
			send_bytes = c["send_bytes"].(float64)
			qps = c["qps"].(float64)
		}
	}
	return core.Success(map[string]interface{}{
		"proxy_time": proxy_time,
		"recv_bytes": recv_bytes,
		"send_bytes": send_bytes,
		"qps":        qps,
	})
}

func (o *Overview) Restart(request *http.Request) core.Response {
	_, err := public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	if err != nil {
		return core.Fail("重启失败")
	}
	return core.Success("重启成功")
}

func (o *Overview) SlowRequest(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	sites := ""
	if v, ok := params["sites"].(string); ok {
		sites = public.InterfaceToString(v)
	}
	if sites == "" {
		return core.Fail("缺少参数：sites")
	}
	cacheKey := "OverView__SlowRequest_" + sites
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	result := o.slowRequest(sites)
	cache.Set(cacheKey, result, 60)
	return core.Success(result)

}

func (o *Overview) Infos(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	new_time := ""

	if v, ok := params["start_time"].(string); ok {
		new_time = public.InterfaceToString(v)
		if !public.IsTime(new_time) {
			return core.Fail("时间格式错误")
		}
	}
	cacheKey := "OverView__Infos" + new_time
	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}

	startDate, startHour := o.day_range()
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("totla_log").
			Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "action",
				"ip_province", "request_uri", "host", "risk_type",
			}).
			Order("time", "desc").
			Limit([]int64{0, 20})
		intercept, err := query.Select()
		if len(intercept) == 0 {
			intercept = []map[string]interface{}{}
		}
		result_all := []types.OverViewRequest{}
		if new_time == "" {
			query_yesterday := conn.NewQuery()
			query_today := conn.NewQuery()
			query_yesterday.Table("request_total").
				Where("date = ?", []interface{}{yesterday}).
				Where("hour >= ?", []interface{}{startHour}).
				Field([]string{
					"any_value(id) as id",
					"any_value(date) as date",
					"any_value(request) as request",
					"any_value(err_499) as err_499",
					"any_value(err_502) as err_502",
					"any_value(err_504) as err_504",
					"any_value(hour) as hour",
					"any_value(minute) as minute",
					"(`hour`*60+ `minute`) AS `data_m`"})

			query_today.Table("request_total").
				Where("date = ?", []interface{}{startDate}).
				Field([]string{
					"any_value(id) as id",
					"any_value(date) as date",
					"any_value(request) as request",
					"any_value(err_499) as err_499",
					"any_value(err_502) as err_502",
					"any_value(err_504) as err_504",
					"any_value(hour) as hour",
					"any_value(minute) as minute",
					"(`hour`*60+ `minute`) AS `data_m`"})

			result_t, _ := query_today.Select()
			result_y, _ := query_yesterday.Select()
			result_ya := make([]types.OverViewRequest, 0, len(result_y))
			for _, v := range result_y {
				dateStr := v["date"].(string)
				hour := v["hour"].(int64)
				minute := v["minute"].(int64)
				minuteStr := fmt.Sprintf("%02d", minute)
				t, err := public.ParseDateStrToTime("2006-01-02 15:04", dateStr+" "+strconv.Itoa(int(hour))+":"+minuteStr)
				if err != nil {
					continue
				}

				result_ya = append(result_ya, types.OverViewRequest{
					Id:        v["id"].(int64),
					Date:      v["date"].(string),
					Err499:    v["err_499"].(int64),
					Err502:    v["err_502"].(int64),
					Err504:    v["err_504"].(int64),
					Request:   v["request"].(int64),
					Hour:      v["hour"].(int64),
					Minute:    v["minute"].(int64),
					Datam:     v["data_m"].(int64),
					Timestamp: t.Unix(),
				})
			}
			resulty := o.aggregateData1(result_ya)
			if len(resulty) > 0 {
				resulty = o.completeMissingDataStruct(resulty, 2, []string{"request", "err_499", "err_502", "err_504"})
			}
			result_ta := make([]types.OverViewRequest, 0, len(result_t))
			for _, v := range result_t {
				dateStr := v["date"].(string)
				hour := v["hour"].(int64)
				minute := v["minute"].(int64)

				minuteStr := fmt.Sprintf("%02d", minute)
				t, err := public.ParseDateStrToTime("2006-01-02 15:04", dateStr+" "+strconv.Itoa(int(hour))+":"+minuteStr)
				if err != nil {
					continue
				}

				result_ta = append(result_ta, types.OverViewRequest{
					Id:        v["id"].(int64),
					Date:      v["date"].(string),
					Err499:    v["err_499"].(int64),
					Err502:    v["err_502"].(int64),
					Err504:    v["err_504"].(int64),
					Request:   v["request"].(int64),
					Hour:      v["hour"].(int64),
					Minute:    v["minute"].(int64),
					Datam:     v["data_m"].(int64),
					Timestamp: t.Unix(),
				})
			}

			resulta := o.aggregateData1(result_ta)
			if len(resulta) > 0 {
				resulta = o.completeMissingDataStruct(resulta, 1, []string{"request", "err_499", "err_502", "err_504"})
			}
			result_all = append(resulta, resulty...)

			if len(result_all) == 0 {
				result_all = []types.OverViewRequest{}
			}
		} else {
			query_today := conn.NewQuery()
			query_today.Table("request_total").
				Where("date = ?", []interface{}{new_time}).
				Field([]string{
					"any_value(id) as id",
					"any_value(date) as date",
					"any_value(request) as request",
					"any_value(err_499) as err_499",
					"any_value(err_502) as err_502",
					"any_value(err_504) as err_504",
					"any_value(hour) as hour",
					"any_value(minute) as minute",
					"(`hour`*60+ `minute`) AS `data_m`"})

			result_t, _ := query_today.Select()
			result_ta := make([]types.OverViewRequest, 0, len(result_t))
			for _, v := range result_t {
				dateStr := v["date"].(string)
				hour := v["hour"].(int64)
				minute := v["minute"].(int64)
				minuteStr := fmt.Sprintf("%02d", minute)
				t, err := public.ParseDateStrToTime("2006-01-02 15:04", dateStr+" "+strconv.Itoa(int(hour))+":"+minuteStr)
				if err != nil {
					continue
				}
				result_ta = append(result_ta, types.OverViewRequest{
					Id:        v["id"].(int64),
					Date:      v["date"].(string),
					Err499:    v["err_499"].(int64),
					Err502:    v["err_502"].(int64),
					Err504:    v["err_504"].(int64),
					Request:   v["request"].(int64),
					Hour:      v["hour"].(int64),
					Minute:    v["minute"].(int64),
					Datam:     v["data_m"].(int64),
					Timestamp: t.Unix(),
				})
			}

			resulta := o.aggregateData1(result_ta)
			if len(resulta) > 0 {
				resulta = o.completeMissingDataStruct_New(resulta, 1, []string{"request", "err_499", "err_502", "err_504"}, new_time)
			}
			result_all = resulta

			if len(result_all) == 0 {
				result_all = []types.OverViewRequest{}
			}

		}

		result := map[string]interface{}{
			"intercept": intercept,
			"request":   result_all,
		}
		return result, err
	})

	if err != nil {
		return core.Fail("获取拦截详情+请求趋势失败")
	}

	cache.Set(cacheKey, res, 2)
	return core.Success(res)
}

func (o *Overview) GetSpiderInfos(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	new_time := ""

	if v, ok := params["start_time"].(string); ok {
		new_time = public.InterfaceToString(v)
		if !public.IsTime(new_time) {
			return core.Fail("时间格式错误")
		}
	} else {
		new_time = time.Now().Format("2006-01-02")
	}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query_today := conn.NewQuery()
		query_today.Table("request_total").
			Where("date = ?", []interface{}{new_time}).
			Field([]string{
				"hour",
				"sum(spider_baidu) as baidu",
				"sum(spider_google) as google",
				"sum(spider_bing) as bing",
				"sum(spider_sogou) as sogou",
				"sum(spider_360) as spider_360",
			}).
			Group("hour").
			Sort("hour", "desc")
		result_t, err := query_today.Select()
		if err != nil {
			return nil, err
		}
		result := make([]types.SpiderRequest, 0, len(result_t))
		for _, v := range result_t {
			hour, _ := strconv.Atoi(public.InterfaceToString(v["hour"]))

			baidu, _ := strconv.Atoi(public.InterfaceToString(v["baidu"]))
			google, _ := strconv.Atoi(public.InterfaceToString(v["google"]))
			bing, _ := strconv.Atoi(public.InterfaceToString(v["bing"]))
			sogou, _ := strconv.Atoi(public.InterfaceToString(v["sogou"]))
			spider_360, _ := strconv.Atoi(public.InterfaceToString(v["spider_360"]))

			result = append(result, types.SpiderRequest{
				Hour:      hour,
				Baidu:     baidu,
				Google:    google,
				Bing:      bing,
				Sogou:     sogou,
				Spider360: spider_360,
			})
		}

		return result, err
	})

	return core.Success(res)

}

func (o *Overview) CountInfo(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	sites := ""
	if v, ok := params["sites"].(string); ok {
		sites = public.InterfaceToString(v)
	}

	infos := map[string]interface{}{
		"slow":  []map[string]interface{}{},
		"sys":   types.SystemInfo{},
		"count": map[string]interface{}{},
	}

	cacheKey_slow := "OverView__SlowRequest_" + sites
	cacheKey_count := "OverView__CountInfo"
	cacheKey_sys := "OverView__sysInfo"
	if cache.Has(cacheKey_slow) {
		infos["slow"] = cache.Get(cacheKey_slow)
	} else {
		var slow []map[string]interface{}
		if sites == "" {
			slow = []map[string]interface{}{}
		} else {
			slow = o.slowRequest(sites)
			if len(slow) != 0 {
				infos["slow"] = slow
			}
		}
		cache.Set(cacheKey_slow, slow, 60)
	}
	if cache.Has(cacheKey_sys) {
		infos["sys"] = cache.Get(cacheKey_sys)
	} else {
		var systemInfo types.SystemInfo
		systemInfo = public.GetSystemInfo()

		infos["sys"] = systemInfo
		cache.Set(cacheKey_sys, systemInfo, 2)
	}
	if cache.Has(cacheKey_count) {
		infos["count"] = cache.Get(cacheKey_count)
	} else {
		var request_total float64
		var proxy_time float64
		var recv_bytes float64
		var send_bytes float64
		var qps float64
		negix, err := o.realTime()
		if err != nil {
			request_total = 0
			proxy_time = 0
			recv_bytes = 0
			send_bytes = 0
			qps = 0
		}
		request_total = negix["request_total"].(float64)
		proxy_time = negix["proxy_time"].(float64)
		recv_bytes = negix["recv_bytes"].(float64)
		send_bytes = negix["send_bytes"].(float64)
		qps = negix["qps"].(float64)

		startDate, _ := o.day_range()
		count_info, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
			query := conn.NewQuery()
			query1 := conn.NewQuery()

			query.Table("ip_intercept").
				Where("date = ?", []interface{}{startDate}).
				Field([]string{"sum(request) as `total`"})
			query1.Table("request_total").
				Where("date = ?", []interface{}{startDate}).
				Field([]string{
					"ifnull(SUM(request), 0) as `request_total`",
				})
			result, err := query.Find()
			result1, err := query1.Find()
			if err != nil {
				return nil, err
			}
			database_request_total := result1["request_total"].(float64)
			if database_request_total > request_total {
				request_total = database_request_total
			}
			return map[string]interface{}{

				"request_total":   request_total,
				"malicious_total": public.InterfaceToInt(result["total"]),
				"proxy_time":      proxy_time,
				"recv_bytes":      recv_bytes,
				"send_bytes":      send_bytes,
				"qps":             qps,
			}, nil
		})
		if err != nil {
			count_info = map[string]interface{}{
				"request_total":   0,
				"malicious_total": 0,
				"proxy_time":      proxy_time,
				"recv_bytes":      recv_bytes,
				"send_bytes":      send_bytes,
				"qps":             qps,
			}

		}
		infos["count"] = count_info
		cache.Set(cacheKey_count, count_info, 2)

	}

	return core.Success(infos)
}

func (o *Overview) Map(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if params["type"] == nil || params["request"] == nil || params["country"] == nil {
		return core.Fail("参数错误 缺少type/request/country")
	}
	cacheKey := "OverView__Map_" + fmt.Sprintf("Request%v", params["request"]) + "_" + fmt.Sprintf("country%v", params["country"]) + "_" + fmt.Sprintf("type%v", params["type"]) + "_" + fmt.Sprintf("query_data%d", params["query_data"])

	if cache.Has(cacheKey) {
		return core.Success(cache.Get(cacheKey))
	}
	date_n := o.the_other_day(30)

	if v, ok := params["query_data"].(float64); ok {
		date_n = o.the_other_day(int(v))
	}

	var res interface{}
	var top interface{}
	if params["request"].(float64) == 0 {
		if params["type"].(float64) == 0 {
			res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
				query := conn.NewQuery()
				query.Table("area_total").
					Where("date >= ?", []interface{}{date_n}).
					Field([]string{
						"any_value(province) as province",
						"any_value(country) as country",
						"SUM(request) as visits",
					}).Sort("visits", "desc")

				if params["country"].(float64) == 0 {
					query.Group("country")
				} else {
					query.Where("country = ?", []interface{}{"中国"})
					query.Group("province")
				}
				result, err := query.Select()
				if len(result) > 1000 {
					result = result[:1000]
				}
				return result, err
			})

			if err != nil {
				return core.Fail("获取请求地图地区数据失败2")
			}
			top, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
				query := conn.NewQuery()
				query.Table("ip_total").
					Where("date >= ?", []interface{}{date_n}).
					WhereNotIn("ip", []interface{}{"127.0.0.1"}).
					Field([]string{
						"any_value(ip) as ip",
						"request as visits"}).
					Sort("visits", "desc")

				if params["country"].(float64) == 1 {
					query.Where("is_inland = ?", []interface{}{1})
				}

				query.Limit([]int64{0, 5000})

				result, err := query.Select()
				result = o.aggregateData(result)
				intercept_query := conn.NewQuery()

				intercept_query.Table("ip_intercept").
					Where("date >= ?", []interface{}{date_n}).
					WhereNotIn("ip", []interface{}{"127.0.0.1"}).
					Field([]string{
						"any_value(ip) as ip",
						"any_value(country) as country",
						"any_value(city) as city",
						"any_value(province) as province",
						"request  as visits"}).
					Sort("visits", "desc").
					Limit([]int64{0, 5000})
				if params["country"].(float64) == 1 {
					intercept_query.Where("country = ?", []interface{}{"中国"})
				}
				intercept_result, err := intercept_query.Select()
				intercept_result = o.aggregateData(intercept_result)
				check_result := make([]map[string]interface{}, 0)
				if len(result) > 100 {
					check_result = result[:100]
				} else {
					check_result = result
				}
				checkMap := make(map[string]string, 0)
				if len(check_result) > 0 {
					for _, v := range check_result {
						if c, ok := v["ip"].(string); ok {
							checkMap[c] = "1"
						}
					}
				}
				if len(intercept_result) > 0 && len(result) > 0 && len(checkMap) > 0 {
					for _, v := range intercept_result {
						if _, ok := checkMap[v["ip"].(string)]; !ok {
							result = append(result, v)
						}
					}
					sort.Slice(result, func(i, j int) bool {
						return public.InterfaceToInt(result[i]["visits"]) > public.InterfaceToInt(result[j]["visits"])
					})
				}

				if len(result) > 100 {
					top = result[:100]
				} else {
					top = result
				}

				return result, err
			})

			if err != nil {
				return core.Fail("获取请求ip数据失败")
			}
			for _, v := range top.([]map[string]interface{}) {
				if c, ok := v["ip"].(string); ok {
					ipInfo := public.GetIPAreaIpInfo(c)
					v["city"] = ipInfo.City
					v["province"] = ipInfo.Province
					v["country"] = ipInfo.Country
				}
			}

		}

		if params["type"].(float64) == 1 {
			res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
				query := conn.NewQuery()
				query.Table("area_total").
					Where("date >= ?", []interface{}{date_n}).
					Field([]string{"any_value(date) as date",
						"any_value(city) as city",
						"any_value(province) as province",
						"any_value(country) as country",
						"SUM(request) as visits"})
				if params["country"].(float64) == 0 {
					query.Group("country")
				} else {
					query.Where("country = ?", []interface{}{"中国"})
					query.Group("province")
				}
				result, err := query.Select()
				sort.Slice(result, func(i, j int) bool {
					return result[i]["visits"].(float64) > result[j]["visits"].(float64)
				})
				if len(result) > 1000 {
					result = result[:1000]
				}
				if len(result) > 100 {
					top = result[:100]
				} else {
					top = result
				}

				return result, err
			})

			if err != nil {
				return core.Fail("获取请求地图地区失败")
			}

		}

	}

	if params["request"].(float64) == 1 {
		if params["type"].(float64) == 0 {
			res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
				query := conn.NewQuery()
				query.Table("ip_intercept").
					Where("date >= ?", []interface{}{date_n}).
					WhereNotIn("ip", []interface{}{"127.0.0.1"}).
					Field([]string{
						"any_value(ip) as ip",
						"any_value(country) as country",
						"any_value(city) as city",
						"any_value(province) as province",
						"request  as visits"}).
					Sort("visits", "desc").
					Limit([]int64{0, 5000})
				if params["country"].(float64) == 1 {
					query.Where("country = ?", []interface{}{"中国"})
				}
				result, err := query.Select()
				result = o.aggregateData(result)
				if len(result) > 100 {
					top = result[:100]
				} else {
					top = result
				}

				return result, err
			})

			if err != nil {
				return core.Fail("获取拦截地图ip失败")
			}
		}

		if params["type"].(float64) == 1 {
			res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
				query := conn.NewQuery()
				query.Table("area_intercept").
					Where("date >= ?", []interface{}{date_n}).
					Field([]string{
						"any_value(city) as city",
						"any_value(province) as province",
						"any_value(country) as country",
						"sum(request) as visits"})
				if params["country"].(float64) == 0 {
					query.Group("country")
				} else {
					query.Where("country = ?", []interface{}{"中国"})
					query.Group("province")
				}
				result, err := query.Select()
				sort.Slice(result, func(i, j int) bool {
					return result[i]["visits"].(float64) > result[j]["visits"].(float64)
				})
				if len(result) > 1000 {
					result = result[:1000]
				}

				if len(result) > 100 {
					top = result[:100]
				} else {
					top = result
				}

				return result, err
			})

			if err != nil {
				return core.Fail("获取拦截地图地区失败")
			}
		}

	}

	if len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}
	}
	if top == nil || len(top.([]map[string]interface{})) == 0 {
		top = []map[string]interface{}{}
	}
	for _, v := range top.([]map[string]interface{}) {
		if c, ok := v["ip"].(string); ok {
			if public.IsIpv4(c) {
				v["ip_type"] = 0
			} else {
				v["ip_type"] = 1
			}
		}
	}

	ress := map[string]interface{}{
		"list": res,
		"top":  top,
	}
	cache.Set(cacheKey, ress, 60)
	return core.Success(ress)
}

func (o *Overview) InterceptPage(request *http.Request) core.Response {
	cacheKey_count := "InterceptPage__Count"
	cacheKey_infos := "InterceptPage__Infos"
	cacheKey_site := "InterceptPage__SiteTop5"
	cacheKey_new := "InterceptPage__NewIntercept"
	cacheKey_address := "InterceptPage__IPAddress"
	allinfos := map[string]interface{}{
		"count":    map[string]interface{}{},
		"infos":    map[string]interface{}{},
		"siteTop5": []map[string]interface{}{},
		"newdata":  []map[string]interface{}{},
		"xyz":      map[string]interface{}{},
	}
	type IPTop struct {
		Ip         string `json:"ip"`
		IpCity     string `json:"ip_city"`
		IpCountry  string `json:"ip_country"`
		IpProvince string `json:"ip_province"`
		Visits     int    `json:"visits"`
	}
	if cache.Has(cacheKey_count) {
		allinfos["count"] = cache.Get(cacheKey_count)
	} else {
		count := o.interceptCountHelp()
		allinfos["count"] = count
		cache.Set(cacheKey_count, count, 2)
	}

	if cache.Has(cacheKey_infos) {
		allinfos["infos"] = cache.Get(cacheKey_infos)
	} else {
		infos := map[string]interface{}{
			"ip": []map[string]interface{}{},
		}
		enddate, _ := o.day_range()
		startdate := o.the_other_day(7)
		ip_infos := o.interceptMapHelp(startdate, enddate, 0, 0)
		var ip_top []IPTop
		for _, v := range ip_infos["top"].([]map[string]interface{}) {
			ip_top = append(ip_top, IPTop{
				Ip:         v["ip"].(string),
				IpCity:     v["city"].(string),
				IpCountry:  v["country"].(string),
				IpProvince: v["province"].(string),
				Visits:     int(v["visits"].(int64)),
			})
		}
		infos["ip"] = map[string]interface{}{
			"list": ip_infos["list"],
			"top":  ip_top,
		}

		infos["xyz"] = o.interceptXYZHelp()
		day7 := o.interceptTrendHelp(startdate, enddate)
		infos["day7"] = o.interceptTrendHelp1(day7)

		allinfos["infos"] = infos
		cache.Set(cacheKey_infos, infos, 60)
	}

	if cache.Has(cacheKey_site) {
		allinfos["siteTop5"] = cache.Get(cacheKey_site)
	} else {
		sitetop5 := o.interceptSiteTop5Help()
		allinfos["siteTop5"] = sitetop5
		cache.Set(cacheKey_site, sitetop5, 20)
	}

	if cache.Has(cacheKey_new) {
		allinfos["newdata"] = cache.Get(cacheKey_new)
	} else {
		newdata := o.interceptNewInterceptHelp(20)
		allinfos["newdata"] = newdata
		cache.Set(cacheKey_new, newdata, 2)
	}

	if cache.Has(cacheKey_address) {
		allinfos["xyz"] = cache.Get(cacheKey_address)
	} else {

		data := map[string]interface{}{}
		publicIpInfo, err := public.Rconfigfile(o.ip_path)
		if err == nil && publicIpInfo != nil && publicIpInfo["ip_longitude"] != "" && publicIpInfo["ip_latitude"] != "" {
			data = publicIpInfo
		} else {
			serverIp, _ := core.GetServerIp()
			ipInfo := public.GetIPAreaIpInfo(serverIp)
			data = map[string]interface{}{
				"ip_address":   serverIp,
				"ip_longitude": ipInfo.Longitude,
				"ip_latitude":  ipInfo.Latitude,
			}
		}

		allinfos["xyz"] = data
		cache.Set(cacheKey_address, data, 60*60*24)
	}

	return core.Success(allinfos)
}

func (o *Overview) SetIpAddress(request *http.Request) core.Response {
	paramss := struct {
		IpLongitude string `json:"ip_longitude"`
		IpLatitude  string `json:"ip_latitude"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &paramss); err != nil {
		return core.Fail(err)
	}
	if paramss.IpLatitude == "" || paramss.IpLongitude == "" {
		return core.Fail("请完整填写经纬度")
	}
	serverIp, _ := core.GetServerIp()

	IpInfo, err := public.Rconfigfile(o.ip_path)
	if err != nil || IpInfo == nil {
		data := map[string]interface{}{
			"ip_address":   serverIp,
			"ip_longitude": paramss.IpLongitude,
			"ip_latitude":  paramss.IpLatitude,
		}
		err = public.Wconfigfile(o.ip_path, data)
		if err != nil {
			return core.Fail("设置失败")
		}

	} else {
		if paramss.IpLatitude != "" && paramss.IpLongitude != "" {
			IpInfo["ip_latitude"] = paramss.IpLatitude
			IpInfo["ip_longitude"] = paramss.IpLongitude
			err = public.Wconfigfile(o.ip_path, IpInfo)
			if err != nil {
				return core.Fail("设置失败")
			}
		}

	}
	data := map[string]interface{}{
		"ip_address":   serverIp,
		"ip_longitude": paramss.IpLongitude,
		"ip_latitude":  paramss.IpLatitude,
	}

	cacheKey_address := "InterceptPage__IPAddress"
	cache.Set(cacheKey_address, data, 60*60*24)

	return core.Success("设置成功")
}

func (o *Overview) clusterCountHelp() map[string]interface{} {
	timestamp := public.ZeroTimestamp()
	query := public.M("cluster_day_counts")
	query.Where("timestamp_day = ?", []interface{}{timestamp}).
		Field([]string{
			"ifnull(SUM(total), 0) as `total`",
			"ifnull(SUM(malicious), 0) as `malicious`",
			"ifnull(SUM(ip), 0) as `ip`",
		})

	data, err := query.Find()
	site, _ := public.M("site_info").Count()
	if err != nil {
		data = map[string]interface{}{
			"total":     0,
			"malicious": 0,
			"ip":        0,
			"site":      0,
		}
	}
	data["site"] = site
	return data

}

func (o *Overview) clusterRequestTrendHelp() []map[string]interface{} {
	now := time.Now().Unix()
	start := now - 60*60*24*2
	query := public.M("cluster_request_trend")
	query.Where("timestamp_minute >= ?", []interface{}{start}).
		Where("timestamp_minute <= ?", []interface{}{now}).
		Field([]string{
			"sum(err_499) as `err_499`",
			"sum(err_502) as `err_502`",
			"sum(err_504) as `err_504`",
			"sum(total) as `total`",
			"timestamp_minute",
		})
	query.Group("timestamp_minute")
	query.Sort("timestamp_minute", "asc")
	data, err := query.Select()
	if err != nil {
		data = []map[string]interface{}{}
	}
	return data

}

func (o *Overview) clusterInterceptHelp() []map[string]interface{} {
	query := public.M("cluster_totla_log_all_merge")
	query.Field([]string{
		"id",
		"node_id",
		"server_name",
		"ip",
		"method",
		"request_uri",
		"uri",
		"action",
		"host",
		"ip_city",
		"ip_province",
		"ip_country",
		"time",
		"risk_type",
	})
	query.Sort("time", "desc")
	query.Limit([]int64{0, 20})

	data, err := query.Select()

	if err != nil {
		data = []map[string]interface{}{}
	}
	return data

}

func (o *Overview) clusterSlowRequestHelp() []map[string]interface{} {
	query := public.M("cluster_slow_log")
	query.Field([]string{
		"id",
		"server_name",
		"domain",
		"ip",
		"method",
		"request_uri",
		"times",
		"timestamp",
	})
	query.Sort("timestamp", "desc")
	query.Limit([]int64{0, 20})
	data, err := query.Select()
	if err != nil {
		return []map[string]interface{}{}
	}
	if len(data) == 0 {
		return []map[string]interface{}{}
	}
	ip_list := []int{}
	ip_map := map[string]string{}
	method_list := []int{}
	method_map := map[string]string{}
	request_uri_list := []int{}
	request_uri_map := map[string]string{}
	for _, v := range data {
		if c, ok := v["ip"].(int); ok {
			ip_list = append(ip_list, c)
		}
		if d, ok := v["method"].(int); ok {
			method_list = append(method_list, d)
		}
		if e, ok := v["request_uri"].(int); ok {
			request_uri_list = append(request_uri_list, e)
		}
	}
	if len(ip_list) > 0 {
		ip_lists, _ := public.M("ip").WhereIn("id", ip_list).Field([]string{"id", "ip"}).Select()
		for _, v := range ip_lists {
			if c, ok := v["id"].(int64); ok {
				ip_map[public.Int64ToString(c)] = v["ip"].(string)
			}
		}
	}
	if len(method_list) > 0 {
		method_lists, _ := public.M("method").WhereIn("id", method_list).Field([]string{"id", "method"}).Select()
		for _, v := range method_lists {
			if c, ok := v["id"].(int64); ok {
				method_map[public.Int64ToString(c)] = v["method"].(string)
			}
		}
	}
	if len(request_uri_list) > 0 {
		request_uri_lists, _ := public.M("request_uri").WhereIn("id", request_uri_list).Field([]string{"id", "request_uri"}).Select()
		for _, v := range request_uri_lists {
			if c, ok := v["id"].(int64); ok {
				request_uri_map[public.Int64ToString(c)] = v["request_uri"].(string)
			}
		}
	}
	for _, v := range data {
		if c, ok := v["ip"].(int); ok {
			v["ip"] = ip_map[public.IntToString(c)]
		}
		if d, ok := v["method"].(int); ok {
			v["method"] = method_map[public.IntToString(d)]
		}
		if e, ok := v["request_uri"].(int); ok {
			v["request_uri"] = request_uri_map[public.IntToString(e)]
		}
	}

	if err != nil {
		data = []map[string]interface{}{}
	}
	return data

}

func (o *Overview) clusterMapHelp(params map[string]interface{}) map[string]interface{} {
	cacheKey := "ClusterOverView__Map_" + fmt.Sprintf("Request%v", params["request"]) + "_" + fmt.Sprintf("country%v", params["country"]) + "_" + fmt.Sprintf("type%v", params["type"]) + "_" + fmt.Sprintf("query_data%d", params["query_data"])

	if cache.Has(cacheKey) {
		return cache.Get(cacheKey).(map[string]interface{})
	}
	date_n := o.the_other_day(30)
	is_yesterday := false
	if v, ok := params["query_data"].(float64); ok {
		date_n = o.the_other_day(int(v))
		if v == 1 {
			is_yesterday = true
		}
	}
	timestamp_n := public.GetDayZeroTime(date_n)
	var res []map[string]interface{}
	var top []map[string]interface{}

	if params["request"].(float64) == 0 {
		query := public.M("cluster_request_map_area")
		if is_yesterday {
			query.Where("timestamp_day = ?", []interface{}{timestamp_n})
		} else {
			query.Where("timestamp_day >= ?", []interface{}{timestamp_n})
		}
		query.Field([]string{
			"ifnull(SUM(visits), 0) as `visits`",
			"any_value(ip_country) as ip_country",
			"any_value(ip_province) as ip_province",
			"any_value(ip_city) as ip_city",
			"any_value(is_inland) as is_inland",
		})

		if params["country"].(float64) == 0 {
			query.Group("ip_country")
		} else {
			query.Where("is_inland = ?", []interface{}{1})
			query.Group("ip_province")
		}
		areaResult, err := query.Select()
		if err != nil {
			areaResult = []map[string]interface{}{}
			res = areaResult
		}

		if len(areaResult) > 0 {
			sort.Slice(areaResult, func(i, j int) bool {
				return areaResult[i]["visits"].(float64) > areaResult[j]["visits"].(float64)
			})
			if len(areaResult) > 1000 {
				res = areaResult[:1000]
			} else {
				res = areaResult
			}
		} else {
			res = areaResult
		}
		if params["type"].(float64) == 0 {

			query_ip := public.M("cluster_request_map_ip")
			if is_yesterday {
				query_ip.Where("timestamp_day = ?", []interface{}{timestamp_n})
			} else {
				query_ip.Where("timestamp_day >= ?", []interface{}{timestamp_n})
			}
			query_ip.WhereNotIn("ip", []interface{}{"127.0.0.1"})
			query_ip.Field([]string{
				"any_value(ip_country) as ip_country",
				"any_value(ip_province) as ip_province",
				"any_value(ip_city) as ip_city",
				"any_value(is_inland) as is_inland",
				"any_value(ip) as ip",
				"any_value(visits) as visits",
			})

			if params["country"].(float64) == 1 {
				query_ip.Where("is_inland = ?", []interface{}{1})
			}
			query_ip.Sort("visits", "desc").Limit([]int64{0, 5000})
			ipResult, err := query_ip.Select()
			if err != nil {
				ipResult = []map[string]interface{}{}
				top = ipResult
			}
			if len(ipResult) > 1 {
				ipResult = o.aggregateData(ipResult)

				if len(ipResult) > 100 {
					top = ipResult[:100]
				} else {
					top = ipResult
				}

			} else {
				top = ipResult
			}
			res = ipResult
		}
		if params["type"].(float64) == 1 {
			if len(res) > 100 {
				top = res[:100]
			} else {
				top = res
			}
		}

	}
	if params["request"].(float64) == 1 {
		query := public.M("cluster_intercept_map_area")
		if is_yesterday {
			query.Where("timestamp_day = ?", []interface{}{timestamp_n})
		} else {
			query.Where("timestamp_day >= ?", []interface{}{timestamp_n})
		}
		query.Field([]string{
			"any_value(ip_country) as ip_country",
			"any_value(ip_province) as ip_province",
			"any_value(ip_city) as ip_city",
			"any_value(is_inland) as is_inland",
			"ifnull(SUM(visits), 0) as `visits`",
		})

		if params["country"].(float64) == 0 {
			query.Group("ip_country")
		} else {
			query.Where("is_inland = ?", []interface{}{1})
			query.Group("ip_province")
		}
		areaResult, err := query.Select()
		if err != nil {
			areaResult = []map[string]interface{}{}
			res = areaResult
		}
		if len(areaResult) > 0 {
			sort.Slice(areaResult, func(i, j int) bool {
				return areaResult[i]["visits"].(float64) > areaResult[j]["visits"].(float64)
			})
			if len(areaResult) > 1000 {
				res = areaResult[:1000]
			} else {
				res = areaResult
			}
		} else {
			res = areaResult
		}
		if params["type"].(float64) == 0 {
			query_ip := public.M("cluster_intercept_map_ip")
			if is_yesterday {
				query_ip.Where("timestamp_day = ?", []interface{}{timestamp_n})
			} else {
				query_ip.Where("timestamp_day >= ?", []interface{}{timestamp_n})
			}
			query_ip.WhereNotIn("ip", []interface{}{"127.0.0.1"}).
				Field([]string{
					"any_value(ip_country) as ip_country",
					"any_value(ip_province) as ip_province",
					"any_value(ip_city) as ip_city",
					"any_value(is_inland) as is_inland",
					"any_value(ip) as ip",
					"any_value(visits) as visits",
				})

			if params["country"].(float64) == 1 {
				query_ip.Where("is_inland = ?", []interface{}{1})
			}
			query_ip.Sort("visits", "desc").Limit([]int64{0, 5000})
			ipResult, err := query_ip.Select()
			if err != nil {
				ipResult = []map[string]interface{}{}
				top = ipResult
			}
			if len(ipResult) > 1 {
				ipResult = o.aggregateData(ipResult)

				if len(ipResult) > 100 {
					top = ipResult[:100]
				} else {
					top = ipResult
				}
			} else {
				top = ipResult
			}
		}
		if params["type"].(float64) == 1 {
			if len(res) > 100 {
				top = res[:100]
			} else {
				top = res
			}
		}
	}

	if len(top) > 0 {
		for _, v := range top {
			if c, ok := v["ip"].(string); ok {
				if public.IsIpv4(c) {
					v["ip_type"] = 0
				} else {
					v["ip_type"] = 1
				}
			}
		}
	}
	ress := map[string]interface{}{
		"list": res,
		"top":  top,
	}
	cache.Set(cacheKey, ress, 2)
	return ress

}

func (o *Overview) realTime() (map[string]interface{}, error) {
	var request_total float64
	var proxy_time float64
	var recv_bytes float64
	var send_bytes float64
	var qps float64
	res, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15)

	if err != nil {
		proxy_time = 0
		recv_bytes = 0
		send_bytes = 0
		qps = 0
	}
	file_data := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(res), &file_data)
	if err != nil {
		proxy_time = 0
		recv_bytes = 0
		send_bytes = 0
		qps = 0
		request_total = 0
	}

	if v, ok := file_data["msg"]; ok {
		if c, ok := v.(map[string]interface{}); ok {
			proxy_time = c["proxy_time"].(float64)
			recv_bytes = c["recv_bytes"].(float64)
			send_bytes = c["send_bytes"].(float64)
			qps = c["qps"].(float64)

			if x, ok := c["today"].(map[string]interface{}); ok {
				request_total = x["req"].(float64)
			}

		}
	}

	nginx := map[string]interface{}{
		"request_total": request_total,
		"proxy_time":    proxy_time,
		"recv_bytes":    recv_bytes,
		"send_bytes":    send_bytes,
		"qps":           qps,
	}

	return nginx, nil
}

func (o *Overview) day_range() (string, int) {
	currentTime := time.Now()
	startDate := currentTime.Format("2006-01-02")
	startHour := currentTime.Hour()
	return startDate, startHour
}

func (o *Overview) the_other_day(days int) string {
	now := time.Now()
	previousDate := now.AddDate(0, 0, -days)
	previousDateString := previousDate.Format("2006-01-02")
	return previousDateString
}

func (o *Overview) the_other_day_new(current time.Time, days int) (string, []string) {
	previousDate := current.AddDate(0, 0, -days)
	previousDateString := previousDate.Format("2006-01-02")
	previousDateList := make([]string, 0)
	for i := 1; i <= days; i++ {
		previousDateList = append(previousDateList, previousDate.AddDate(0, 0, i).Format("2006-01-02"))
	}

	return previousDateString, previousDateList
}

func (o *Overview) completeMissingData(originalData []map[string]interface{}, fields []string) []map[string]interface{} {
	completedData := make([]map[string]interface{}, 0)
	now := time.Now()
	existingData := make(map[int64]bool)
	for _, d := range originalData {
		if data_m, ok := d["data_m"].(int64); ok {
			existingData[data_m] = true
		}
	}
	for i := 0; i < 60; i++ {
		currentHour, currentMinute, _ := now.Add(-time.Minute * time.Duration(i)).Clock()
		currentDataM := int64(currentHour*60 + currentMinute)
		if _, exists := existingData[currentDataM]; exists {
			for _, d := range originalData {
				if data_m, ok := d["data_m"].(int64); ok && data_m == currentDataM {
					completedData = append(completedData, d)
					break
				}
			}
		} else {
			newData := make(map[string]interface{})
			newData["data_m"] = currentDataM
			newData["date"] = now.Format("2006-01-02")
			newData["hour"] = currentHour
			newData["minute"] = currentMinute

			for _, field := range fields {
				newData[field] = 0
			}
			completedData = append(completedData, newData)
		}
	}
	sort.Slice(completedData, func(i, j int) bool {
		return completedData[i]["data_m"].(int64) > completedData[j]["data_m"].(int64)
	})

	return completedData
}

func (o *Overview) completeMissingDataStruct_New(originalData []types.OverViewRequest, key int, fields []string, datas string) []types.OverViewRequest {
	completedData := make([]types.OverViewRequest, 0)
	existingData := make(map[int64]bool)
	sort.Slice(originalData, func(i, j int) bool {
		return originalData[i].Datam > originalData[j].Datam
	})
	for _, d := range originalData {
		existingData[d.Datam] = true
	}
	var maxDataM int64
	var minDataM int64
	if key == 1 {
		maxDataM = originalData[0].Datam
		minDataM = int64(0)
	} else {
		minDataM = originalData[len(originalData)-1].Datam
		maxDataM = int64(24*60 - 1)
	}
	for currentDataM := minDataM; currentDataM <= maxDataM; currentDataM++ {
		if _, exists := existingData[currentDataM]; exists {
			for _, d := range originalData {
				if d.Datam == currentDataM {
					completedData = append(completedData, d)
					break
				}
			}
		} else {
			if currentDataM > maxDataM {
				continue
			}
			if currentDataM < minDataM {
				continue
			}
			minuteStr := fmt.Sprintf("%02d", currentDataM%60)
			hourStr := fmt.Sprintf("%02d", currentDataM/60)
			t, err := public.ParseDateStrToTime("2006-01-02 15:04", datas+" "+hourStr+":"+minuteStr)
			if err != nil {
				continue
			}

			newData := types.OverViewRequest{
				Datam:     currentDataM,
				Date:      datas,
				Hour:      currentDataM / 60,
				Minute:    currentDataM % 60,
				Timestamp: t.Unix(),
			}

			for _, field := range fields {
				switch field {
				case "err_499":
					newData.Err499 = 0
				case "err_502":
					newData.Err502 = 0
				case "err_504":
					newData.Err504 = 0
				case "request":
					newData.Request = 0
				}
			}

			completedData = append(completedData, newData)
		}
	}
	sort.Slice(completedData, func(i, j int) bool {
		return completedData[i].Timestamp > completedData[j].Timestamp
	})

	return completedData
}

func (o *Overview) completeMissingDataStruct(originalData []types.OverViewRequest, key int, fields []string) []types.OverViewRequest {
	completedData := make([]types.OverViewRequest, 0)
	now := time.Now()
	existingData := make(map[int64]bool)
	sort.Slice(originalData, func(i, j int) bool {
		return originalData[i].Datam > originalData[j].Datam
	})
	for _, d := range originalData {
		existingData[d.Datam] = true
	}
	var maxDataM int64
	var minDataM int64
	var datas string
	if key == 1 {
		maxDataM = originalData[0].Datam
		minDataM = int64(0)
		datas = now.Format("2006-01-02")
	} else {
		minDataM = originalData[len(originalData)-1].Datam
		maxDataM = int64(24*60 - 1)
		datas = now.AddDate(0, 0, -1).Format("2006-01-02")
	}
	for currentDataM := minDataM; currentDataM <= maxDataM; currentDataM++ {
		if _, exists := existingData[currentDataM]; exists {
			for _, d := range originalData {
				if d.Datam == currentDataM {
					completedData = append(completedData, d)
					break
				}
			}
		} else {
			if currentDataM > maxDataM {
				continue
			}
			if currentDataM < minDataM {
				continue
			}
			minuteStr := fmt.Sprintf("%02d", currentDataM%60)
			hourStr := fmt.Sprintf("%02d", currentDataM/60)
			t, err := public.ParseDateStrToTime("2006-01-02 15:04", datas+" "+hourStr+":"+minuteStr)
			if err != nil {
				continue
			}

			newData := types.OverViewRequest{
				Datam:     currentDataM,
				Date:      datas,
				Hour:      currentDataM / 60,
				Minute:    currentDataM % 60,
				Timestamp: t.Unix(),
			}

			for _, field := range fields {
				switch field {
				case "err_499":
					newData.Err499 = 0
				case "err_502":
					newData.Err502 = 0
				case "err_504":
					newData.Err504 = 0
				case "request":
					newData.Request = 0
				}
			}
			completedData = append(completedData, newData)
		}
	}
	sort.Slice(completedData, func(i, j int) bool {
		return completedData[i].Timestamp > completedData[j].Timestamp
	})

	return completedData
}

func (o *Overview) slowRequest(sites string) []map[string]interface{} {
	result := make([]map[string]any, 0)
	path := fmt.Sprintf("/www/cloud_waf/nginx/logs/%s.slow.log", sites)
	data, err := public.Tail(path, 20)
	if err != nil {
		return result
	}
	data = strings.TrimSpace(data)
	if data != "" {
		lines := strings.Split(data, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)

			if line == "" {
				continue
			}

			parts := strings.Split(line, " ")
			if len(parts) < 7 {
				continue
			}
			uri := parts[5]
			times := parts[6]
			date := parts[1] + " " + parts[2]
			date = date[1 : len(date)-1]
			entry := make(map[string]interface{})
			entry["uri"] = uri
			entry["times"] = public.StringToInt(times)
			entry["date"] = date
			entry["server_name"] = parts[3]
			entry["host"] = parts[0]
			entry["sites_id"] = sites

			result = append(result, entry)
		}
		sort.Slice(result, func(i, j int) bool {
			return result[i]["date"].(string) > result[j]["date"].(string)
		})
	}

	return result

}

func (o *Overview) aggregateData(data []map[string]interface{}) []map[string]interface{} {
	aggregatedData := make(map[string]int64)

	for key, item := range data {
		ip := item["ip"].(string)
		if item["visits"] == nil {
			data[key]["visits"] = int64(0)
		} else {
			visits := item["visits"].(int64)
			aggregatedData[ip] += visits
		}

	}

	uniqueData := make([]map[string]interface{}, 0)
	for _, item := range data {
		ip := item["ip"].(string)
		if aggregatedData[ip] > 0 {
			item["visits"] = aggregatedData[ip]
			uniqueData = append(uniqueData, item)
			aggregatedData[ip] = 0
		}
	}

	sort.Slice(uniqueData, func(i, j int) bool {
		return uniqueData[i]["visits"].(int64) > uniqueData[j]["visits"].(int64)
	})
	return uniqueData
}

func (o *Overview) aggregateData1(originalData []types.OverViewRequest) []types.OverViewRequest {

	aggregatedData := make(map[string]*types.OverViewRequest)

	for _, data := range originalData {
		key := fmt.Sprintf("%s-%02d-%02d", data.Date, data.Hour, data.Minute)
		if _, exists := aggregatedData[key]; exists {
			aggregatedData[key].Err499 += data.Err499
			aggregatedData[key].Err502 += data.Err502
			aggregatedData[key].Err504 += data.Err504
			aggregatedData[key].Request += data.Request
			aggregatedData[key].Date = data.Date
			aggregatedData[key].Hour = data.Hour
			aggregatedData[key].Minute = data.Minute
			aggregatedData[key].Datam = data.Datam
			aggregatedData[key].Id = data.Id
			aggregatedData[key].Timestamp = data.Timestamp

		} else {
			aggregatedData[key] = &types.OverViewRequest{
				Id:        data.Id,
				Date:      data.Date,
				Err499:    data.Err499,
				Err502:    data.Err502,
				Err504:    data.Err504,
				Hour:      data.Hour,
				Minute:    data.Minute,
				Request:   data.Request,
				Datam:     data.Datam,
				Timestamp: data.Timestamp,
			}

		}
	}

	aggregatedSlice := make([]types.OverViewRequest, 0, len(aggregatedData))
	for _, data := range aggregatedData {
		aggregatedSlice = append(aggregatedSlice, *data)
	}
	sort.Slice(aggregatedSlice, func(i, j int) bool {
		return aggregatedSlice[i].Timestamp > aggregatedSlice[j].Timestamp
	})

	return aggregatedSlice
}

func (o *Overview) interceptCountHelp() map[string]interface{} {
	var today float64
	var all float64
	startDate, _ := o.day_range()
	query2 := public.M("ip_intercept")
	query2.Where("date = ?", []interface{}{startDate}).
		Field([]string{"sum(request) as `total`"})
	todayCount, err := query2.Find()

	if err != nil {
		today = 0
	}
	if todayCount["total"] != nil {
		today = todayCount["total"].(float64)
	}
	query1 := public.M("ip_intercept")
	query1.Field([]string{"sum(request) as `total`"})
	allCount, err := query1.Find()
	if err != nil {
		all = today
	}
	if allCount["total"] != nil {
		all = allCount["total"].(float64)
	}

	return map[string]interface{}{
		"todayCount": today,
		"allCount":   all,
	}

}

func (o *Overview) interceptSiteTop5Help() []map[string]interface{} {
	startDate, _ := o.day_range()
	query := public.M("ip_intercept")
	query.Where("date = ?", []interface{}{startDate}).
		Field([]string{"server_name", "sum(request) as `total`"}).
		Group("server_name").
		Sort("total", "desc").
		Limit([]int64{0, 5})
	sitetop5, err := query.Select()
	if err != nil {
		sitetop5 = []map[string]interface{}{}
	}
	return sitetop5
}

func (o *Overview) interceptNewInterceptHelp(count int64) []map[string]interface{} {
	query := public.M("totla_log")
	query.Field([]string{"id", "time", "ip", "action",
		"ip_city", "ip_country", "ip_province",
		"request_uri", "host", "risk_type",
	}).
		Order("time", "desc").
		Limit([]int64{0, count})
	newdata, err := query.Select()

	if err != nil {
		newdata = []map[string]interface{}{}
	}
	return newdata
}

func (o *Overview) interceptXYZHelp() []map[string]interface{} {
	timestamp, _ := public.GetLastDaysByTimestamp(7)
	query := public.M("totla_log")
	query.Where("time >= ?", []interface{}{timestamp}).
		Field([]string{"id", "time", "ip",
			"ip_longitude", "ip_latitude",
		}).
		Order("time", "desc")
	newdata, err := query.Select()
	if err != nil {
		newdata = []map[string]interface{}{}
	}
	return newdata
}

func (o *Overview) interceptTrendHelp(startdate string, enddate string) []map[string]interface{} {
	query := public.M("ip_intercept")
	query.Where("date >= ?", []interface{}{startdate}).
		Where("date <= ?", []interface{}{enddate}).
		WhereNotIn("ip", []interface{}{"127.0.0.1"}).
		Field([]string{
			"any_value(date) as date",
			"sum(request) as `total`"}).
		Group("date")

	result, err := query.Select()
	if err != nil {
		return []map[string]interface{}{}
	}
	return result
}

func (o *Overview) interceptTrendHelp1(data []map[string]interface{}) []map[string]interface{} {
	currentDate := time.Now().Format("2006-01-02")
	currentDateTime, _ := public.ParseDateStrToTime("2006-01-02", currentDate)
	dateMap := make(map[string]bool)
	for _, d := range data {
		if dateStr, ok := d["date"].(string); ok {
			dateMap[dateStr] = true
		}
	}
	for i := 0; i < 7; i++ {
		date := currentDateTime.AddDate(0, 0, -i).Format("2006-01-02")
		if !dateMap[date] {
			data = append(data, map[string]interface{}{
				"date":  date,
				"total": 0,
			})
		}
	}
	sort.Slice(data, func(i, j int) bool {
		return data[i]["date"].(string) < data[j]["date"].(string)
	})

	return data
}

func (o *Overview) requestTotalHelp(start int64, end int64) []types.OverViewRequest {
	starts := o.timestampToTime(start)
	ends := o.timestampToTime(end)
	startdata := starts["date"].(string)
	starthour := starts["hour"].(string)
	startminute := starts["minute"].(string)

	enddata := ends["date"].(string)
	endhour := ends["hour"].(string)
	endminute := ends["minute"].(string)

	query := public.M("request_total")
	query.Where("date >= ?", []interface{}{startdata}).
		Where("hour >= ?", []interface{}{starthour}).
		Where("minute >= ?", []interface{}{startminute}).
		Where("date <= ?", []interface{}{enddata}).
		Where("hour <= ?", []interface{}{endhour}).
		Where("minute <= ?", []interface{}{endminute}).
		Field([]string{
			"any_value(id) as id",
			"any_value(date) as date",
			"any_value(request) as request",
			"any_value(err_499) as err_499",
			"any_value(err_502) as err_502",
			"any_value(err_504) as err_504",
			"any_value(hour) as hour",
			"any_value(minute) as minute",
			"(`hour`*60+ `minute`) AS `data_m`"}).
		Order("id", "desc")

	result, err := query.Select()
	if err != nil {
		return []types.OverViewRequest{}
	}
	var result_a []types.OverViewRequest
	for _, v := range result {
		timestamp := o.dateToTimestamp(v["date"].(string), v["hour"].(int64), v["minute"].(int64))
		result_a = append(result_a, types.OverViewRequest{
			Id:        v["id"].(int64),
			Date:      v["date"].(string),
			Err499:    v["err_499"].(int64),
			Err502:    v["err_502"].(int64),
			Err504:    v["err_504"].(int64),
			Request:   v["request"].(int64),
			Hour:      v["hour"].(int64),
			Minute:    v["minute"].(int64),
			Timestamp: timestamp,
		})
	}
	result_a = o.aggregateData1(result_a)
	result_a = o.requestTrendHelp(start, end, result_a)
	sort.Slice(result_a, func(i, j int) bool {
		return result_a[i].Timestamp > result_a[j].Timestamp
	})

	return result_a
}

func (o *Overview) infosHelp(start int64, end int64) []map[string]interface{} {
	query := public.M("totla_log")
	query.Where("time >= ?", []interface{}{start}).
		Where("time <= ?", []interface{}{end}).
		Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "action",
			"ip_province", "request_uri", "host", "risk_type",
		}).
		Order("time", "desc")
	intercept, err := query.Select()
	if err != nil {
		return []map[string]interface{}{}
	}
	if len(intercept) == 0 {
		intercept = []map[string]interface{}{}
	}
	return intercept

}

func (o *Overview) slowHelp() []map[string]interface{} {

	resultAll := make([]map[string]any, 0)
	servers, _ := public.GetAllDomain()
	for _, server := range servers {
		result := make([]map[string]any, 0)
		path := fmt.Sprintf("/www/cloud_waf/nginx/logs/%s.slow.log", server["site_id"])
		data, err := public.Tail(path, 20)
		if err != nil {
			continue
		}
		data = strings.TrimSpace(data)
		if data != "" {
			lines := strings.Split(data, "\n")

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, " ")
				if len(parts) < 7 {
					continue
				}
				date := parts[1] + " " + parts[2]
				date = date[1 : len(date)-1]
				entry := make(map[string]interface{})
				entry["uri"] = parts[5]
				entry["times"] = public.StringToInt(parts[6])
				entry["date"] = date
				entry["server_name"] = parts[3]
				entry["host"] = parts[0]
				entry["name"] = server["site_id"]
				entry["domain"] = server["site_name"]

				result = append(result, entry)
			}
		}
		resultAll = append(resultAll, result...)
	}
	sort.Slice(resultAll, func(i, j int) bool {
		return resultAll[i]["date"].(string) > resultAll[j]["date"].(string)
	})

	return resultAll
}

func (o *Overview) countsHelp() map[string]interface{} {
	timestamp := time.Now().Unix()
	starts := o.timestampToTime(timestamp)
	startdata := starts["date"].(string)
	data := map[string]interface{}{
		"request_total":   0,
		"malicious_total": 0,
		"ips_total":       0,
	}

	query := public.M("ip_intercept")
	query.Where("date = ?", []interface{}{startdata}).
		Field([]string{"ifnull(SUM(request), 0) as `total`"})
	result, err := query.Find()
	if err != nil {
		data["malicious_total"] = 0
	} else {
		data["malicious_total"] = result["total"]
	}
	query1 := public.M("ip_total")
	query1.Where("date = ?", []interface{}{startdata}).
		Field([]string{
			"ifnull(SUM(request), 0) as `request_total`",
		})

	result1, err := query1.Find()

	if err != nil {
		data["request_total"] = 0
	} else {
		data["request_total"] = result1["request_total"]
	}
	query2 := public.M("ip_total")
	query2.Where("date = ?", []interface{}{startdata}).
		Field([]string{"ip"}).
		Group("ip")

	result2, err := query2.Select()
	if err != nil {
		data["ips_total"] = 0
	} else {
		data["ips_total"] = len(result2)
	}

	return data

}

func (o *Overview) timestampToTime(timestamp int64) map[string]interface{} {
	tm := time.Unix(timestamp, 0)
	data := map[string]interface{}{
		"date":   tm.Format("2006-01-02"),
		"hour":   tm.Format("15"),
		"minute": tm.Format("04"),
	}
	return data
}

func (o *Overview) mapHelp(start int64, end int64) map[string]interface{} {
	starts := o.timestampToTime(start)
	ends := o.timestampToTime(end)
	startdate := starts["date"].(string)
	enddate := ends["date"].(string)

	data := map[string]interface{}{
		"g_ip_r":    map[string]interface{}{},
		"c_ip_r":    map[string]interface{}{},
		"g_area_r":  map[string]interface{}{},
		"c_area_r":  map[string]interface{}{},
		"g_ip_in":   map[string]interface{}{},
		"c_ip_in":   map[string]interface{}{},
		"g_area_in": map[string]interface{}{},
		"c_area_in": map[string]interface{}{},
	}
	data["g_ip_r"] = o.requestMapHelp(startdate, enddate, 0, 0)
	data["c_ip_r"] = o.requestMapHelp(startdate, enddate, 0, 1)
	data["g_area_r"] = o.requestMapHelp(startdate, enddate, 1, 0)
	data["c_area_r"] = o.requestMapHelp(startdate, enddate, 1, 1)
	data["g_ip_in"] = o.interceptMapHelp(startdate, enddate, 0, 0)
	data["c_ip_in"] = o.interceptMapHelp(startdate, enddate, 0, 1)
	data["g_area_in"] = o.interceptMapHelp(startdate, enddate, 1, 0)
	data["c_area_in"] = o.interceptMapHelp(startdate, enddate, 1, 1)

	return data

}

func (o *Overview) requestMapHelp(startdata string, enddata string, types int, country int) map[string]interface{} {

	data := map[string]interface{}{
		"list": []map[string]interface{}{},
		"top":  []map[string]interface{}{},
	}
	if types == 0 {

		query := public.M("ip_total")
		query.Where("date >= ?", []interface{}{startdata}).
			Where("date <= ?", []interface{}{enddata}).
			WhereNotIn("ip", []interface{}{"127.0.0.1"}).
			Field([]string{
				"any_value(date) as date",
				"any_value(ip) as ip",
				"request as visits"}).
			Sort("visits", "desc")

		if country == 1 {
			query.Where("is_inland = ?", []interface{}{1})
		}
		result, err := query.Select()
		if err != nil {
			return map[string]interface{}{}
		}
		result = o.aggregateData(result)
		data["list"] = result
		if len(result) > 100 {
			result = result[:100]
		}

		for _, v := range result {
			if c, ok := v["ip"].(string); ok {
				ipInfo := public.GetIPAreaIpInfo(c)
				v["city"] = ipInfo.City
				v["province"] = ipInfo.Province
				v["country"] = ipInfo.Country
			}
		}
		data["top"] = result
	}
	if types == 1 {
		query := public.M("area_total")
		query.Where("date >= ?", []interface{}{startdata}).
			Where("date <= ?", []interface{}{enddata}).
			Field([]string{"any_value(date) as date",
				"any_value(city) as city",
				"any_value(province) as province",
				"any_value(country) as country",
				"SUM(request) as visits"})
		if country == 0 {
			query.Group("country")
		} else {
			query.Where("country = ?", []interface{}{"中国"})
			query.Group("province")
		}
		result, err := query.Select()
		if err != nil {
			return map[string]interface{}{}
		}
		sort.Slice(result, func(i, j int) bool {
			return result[i]["visits"].(float64) > result[j]["visits"].(float64)
		})
		if len(result) > 1000 {
			result = result[:1000]
		}
		data["list"] = result

		if len(result) > 100 {
			data["top"] = result[:100]
		} else {
			data["top"] = result
		}

	}

	return data
}

func (o *Overview) requestMapRenderHelp(stardata string, enddata string, country int) []map[string]interface{} {
	query := public.M("area_total")
	query.Where("date >= ?", []interface{}{stardata}).
		Where("date <= ?", []interface{}{enddata}).
		Field([]string{
			"any_value(date) as date",
			"any_value(province) as province",
			"any_value(country) as country",
			"SUM(request) as visits",
		}).Sort("visits", "desc")

	if country == 0 {
		query.Group("country")
	} else {
		query.Where("country = ?", []interface{}{"中国"})
		query.Group("province")
	}
	result, err := query.Select()
	if len(result) > 1000 {
		result = result[:1000]
	}
	if err != nil {
		result = []map[string]interface{}{}
	}
	return result
}

func (o *Overview) interceptMapHelp(startdata string, enddata string, types int, country int) map[string]interface{} {
	data := map[string]interface{}{
		"list": []map[string]interface{}{},
		"top":  []map[string]interface{}{},
	}
	if types == 0 {
		query := public.M("ip_intercept")
		query.Where("date >= ?", []interface{}{startdata}).
			Where("date <= ?", []interface{}{enddata}).
			WhereNotIn("ip", []interface{}{"127.0.0.1"}).
			Field([]string{
				"any_value(date) as date",
				"any_value(ip) as ip",
				"any_value(country) as country",
				"any_value(city) as city",
				"any_value(province) as province",
				"request  as visits"}).
			Sort("visits", "desc")

		if country == 1 {
			query.Where("country = ?", []interface{}{"中国"})
		}

		result, err := query.Select()
		if err != nil {
			return map[string]interface{}{}
		}
		result = o.aggregateData(result)
		data["list"] = result
		if len(result) > 100 {
			result = result[:100]
		}
		data["top"] = result
	}
	if types == 1 {

		query := public.M("area_intercept")
		query.Where("date >= ?", []interface{}{startdata}).
			Where("date <= ?", []interface{}{enddata}).
			Field([]string{
				"any_value(date) as date",
				"any_value(city) as city",
				"any_value(province) as province",
				"any_value(country) as country",
				"sum(request) as visits"})
		if country == 0 {
			query.Group("country")
		} else {
			query.Where("country = ?", []interface{}{"中国"})
			query.Group("province")
		}
		result, err := query.Select()
		if err != nil {
			return map[string]interface{}{}
		}
		sort.Slice(result, func(i, j int) bool {
			return result[i]["visits"].(float64) > result[j]["visits"].(float64)
		})
		if len(result) > 1000 {
			result = result[:1000]
		}
		data["list"] = result
		if len(result) > 100 {
			data["top"] = result[:100]
		} else {
			data["top"] = result
		}
	}

	return data
}

func (o *Overview) interceptMapRenderHelp(stardata string, enddata string, country int) []map[string]interface{} {
	query := public.M("area_intercept")
	query.Where("date >= ?", []interface{}{stardata}).
		Where("date <= ?", []interface{}{enddata}).
		Field([]string{
			"any_value(date) as date",
			"any_value(city) as city",
			"any_value(province) as province",
			"any_value(country) as country",
			"sum(request) as visits"})
	if country == 0 {
		query.Group("country")
	} else {
		query.Where("country = ?", []interface{}{"中国"})
		query.Group("province")
	}
	result, err := query.Select()
	if err != nil {
		return []map[string]interface{}{}
	}
	return result
}

func (o *Overview) dateToTimestamp(date string, hour int64, minute int64) int64 {
	timeLayout := "2006-01-02 15:04:05"
	timeStr := fmt.Sprintf("%s %02d:%02d:00", date, hour, minute)
	res, err := public.ParseDateStr(timeLayout, timeStr)
	if err != nil {
		return 0
	}
	return res
}

func (o *Overview) requestTrendHelp(start int64, end int64, data []types.OverViewRequest) []types.OverViewRequest {
	startTimestamp := start - (start % 60)
	endTimestamp := end - (end % 60) + 60
	dataMap := make(map[int64]types.OverViewRequest)
	for _, item := range data {
		dataMap[item.Timestamp] = item
	}

	for timestamp := startTimestamp; timestamp <= endTimestamp; timestamp += 60 {
		if _, ok := dataMap[timestamp]; !ok {
			t := time.Unix(timestamp, 0).In(time.UTC).Add(8 * time.Hour)
			newData := types.OverViewRequest{
				Date:      t.Format("2006-01-02"),
				Hour:      int64(t.Hour()),
				Minute:    (timestamp % (60 * 60)) / 60,
				Timestamp: timestamp,
			}
			data = append(data, newData)
		}
	}
	return data
}

func (o *Overview) MapNewBranch(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if params["type"] == nil || params["site_id"] == nil || params["query_data"] == nil {
		return core.Fail("参数错误 site_id/type/query_data")
	}
	p := 1
	p_size := 10000
	if params["p"] != nil && params["p_size"] != nil {
		p = public.InterfaceToInt(params["p"])
		p_size = public.InterfaceToInt(params["p_size"])
	}
	cacheKey := "OverView__MapNewBranch_" + fmt.Sprintf("SiteId%v", params["site_id"]) + "_" + fmt.Sprintf("type%v", params["type"]) + "_" + fmt.Sprintf("query_data%d", params["query_data"])
	if cache.Has(cacheKey) {
		core.Success(public.PaginateData(cache.Get(cacheKey), p, p_size))
	}
	date_n := o.the_other_day(30)

	if v, ok := params["query_data"].(float64); ok {
		date_n = o.the_other_day(int(v))
	}
	var res interface{}
	request_total := 0
	if params["type"].(float64) == 0 {
		res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
			query := conn.NewQuery()
			query.Table("ip_total").
				Where("date >= ?", []interface{}{date_n}).
				Where("server_name = ?", []interface{}{params["site_id"].(string)}).
				Field([]string{
					"any_value(ip) as ip",
					"SUM(request) as visits",
				}).
				Group("ip").
				Sort("visits", "desc")
			result, err := query.Select()
			for _, v := range result {
				if v["visits"] == nil {
					continue
				}
				if _, ok := v["visits"].(float64); !ok {
					continue
				}
				request_total += int(v["visits"].(float64))
			}
			for _, v := range result {
				v["percent"] = 0.00
				if v["visits"] == nil {
					continue
				}
				if _, ok := v["visits"].(float64); !ok {
					continue
				}
				if request_total != 0 && v["visits"].(float64) != 0 {
					v["percent"] = public.Round(v["visits"].(float64)*100/float64(request_total), 2)
				}
			}
			return result, err
		})

		if err != nil {
			return core.Fail("获取请求地图ip统计数据失败2")
		}
	}
	if params["type"].(float64) == 1 {
		res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
			query := conn.NewQuery()
			query.Table("uri_total").
				Where("date >= ?", []interface{}{date_n}).
				Where("server_name = ?", []interface{}{params["site_id"].(string)}).
				Field([]string{"any_value(uri) as uri",
					"SUM(request) as visits"}).
				Group("uri").
				Sort("visits", "desc")
			result, err := query.Select()
			for _, v := range result {
				if v["visits"] == nil {
					continue
				}
				if _, ok := v["visits"].(float64); !ok {
					continue
				}
				request_total += int(v["visits"].(float64))
			}
			for _, v := range result {
				v["percent"] = 0.00
				if v["visits"] == nil {
					continue
				}
				if _, ok := v["visits"].(float64); !ok {
					continue
				}
				if request_total != 0 && v["visits"].(float64) != 0 {
					v["percent"] = public.Round(v["visits"].(float64)*100/public.InterfaceToFloat64(request_total), 2)
				}
			}

			return result, err
		})

		if err != nil {
			return core.Fail("获取请求地图url统计失败")
		}

	}
	if params["type"].(float64) == 2 {
		res, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
			query := conn.NewQuery()
			query.Table("request_total").
				Where("date >= ?", []interface{}{date_n}).
				Where("server_name = ?", []interface{}{params["site_id"].(string)}).
				Field([]string{
					"SUM(request) as visits"})
			result, err := query.Select()
			if result != nil && len(result) > 0 {
				if _, ok := result[0]["visits"]; ok && result[0]["visits"] != nil {
					request_total = public.InterfaceToInt(result[0]["visits"])
				}

			}
			all_spider := []string{"baidu", "google", "bing", "sogou", "_360", "_other"}
			spiderData := make([]map[string]interface{}, 0)
			for _, v := range all_spider {
				spider := make(map[string]interface{}, 0)
				spider[v] = 0
				spider["percent"] = 0.00
				vv := "spider_" + v
				vv = strings.Replace(vv, "__", "_", -1)
				query.Table("request_total").
					Where("date >= ?", []interface{}{date_n}).
					Where("server_name = ?", []interface{}{params["site_id"].(string)}).
					Where(vv+" != ?", []any{0}).
					Field([]string{
						"SUM(request) as visits",
					})
				result, err = query.Select()
				if err != nil {
					return nil, err
				}
				if len(result[0]) > 0 && result[0]["visits"] != nil {
					spider_float64 := public.InterfaceToFloat64(result[0]["visits"])
					spider[v] = spider_float64
					spider["percent"] = 0.00
					if request_total != 0 && spider_float64 != 0 {
						spider["percent"] = public.Round(spider_float64*100/public.InterfaceToFloat64(request_total), 2)
					}
				}
				spiderData = append(spiderData, spider)
			}
			res = spiderData

			return spiderData, err
		})

		if err != nil {
			return core.Fail("获取拦截地图蜘蛛统计失败")
		}

	}
	if res == nil || len(res.([]map[string]interface{})) == 0 {
		res = []map[string]interface{}{}
	}
	cache.Set(cacheKey, res, 60)
	return core.Success(public.PaginateData(res, p, p_size))
}

func (o *Overview) MapNewTotal(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if params["site_id"] == nil || params["contrast_particle"] == nil || params["query_data"] == nil || params["contrast_start"] == nil || params["is_contrast"] == nil {
		return core.Fail("参数错误 site_id/contrast_particle/query_data/contrast_start/is_contrast")
	}
	cacheKey := "OverView__MapNewTotal_" + fmt.Sprintf("SiteId%v", params["site_id"]) + "_" + fmt.Sprintf("ContrastParticle%v", params["contrast_particle"]) + "_" + fmt.Sprintf("queryData%d", params["query_data"]) + "_" + fmt.Sprintf("contrastStart%d", params["contrast_start"])
	if cache.Has(cacheKey) {
		cacheData := cache.Get(cacheKey)
		var data map[string]interface{}
		err := json.Unmarshal([]byte(public.InterfaceToString(cacheData)), &data)
		if err == nil {
			if public.InterfaceToInt64(params["is_contrast"]) == 0 {
				if _, ok := data["old"]; ok {
					delete(data, "old")
					return core.Success(data)
				}

			} else {
				if _, ok := data["old"]; ok {
					return core.Success(data)
				}
			}
		}
	}
	returnData := make(map[string]interface{}, 0)
	twoList := []string{"current", "old"}
	for _, vvv := range twoList {
		start_time_tmp := time.Now().Unix()
		start_time := time.Unix(public.InterfaceToInt64(start_time_tmp), 0).UTC()
		if vvv == "old" {
			if public.InterfaceToInt64(params["is_contrast"]) == 0 {
				continue
			}
			start_time = time.Unix(public.InterfaceToInt64(params["contrast_start"]), 0).UTC()
		}
		date_start, dateList := o.the_other_day_new(start_time, 28)
		date_end, _ := o.the_other_day_new(start_time, 0)
		if v, ok := params["query_data"].(float64); ok {
			date_start, dateList = o.the_other_day_new(start_time, int(v))

		}
		if len(dateList) == 0 {
			dateList = []string{date_end}
		}
		dataMap := make(map[string]string, 0)
		for _, date := range dateList {
			if _, ok := dataMap[date]; !ok {
				dataMap[date] = "1"
			}
		}
		_, err = public.M("request_total").Where("date>=? and ip_count =?", []any{date_start, 0}).Update(map[string]interface{}{"ip_count": 1})
		if err != nil {
			logging.Error("修复异常数据失败：", err)
		}
		lastData := make(map[string]map[string]interface{}, 0)
		total := map[string]interface{}{"request_total": 0, "ip_total": 0, "pv_total": 0, "uv_total": 0, "spider_total": 0}
		_, err = public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
			query := conn.NewQuery()
			query.Table("request_total").
				Where("date >= ?", []interface{}{date_start}).
				Where("server_name = ?", []interface{}{params["site_id"].(string)}).
				Field([]string{
					"any_value(date) as date",
					"any_value(hour) as hour",
					"SUM(ip_count) as ip_total",
					"SUM(pv_count) as pv_total",
					"SUM(uv_count) as uv_total",
					"SUM(request) as request_total",
				}).
				Group("date")
			if vvv == "old" {
				query.Where("date <= ?", []interface{}{date_end})
			}
			if params["contrast_particle"].(float64) == 0 {
				query.Group("hour")
			}
			request_result, err := query.Select()
			key_total := 0
			for _, request_v := range request_result {
				if _, ok := lastData[request_v["date"].(string)]; !ok {
					if public.InterfaceToInt(params["contrast_particle"]) == 1 {
						lastData[request_v["date"].(string)] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}
					} else {
						lastData[request_v["date"].(string)] = make(map[string]interface{}, 0)
						for i := 0; i < 24; i++ {
							lastData[request_v["date"].(string)][public.InterfaceToString(i)] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}

						}
					}
				}
				if _, ok := dataMap[request_v["date"].(string)]; !ok {
					continue
				}
				for key, _ := range total {
					if key == "spider_total" {
						continue
					}
					if request_v[key] != nil {
						total[key] = public.InterfaceToInt(total[key]) + public.InterfaceToInt(request_v[key])
						if public.InterfaceToInt(params["contrast_particle"]) == 1 {
							key_total += public.InterfaceToInt(request_v[key])
							lastData[request_v["date"].(string)][key] = public.InterfaceToInt(lastData[request_v["date"].(string)][key]) + public.InterfaceToInt(request_v[key])
						} else {
							lastData[request_v["date"].(string)][public.InterfaceToString(request_v["hour"])].(map[string]interface{})[key] = request_v[key]
						}

					}
				}
			}
			query.Table("request_total").
				Where("date >= ?", []interface{}{date_start}).
				Where("server_name = ?", []interface{}{params["site_id"].(string)}).
				Field([]string{
					"any_value(date) as date",
					"any_value(hour) as hour",
					"SUM(request) as spider_total",
				})
			query.WhereNest(func(q *db.Query) {
				q.Where("spider_baidu != ?", []any{0})
				q.WhereOr("spider_google != ?", []any{0})
				q.WhereOr("spider_bing != ?", []any{0})
				q.WhereOr("spider_sogou != ?", []any{0})
				q.WhereOr("spider_360 != ?", []any{0})
				q.WhereOr("spider_other != ?", []any{0})
			}).
				Group("date")
			if vvv == "old" {
				query.Where("date <= ?", []interface{}{date_end})
			}
			if params["contrast_particle"].(float64) == 0 {
				query.Group("hour")
			}
			spider_result, err := query.Select()
			if err != nil {
				return nil, err
			}
			for _, spider_v := range spider_result {
				if _, ok := lastData[spider_v["date"].(string)]; !ok {
					if public.InterfaceToInt(params["contrast_particle"]) == 1 {
						lastData[spider_v["date"].(string)] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}
					} else {
						lastData[spider_v["date"].(string)] = make(map[string]interface{}, 0)
						for i := 0; i < 24; i++ {
							lastData[spider_v["date"].(string)][public.InterfaceToString(i)] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}
						}
					}
				}
				if _, ok := dataMap[spider_v["date"].(string)]; !ok {
					continue
				}
				if _, ok := spider_v["spider_total"].(float64); !ok {
					continue
				}
				if spider_v["spider_total"] != nil && spider_v["spider_total"].(float64) != 0 {
					if public.InterfaceToInt(params["contrast_particle"]) == 1 {
						lastData[spider_v["date"].(string)]["spider_total"] = public.InterfaceToInt(lastData[spider_v["date"].(string)]["spider_total"]) + public.InterfaceToInt(spider_v["spider_total"])
					} else {
						lastData[spider_v["date"].(string)][public.InterfaceToString(spider_v["hour"])].(map[string]interface{})["spider_total"] = spider_v["spider_total"]
					}
					total["spider_total"] = public.InterfaceToInt(total["spider_total"]) + public.InterfaceToInt(spider_v["spider_total"])
				}
			}
			lastData["total"] = total
			for _, v := range dateList {
				if _, ok := lastData[v]; !ok {
					if public.InterfaceToInt(params["contrast_particle"]) == 1 {
						lastData[v] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}
					} else {
						lastData[v] = make(map[string]interface{}, 0)
						for i := 0; i < 24; i++ {
							lastData[v][public.InterfaceToString(i)] = map[string]interface{}{"ip_total": 0, "pv_total": 0, "uv_total": 0, "request_total": 0, "spider_total": 0}
						}
					}

				}
			}
			returnData[vvv] = lastData
			return nil, err
		})

		if err != nil {
			return core.Fail("获取请求地图ip统计数据失败2")
		}
	}
	cache.Set(cacheKey, returnData, 60)
	return core.Success(returnData)
}

func (o *Overview) GetHelpConfig(request *http.Request) core.Response {
	result := make(map[string]interface{}, 0)

	result["spider"] = map[string]interface{}{
		"baidu": map[string]string{
			"english": "baidu",
			"chinese": "百度",
			"keyword": "baidu",
		},
		"google": map[string]string{
			"english": "google",
			"chinese": "谷歌",
			"keyword": "googlebot",
		},
		"bing": map[string]string{
			"english": "bing",
			"chinese": "必应",
			"keyword": "bing",
		},
		"sogou": map[string]string{
			"english": "sogou",
			"chinese": "搜狗",
			"keyword": "sogou",
		},
		"_360": map[string]string{
			"english": "360",
			"chinese": "360",
			"keyword": "360",
		},
		"_other": map[string]string{
			"english": "other",
			"chinese": "其他",
			"keyword": "other",
		},
	}
	return core.Success(result)

}
