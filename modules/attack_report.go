package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Report{
		fengsuo:       "/tmp/blockade_log_",
		lanjie:        "/tmp/intercept_log_",
		hit_type_path: "/www/cloud_waf/nginx/conf.d/waf/rule/rule_hit_list.json",
	})
}

type Report struct {
	fengsuo       string
	lanjie        string
	hit_type_path string
}

func (r *Report) AttackReportCount(request *http.Request) core.Response {
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		params, err := core.GetParamsFromRequest(request)
		if err != nil {
			return core.Fail(err), nil
		}
		start, end := public.GetQueryTimestamp(public.InterfaceToString(params["query_data"]))
		query_ip := conn.NewQuery()
		query_type := conn.NewQuery()
		query_uri := conn.NewQuery()
		query_ip.Table("totla_log").
			Where("time >= ?", []interface{}{start}).
			Where("time <= ?", []interface{}{end}).
			Field([]string{"time", "ip", "ip_country", "ip_city", "ip_province", "count(ip) as visits"}).
			Group("ip").
			Sort("visits", "desc")
		query_type.Table("totla_log").
			Where("time >= ?", []interface{}{start}).
			Where("time <= ?", []interface{}{end}).
			Field([]string{"risk_type", "count(*) as type_total"}).
			Group("risk_type").
			Sort("type_total", "desc")
		query_uri.Table("totla_log").
			Where("time >= ?", []interface{}{start}).
			Where("time <= ?", []interface{}{end}).
			Field([]string{"uri", "count(*) as uri_total"}).
			Group("uri").
			Sort("uri_total", "desc")
		type_result, err := query_type.Select()
		ip_result, err := query_ip.Select()
		uri_result, err := query_uri.Select()
		return map[string]interface{}{
			"type": type_result,
			"ip":   ip_result,
			"uri":  uri_result,
		}, err
	})
	if err != nil {
		return core.Fail("获取攻击报表信息失败")
	}
	return core.Success(res)
}

var uriMap = make(map[string]interface{})

func (r *Report) AttackReportUri(request *http.Request) core.Response {
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		params, err := core.GetParamsFromRequest(request)
		if err != nil {
			return core.Fail(err), nil
		}

		start, end := public.GetQueryTimestamp(public.InterfaceToString(params["query_data"]))
		query_info := conn.NewQuery()
		query_name := conn.NewQuery()
		uriName, _ := query_name.Table("totla_log").
			Where("time >= ?", []interface{}{start}).
			Where("time <= ?", []interface{}{end}).
			Field([]string{"uri"}).
			Group("uri").
			Select()
		for _, v := range uriName {
			q, _ := query_info.Table("totla_log").
				Where("time >= ?", []interface{}{start}).
				Where("time <= ?", []interface{}{end}).
				Where("uri =?", []interface{}{v["uri"]}).
				Field([]string{"id", "filter_rule ", "time", "ip", "ip_country", "ip_city", "ip_province", "server_name", "uri"}).
				Select()
			uriMap[v["uri"].(string)] = q
		}
		return uriMap, err
	})
	if err != nil {
		return core.Fail("获取uri信息失败")
	}
	return core.Success(res)
}

func (r *Report) AttackReportLog(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["query_data"].(string); !ok {
		return core.Fail("query_data parameter error")
	}
	var start int64
	var end int64
	var flag bool
	if params["query_data"] == "" {
		flag = false
	} else {
		flag = true
		start, end = public.GetQueryTimestamp(public.InterfaceToString(params["query_data"]))
	}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("totla_log")
		if flag {
			query.Where("time >= ?", []interface{}{start}).Where("time <= ?", []interface{}{end})
		}
		query.Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "ip_province", "uri", "action", "server_name", "risk_type", "method", "request_uri", "host", "http_log_path", "user_agent"}).Order("time", "desc")
		if v, ok := params["keyword"]; ok {
			if c, ok := v.(string); ok && c != "" {
				query.Where("server_name like ? or uri like ? or ip like ? or ip_country like ? or  ip_city like ? or request_uri like ? or host like ?", []interface{}{
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
				})
			}
		}
		if c, ok := params["filters"]; ok {
			filters, _ := c.([]interface{})
			for _, v := range filters {
				filterMap, _ := v.(map[string]interface{})
				values := public.InterfaceToString(filterMap["values"])
				values = strings.TrimSpace(values)
				query.Where(fmt.Sprintf("%s %s ?", filterMap["field"].(string), filterMap["operand"].(string)), []interface{}{html.UnescapeString(values)})
			}
		}
		if v, ok := params["export"]; ok {
			if c, ok := v.(float64); ok && c == 1 {
				res, err := query.Select()
				if err == nil && len(res) > 0 {
					var data []types.ExportData1
					for _, v := range res {
						var t types.ExportData1
						public.MapToStruct(v, &t)
						data = append(data, t)
					}
					header := []string{"访问时间", "状态", "域名", "url", "攻击ip", "地区", "攻击类型"}
					now := time.Now()
					year, month, day := now.Date()
					rdm := public.RandomStr(3)
					filePath := r.lanjie + strconv.Itoa(year) + "_" + strconv.Itoa(int(month)) + "_" + strconv.Itoa(day) + rdm + ".csv"
					err := r.exportDataToCSV1(data, filePath, header)
					if err != nil {
						return core.Fail("导出失败"), nil
					}
					rep, err := core.DownloadFile(filePath, "拦截日志.csv")
					if err != nil {
						return core.Fail("导出失败"), nil
					}
					return rep, nil
				} else {
					return "无数据", nil
				}
			}
		}
		if v, ok := params["clear"]; ok {
			if c, ok := v.(float64); ok && c == 1 {
				q2 := conn.NewQuery()
				public.MapToStruct(query, &q2)
				path_list := []string{}
				if flag {
					info1, _ := query.Select()
					for _, v := range info1 {
						if v["http_log_path"] != nil && v["http_log_path"] != "" {
							path_list = append(path_list, v["http_log_path"].(string))
						}
					}
				}
				_, errs := q2.Delete()
				if errs != nil {
					return core.Fail("清空失败"), nil
				}
				if flag == false {
					path := "/www/cloud_waf/nginx/conf.d/waf/logs/"
					if public.FileExists(path) {
						err := os.RemoveAll(path)
						if err != nil {
							logging.Error("清空post日志失败：", err)
						}
					}
				} else {
					if len(path_list) > 0 {
						for _, v := range path_list {
							if public.FileExists(v) {
								err := os.RemoveAll(v)
								if err != nil {
									continue
								}
							}
						}
					}
				}
				public.WriteOptLog(fmt.Sprintf("拦截日志清空成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
				return "清空成功", nil
			}
		}
		resp, err := public.SimplePage(query, params)
		listdata := resp.(map[string]interface{})["list"]
		for _, item := range listdata.([]map[string]interface{}) {
			ip := item["ip"].(string)
			if public.IsIpv4(ip) {
				item["ip_type"] = 0
			} else {
				item["ip_type"] = 1
			}
		}
		return resp, err
	})

	if err != nil {
		return core.Fail("获取拦截日志失败")
	}
	if v, ok := params["export"]; ok {
		if c, ok := v.(float64); ok && c == 1 {
			if res == "无数据" {
				return core.Fail("无数据可导出")
			}
			public.WriteOptLog(fmt.Sprintf("拦截日志导出成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
			return res.(core.Response)
		}
	}
	return core.Success(res)

}

func (r *Report) AttackReportIpLog(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["query_data"].(string); !ok {
		return core.Fail("query_data parameter error")
	}
	var start int64
	var end int64
	var flag bool
	if params["query_data"] == "" {
		flag = false
	} else {
		flag = true
		start, end = public.GetQueryTimestamp(public.InterfaceToString(params["query_data"]))
	}
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("blocking_ip")
		if flag {
			query.Where("time >= ?", []interface{}{start}).Where("time <= ?", []interface{}{end})
		}
		query.Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "ip_province", "uri", "block_status", "server_name", "blocking_time", "request_uri", "risk_type", "method", "request_uri", "host", "block_type", "http_log_path", "user_agent"}).
			Order("time", "desc")

		if v, ok := params["keyword"]; ok {
			if c, ok := v.(string); ok && c != "" {
				query.Where("server_name like ? or uri like ? or ip like ? or ip_country like ? or  ip_city like ? or request_uri like ? or host like ?", []interface{}{
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
					fmt.Sprintf("%%%s%%", c),
				})
			}
		}
		if c, ok := params["filters"]; ok {
			filters, _ := c.([]interface{})
			for _, v := range filters {
				filterMap, _ := v.(map[string]interface{})
				values := public.InterfaceToString(filterMap["values"])
				values = strings.TrimSpace(values)
				query.Where(fmt.Sprintf("%s %s ?", filterMap["field"].(string), filterMap["operand"].(string)), []interface{}{html.UnescapeString(values)})
			}
		}

		if v, ok := params["export"]; ok {
			if c, ok := v.(float64); ok && c == 1 {
				res, err := query.Select()
				if err == nil && len(res) > 0 {
					var data []types.ExportData2
					for _, v := range res {
						var t types.ExportData2
						public.MapToStruct(v, &t)
						data = append(data, t)
					}

					header := []string{"封锁时间", "封锁状态", "封锁时长", "攻击ip", "地区", "域名", "url", "攻击类型"}
					now := time.Now()
					year, month, day := now.Date()
					rdm := public.RandomStr(3)
					filePath := r.fengsuo + strconv.Itoa(year) + "_" + strconv.Itoa(int(month)) + "_" + strconv.Itoa(day) + rdm + ".csv"
					err := r.exportDataToCSV2(data, filePath, header)
					if err != nil {
						return core.Fail("导出失败"), nil
					}
					rep, err := core.DownloadFile(filePath, "封锁记录.csv")
					if err != nil {
						return core.Fail("导出失败"), nil
					}

					return rep, nil
				} else {
					return "无数据", nil
				}

			}
		}
		if v, ok := params["clear"]; ok {
			if c, ok := v.(float64); ok && c == 1 {
				q2 := conn.NewQuery()
				public.MapToStruct(query, &q2)
				path_list := []string{}
				if flag {
					info1, _ := query.Select()
					for _, v := range info1 {
						if v["http_log_path"] != nil && v["http_log_path"] != "" {
							path_list = append(path_list, v["http_log_path"].(string))
						}
					}
				}
				_, errs := q2.Delete()
				if errs != nil {
					return core.Fail("清空失败"), nil
				}
				if flag == false {
					path := "/www/cloud_waf/nginx/conf.d/waf/logs/"
					if public.FileExists(path) {
						err := os.RemoveAll(path)
						if err != nil {
							logging.Error("清空post日志失败：", err)
						}
					}
				} else {
					if len(path_list) > 0 {
						for _, v := range path_list {
							if public.FileExists(v) {
								err := os.RemoveAll(v)
								if err != nil {
									continue
								}
							}
						}
					}
				}
				public.WriteOptLog(fmt.Sprintf("封锁日志清空成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
				return "清空成功", nil
			}
		}
		resp, err := public.SimplePage(query, params)
		if resp.(map[string]interface{})["list"] != nil {
			listdata := resp.(map[string]interface{})["list"]
			for _, item := range listdata.([]map[string]interface{}) {
				ip := item["ip"].(string)
				if public.IsIpv4(ip) {
					item["ip_type"] = 0
				} else {
					item["ip_type"] = 1
				}
			}
		}
		return resp, err
	})

	if err != nil {
		return core.Fail("获取IP封锁记录失败")
	}
	if v, ok := params["export"]; ok {
		if c, ok := v.(float64); ok && c == 1 {
			if res == "无数据" {
				return core.Fail("无数据可导出")
			}
			public.WriteOptLog(fmt.Sprintf("封锁日志导出成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
			return res.(core.Response)
		}
	}
	return core.Success(res)

}

func (r *Report) AttackReportIpLogInfo(request *http.Request) core.Response {
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		params, err := core.GetParamsFromRequest(request)
		if err != nil {
			return core.Fail(err), nil
		}
		query := conn.NewQuery()
		query.Table("blocking_ip").
			Where("id = ?", public.GetSqlParams(params["id"]))
		return query.Find()
	})
	if err != nil {
		return core.Fail("获取封锁记录失败")
	}
	return core.Success(res)
}

func (r *Report) AttackReportLogInfo(request *http.Request) core.Response {
	res, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		params, err := core.GetParamsFromRequest(request)
		if err != nil {
			return core.Fail(err), nil
		}
		query := conn.NewQuery()
		query.Table("totla_log").
			Where("id = ?", public.GetSqlParams(params["id"]))

		return query.Find()
	})
	if err != nil {
		return core.Fail("获取拦截日志失败")
	}
	return core.Success(res)
}

func (r *Report) GetFileContent(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	path := ""
	if v, ok := params["path"].(string); ok {
		path = public.InterfaceToString(v)
	}
	if len(path) != 73 {
		return core.Fail("参数错误")
	}
	if path == "" {
		return core.Fail("缺少参数：path")
	}
	if strings.Contains(path, "..") {
		return core.Fail("文件路径不合法")
	}
	if !strings.HasPrefix(path, "/www/cloud_waf/nginx/conf.d/waf/logs/") || !strings.HasSuffix(path, ".log") {
		return core.Fail("文件路径不合法")
	}

	file_data, err := public.ReadFile(path)
	if err != nil {
		return core.Success(map[string]interface{}{
			"post_http_log": "",
		})
	}
	return core.Success(map[string]interface{}{
		"post_http_log": file_data,
	})

}

func (r *Report) exportDataToCSV1(data []types.ExportData1, filePath string, headers []string) error {
	_, err := public.ReadFile(filePath)
	if err == nil {
		err = os.Remove(filePath)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write(headers)
	if err != nil {
		return err
	}
	for _, d := range data {
		actionStr := ""
		switch d.Action {
		case 1:
			actionStr = "观察"
		case 2:
			actionStr = "拦截"
		case 3:
			actionStr = "拦截"

		default:
			actionStr = "未知"
		}
		tm := time.Unix(d.Time, 0).Format("2006-01-02 15:04:05")
		row := []string{tm, actionStr, d.Server_name, d.Uri, d.Ip, d.Ip_country, d.Risk_type}
		err = writer.Write(row)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Report) exportDataToCSV1__(data []types.ExportData1, filePath string, headers []string) error {
	_, err := public.ReadFile(filePath)
	if err == nil {
		err = os.Remove(filePath)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write(headers)
	if err != nil {
		return err
	}
	rows := make(chan []string, 100)
	done := make(chan bool)
	go func() {
		for row := range rows {
			err := writer.Write(row)
			if err != nil {
				close(rows)
				return
			}
		}
		done <- true
	}()
	batchSize := 1000
	batch := make([][]string, 0, batchSize)
	for _, d := range data {
		actionStr := ""
		switch d.Action {
		case 1:
			actionStr = "观察"
		case 2:
			actionStr = "拦截"
		case 3:
			actionStr = "拦截"
		default:
			actionStr = "未知"
		}
		tm := time.Unix(d.Time, 0).Format("2006-01-02 15:04:05")
		row := []string{tm, actionStr, d.Server_name, d.Uri, d.Ip, d.Ip_country, d.Risk_type}
		batch = append(batch, row)
		if len(batch) >= batchSize {
			for _, row := range batch {
				rows <- row
			}
			batch = batch[:0]
		}
	}
	for _, row := range batch {
		rows <- row
	}
	close(rows)
	<-done
	return nil
}

func (r *Report) exportDataToCSV2(data []types.ExportData2, filePath string, headers []string) error {
	now := time.Now().Unix()
	_, err := public.ReadFile(filePath)
	if err == nil {
		err = os.Remove(filePath)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write(headers)
	if err != nil {
		return err
	}
	for _, d := range data {
		blockStatusStr := ""
		switch d.Block_status {
		case 1:
			if now > d.Time+d.Blocking_time {
				blockStatusStr = "已解封"
			} else {
				blockStatusStr = "封锁中"
			}

		case 0:
			blockStatusStr = "已解封"
		default:
			blockStatusStr = "未知"
		}
		tm := time.Unix(d.Time, 0).Format("2006-01-02 15:04:05")
		row := []string{tm, blockStatusStr, strconv.Itoa(int(d.Blocking_time)) + "s", d.Server_name, d.Uri, d.Ip, d.Ip_country, d.Risk_type}
		err = writer.Write(row)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Report) UnsetIp(request *http.Request) core.Response {
	params := struct {
		ID float64 `json:"id"`
		IP string  `json:"ip"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.IP == "" || params.ID == 0 {
		return core.Fail("参数错误")
	}
	var drop_ip []string
	var ip_drop map[string]interface{}
	ress, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_btwaf_drop_ip", 2)
	ress = strings.TrimSpace(ress)
	if err != nil {
		return core.Fail("解封失败")
	}
	if ress != "{}" {
		err = json.Unmarshal([]byte(ress), &drop_ip)
		if err != nil {
			return core.Fail(err)
		}
	}
	is_ip := public.InArray(params.IP, drop_ip)
	if is_ip == true {
		resss, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/remove_btwaf_drop_ip?ip="+params.IP, 2)
		resss = strings.TrimSpace(resss)
		if err != nil {
			public.WriteOptLog(fmt.Sprintf("解封IP【%s】失败", params.IP), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
			return core.Fail("解封失败")
		}

		if resss != "{}" {
			err = json.Unmarshal([]byte(resss), &ip_drop)
			if err != nil {
				return core.Fail(err)
			}
		}
		if c, ok := ip_drop["status"]; ok && c.(bool) != true {
			public.WriteOptLog(fmt.Sprintf("解封IP【%s】失败", params.IP), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
			return core.Fail(ip_drop["msg"])
		}
		flag := public.DelFilter(params.IP)
		if flag == 0 {
			public.WriteOptLog(fmt.Sprintf("解封IP【%s】失败", params.IP), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
			return core.Fail("解封失败")
		}
		err = r.updateBlockStatus(params.ID)
		if err != nil {
			public.WriteOptLog(fmt.Sprintf("解封IP【%s】失败", params.IP), public.OPT_LOG_TYPE_USER_OPERATION, public.GetUid(request))
			return core.Fail(err)
		}
		public.WriteOptLog(fmt.Sprintf("解封IP【%s】成功", params.IP), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
		return core.Success("解封成功")
	} else {
		return core.Fail("该ip不在封锁列表中")
	}

}

func (r *Report) UnsetAllIp(request *http.Request) core.Response {
	ress, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/clean_btwaf_drop_ip", 2)
	if err != nil {
		public.WriteOptLog(fmt.Sprintf("解封所有IP失败"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
		return core.Fail("解封失败")
	}
	var res_data map[string]interface{}
	err1 := json.Unmarshal([]byte(ress), &res_data)
	if err1 != nil {
		return core.Fail(err)
	}
	if c, ok := res_data["status"]; ok && c.(bool) != true {
		public.WriteOptLog(fmt.Sprintf("解封所有IP失败"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
		return core.Fail(res_data["msg"])
	}
	flag1 := public.DelFilterallV4()
	flag2 := public.DelFilterallV6()
	if flag1 == 0 && flag2 == 0 {
		public.WriteOptLog(fmt.Sprintf("解封所有IP失败"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
		return core.Fail("解封失败")
	}
	err = r.updateBlockStatus(0)
	if err != nil {
		public.WriteOptLog(fmt.Sprintf("解封所有IP失败"), public.OPT_LOG_TYPE_USER_OPERATION, public.GetUid(request))
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("解封所有IP成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
	return core.Success(res_data["msg"])
}

func (r *Report) updateBlockStatus(id float64) error {
	_, err := public.MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		query := conn.NewQuery()
		query.Table("blocking_ip").
			Field([]string{"id", "block_status"})
		if id != 0 {
			query.Where("id = ?", public.GetSqlParams(id))
		}
		num, err := query.Update(map[string]interface{}{
			"block_status": 0,
		})
		return num, err
	})
	return err
}

func (r *Report) CcList(request *http.Request) core.Response {
	params := struct {
		Keyword   string `json:"keyword"`
		QueryData string `json:"query_data"`
		P         int    `json:"p"`
		PSize     int    `json:"p_size"`
		Clear     int    `json:"clear"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	var start int64
	var end int64
	var flag bool
	ccid_list := make([]string, 0)
	if params.QueryData == "" {
		flag = false
	} else {
		flag = true
		start, end = public.GetQueryTimestamp(public.InterfaceToString(params.QueryData))
	}
	query_ip := public.S("cc_ip_log")
	if params.Keyword != "" {
		query_ip.Where("ip like ? ", []interface{}{
			fmt.Sprintf("%%%s%%", params.Keyword),
		})
		if flag {
			query_ip.Where("create_time >= ?", []interface{}{start}).Where("create_time <= ?", []interface{}{end})
		}
		query_ip.Field([]string{"cc_id", "ip"})
		ip_all, _ := query_ip.Select()
		for _, v := range ip_all {
			ccid_list = append(ccid_list, public.Int64ToString(v["cc_id"].(int64)))
		}
	}
	query := public.S("cc_log")
	if flag {
		query.Where("create_time >= ?", []interface{}{start}).Where("create_time <= ?", []interface{}{end})
	}
	query.Order("create_time", "desc")

	if params.Keyword != "" {
		query.Where("servername like ? or uri like ? or host like ?", []interface{}{
			fmt.Sprintf("%%%s%%", params.Keyword),
			fmt.Sprintf("%%%s%%", params.Keyword),
			fmt.Sprintf("%%%s%%", params.Keyword),
		})

	}
	if len(ccid_list) > 0 {
		query.WhereInOr("id", ccid_list)
	}
	if params.Clear == 1 {
		_, errs := public.S("cc_log").Where("id >?", []interface{}{
			0,
		}).Delete()
		if errs != nil {
			return core.Fail("清空失败")
		}
		public.WriteOptLog(fmt.Sprintf("CC事件清空成功"), public.OPT_LOG_TYPE_ATTACK_REPORT, public.GetUid(request))
		return core.Success("清空成功")
	}
	resp, err := public.SimplePage(query, params)
	if err != nil {
		return core.Fail(err)
	}
	id_show := make([]string, 0)
	for _, v := range resp.(map[string]interface{})["list"].([]map[string]interface{}) {
		id_show = append(id_show, public.Int64ToString(v["id"].(int64)))
	}
	query_ip2 := public.S("cc_ip_log")
	query_ip2.WhereIn("cc_id", id_show)
	ip_list, _ := query_ip2.Select()
	for _, item := range resp.(map[string]interface{})["list"].([]map[string]interface{}) {
		ccid := item["id"].(int64)
		ip_list_show := make([]map[string]interface{}, 0)
		for _, v := range ip_list {
			if v["cc_id"] == ccid {
				ip_list_show = append(ip_list_show, v)
			}
		}
		item["ip_list"] = ip_list_show
	}
	return core.Success(resp)

}

func (r *Report) GetRuleHitList(request *http.Request) core.Response {
	params := struct {
		Keyword string `json:"keyword"`
		Filter  string `json:"filter"`
		P       int    `json:"p"`
		PSize   int    `json:"p_size"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	path := "/www/cloud_waf/nginx/conf.d/waf/data/btwaf_rule_hit.json"
	data, err := public.Tail(path, 2001)
	if err != nil || len(data) < 5 {
		return core.Success(map[string]interface{}{
			"list":  []map[string]interface{}{},
			"total": 0,
		})
	}
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")

	file_data := make([]map[string]interface{}, len(lines))
	for i, line := range lines {
		line_info := strings.Split(line, "|")
		if len(line_info) != 12 {
			line_info[9] = ""
			line_info[10] = ""
			line_info[11] = ""
		}
		server_name_ := strings.Replace(line_info[3], ".", "_", -1)
		line_data := map[string]interface{}{
			"status":       line_info[0],
			"key":          line_info[1],
			"timestimp":    public.InterfaceToInt64(line_info[2]),
			"server_name":  line_info[3],
			"server_name_": server_name_,
			"uri":          line_info[4],
			"rule_name":    line_info[5],
			"rule_type":    line_info[6],
			"rule_ps":      line_info[7],
			"ip":           line_info[8],
			"ip_country":   line_info[9],
			"ip_province":  line_info[10],
			"ip_city":      line_info[11],
		}
		file_data[i] = line_data

	}
	if params.Filter != "" {
		filteredData := make([]map[string]interface{}, 0)
		for _, itemMap := range file_data {
			if itemMap["status"] == params.Filter {
				filteredData = append(filteredData, itemMap)
			}
		}
		file_data = filteredData
	}
	if params.Keyword != "" {
		filteredData := make([]map[string]interface{}, 0)
		for _, itemMap := range file_data {
			for _, value := range itemMap {
				strValue, ok := value.(string)
				if ok && strings.Contains(strValue, params.Keyword) {
					filteredData = append(filteredData, itemMap)
					break
				}
			}
		}
		file_data = make([]map[string]interface{}, 0)
		file_data = filteredData

	}
	if len(file_data) == 0 {
		return core.Success(map[string]interface{}{
			"list":  file_data,
			"total": 0,
		})
	}
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i]["timestimp"].(int64) > file_data[j]["timestimp"].(int64)
	})
	data2 := public.PaginateData(file_data, params.P, params.PSize)
	return core.Success(data2)

}

func (r *Report) DeleteRuleHitList(request *http.Request) core.Response {
	public.HttpPostByToken(public.URL_HTTP_REQUEST+"/clean_btwaf_logs", 15)
	path := "/www/cloud_waf/nginx/conf.d/waf/data/btwaf_rule_hit.json"
	if !public.FileExists(path) {
		return core.Success("清空成功")
	}
	err := os.Remove(path)
	if err != nil {
		return core.Fail("清空失败")
	}
	public.WriteOptLog(fmt.Sprintf("清空规则命中日志成功"), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("清空成功")
}

func (r *Report) GetRuleHitTypeList(request *http.Request) core.Response {
	json_data, err := public.ReadFile(r.hit_type_path)
	file_data := types.RuleHitType{}
	if err != nil {
		file_data = types.RuleHitType{
			IPw:         true,
			IPb:         true,
			URIw:        true,
			URIb:        true,
			UAw:         true,
			UAb:         true,
			Customize:   true,
			CustomizeCC: true,
			Area:        true,
			CloudIP:     true,
			Man:         false,
			Replace:     false,
		}
		rules_js, err := json.Marshal(file_data)
		if err != nil {
			logging.Error("转json失败：", err)
		}
		_, err = public.WriteFile(r.hit_type_path, string(rules_js))
		return core.Success(file_data)

	}
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(file_data)

}

func (r *Report) SetHitType(request *http.Request) core.Response {
	params := types.RuleHitType{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	rules_js, err := json.Marshal(params)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	_, err = public.WriteFile(r.hit_type_path, string(rules_js))
	if err != nil {
		return core.Fail("设置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("设置成功")

}
