package providers

import (
	"CloudWaf/core"
	"CloudWaf/core/cache"
	"CloudWaf/core/logging"
	"CloudWaf/modules"
	"CloudWaf/public"
	"CloudWaf/public/cluster_core"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/notification"
	"CloudWaf/types"
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

var (
	debugLogPath = core.AbsPath("./logs/debug")
	isRestarting = false
)

func init() {

	cr := &cronProvider{}
	registerProviderAlways(cr.addSliceSiteLog)
	registerProviderAlways(cr.addDebugClearLog)
	registerProviderAlways(cr.addCheckNginx)
	registerProviderAlways(cr.addCheckCC)
	registerProviderAlways(cr.addCheckHitLog)
	registerProviderAlways(cr.addCheckSpeedCacheNew)
	registerProviderAlways(cr.addSubmitValidDomainsTwo)
	registerProviderAlways(cr.addSubmitBlockLogsAndUpdateMaliciousIp)
	registerProviderAlways(cr.addWafRuleBackup)
	registerProviderAlways(cr.addWafRuleRestore)
	registerProvider(cr.UpdateRealtimeHistory)
	registerProviderAlways(cr.addSyncRenewalCert)

}

type cronProvider struct{}

func (cr *cronProvider) addSyncRenewalCert() {
	public.RemoveTaskByTag("SyncRenewalCert")
	if !public.CheckTaskByTag("SyncRenewalCert") {
		hour := rand.Intn(6) + 1
		minute := rand.Intn(60)
		public.AddTaskDayAtTime("SyncRenewalCert", fmt.Sprintf("%02d:%02d:01", hour, minute), modules.SyncRenewalCert, 0)
	}
}

func (cr *cronProvider) addSliceSiteLog() {
	public.RemoveTaskByTag("SliceSiteLog")
	if !public.CheckTaskByTag("SliceSiteLog") {
		_, err := public.AddTaskDayAtTime("SliceSiteLog", "00:00:01", public.SliceSiteLog, 0)
		if err != nil {
			public.WriteFile(public.SliceSiteLogPath, public.ReadSliceLog()+"\n"+public.GetNowTimeStr()+"   网站日志切割任务添加失败")
			logging.Error(err)
		} else {
			public.WriteFile(public.SliceSiteLogPath, public.ReadSliceLog()+"\n"+public.GetNowTimeStr()+"   网站日志切割任务添加成功")
		}
	}
}

func (cr *cronProvider) addDebugClearLog() {
	if !public.CheckTaskByTag("DebugClearLog") {
		_, err := public.AddTaskDayAtTime("DebugClearLog", "00:00:02", ClearDebugLog, 0)
		if err != nil {
			public.WriteFile(public.SliceSiteLogPath, public.ReadSliceLog()+"\n"+public.GetNowTimeStr()+"   debug日志清理任务添加失败")
			logging.Error(err)
		} else {
			public.WriteFile(public.SliceSiteLogPath, public.ReadSliceLog()+"\n"+public.GetNowTimeStr()+"   debug日志清理任务添加成功")
		}
	}

}

func (cr *cronProvider) addSubmitValidDomainsTwo() {
	public.RemoveTaskByTag("SubmitValidDomainsTwo")
	if !public.CheckTaskByTag("SubmitValidDomainsTwo") {
		_, err := public.AddTaskInterval("SubmitValidDomainsTwo", 30*time.Second, public.SiteSourceAddressAutoCheck, 5*time.Minute)

		if err != nil {
			logging.Error("创建定时巡检网站回源域名解析是否变化任务失败：", err)
			return
		}
	}
}

func ClearDebugLog() {
	err := os.RemoveAll(debugLogPath)
	if err != nil {
		logging.Error(err)
	}
}

func (cr *cronProvider) RestartNginx() {
	if isRestarting {
		return
	}
	isRestarting = true
	if public.NginxDownCheck() {
		_, err := public.Command("bash /www/cloud_waf/btw.init nginx_restart || docker restart cloudwaf_nginx 2>&1 >/dev/null")
		if err != nil {
			return
		}
	}
	defer func() {
		isRestarting = false
	}()
}

func (cr *cronProvider) addCheckNginx() {
	if isRestarting {
		return
	}

	if !public.CheckTaskByTag("RestartNginx") {
		_, err := public.AddTaskInterval("RestartNginx", 60*time.Second, cr.RestartNginx, 3*time.Second)
		if err != nil {
			return
		}
	}
}

func (cr *cronProvider) addCheckCC() {

	if !public.CheckTaskByTag("CheckCC") {
		_, err := public.AddTaskInterval("CheckCC", 60*time.Second, cr.CheckCC, 60*time.Second)
		if err != nil {
			return
		}
	}
}

func (cr *cronProvider) addCheckHitLog() {
	if !public.CheckTaskByTag("CheckHitLog") {
		_, err := public.AddTaskInterval("CheckHitLog", 40*time.Minute, cr.CheckHitLog, 60*time.Second)
		if err != nil {
			return
		}
	}

}

func (cr *cronProvider) addCheckSpeedCacheNew() {
	if !public.CheckTaskByTag("CheckSpeedCacheNew") {
		_, err := public.AddTaskInterval("CheckSpeedCacheNew", 30*time.Minute, cr.CheckSpeedCacheNew, 10*time.Minute)
		if err != nil {
			return
		}
	}
}

func (cr *cronProvider) CheckSpeedCacheNew() {

	date := int(time.Now().Unix())
	path2 := "/www/cloud_waf/nginx/conf.d/waf/rule/speed.json"
	filedata, err := public.ReadFile(path2)
	if err != nil {
		return
	}
	data_ := make(map[string]struct {
		Open      bool `json:"open"`
		Timestamp int  `json:"timestamp"`
		Expire    int  `json:"expire"`
	}, 0)

	err = json.Unmarshal([]byte(filedata), &data_)
	if err != nil {
		return
	}
	for i, v := range data_ {
		if v.Open && date > v.Timestamp+v.Expire {

			path := "/www/cloud_waf/wwwroot/" + i + "/*"

			public.DeleteFileAll(path)

			cr.updateSpeedTimestamp(i, float64(date))
		}
	}

}

func (cr *cronProvider) updateSpeedTimestamp(site_id string, timestamp float64) bool {

	json_data, err := public.ReadFile("/www/cloud_waf/nginx/conf.d/waf/rule/speed.json")
	if err != nil {
		return false
	}
	file_data := make(map[string]interface{})
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return false
	}
	file_data[site_id].(map[string]interface{})["timestamp"] = timestamp
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return false
	}
	_, err = public.WriteFile("/www/cloud_waf/nginx/conf.d/waf/rule/speed.json", string(rules_js))
	if err != nil {
		return false
	}
	return true
}

func (cr *cronProvider) CheckHitLog() {

	path := "/www/cloud_waf/nginx/conf.d/waf/data/btwaf_rule_hit.json"

	if !public.FileExists(path) {
		return
	}

	data, err := public.Tail(path, 2000)
	if err != nil {

		return
	}

	public.WriteFile(path, data)

}

func (cr *cronProvider) CheckSpeedCache() {
	defer public.TimeCost()()

	date := int(time.Now().Unix())
	total_count := 0
	path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_cache/"

	path2 := "/www/cloud_waf/nginx/conf.d/waf/rule/speed.json"
	filedata, err := public.ReadFile(path2)
	if err != nil {
		return
	}
	data_ := make(map[string]struct {
		Open bool `json:"open"`
	}, 0)
	err = json.Unmarshal([]byte(filedata), &data_)
	if err != nil {
		return
	}
	for i, v := range data_ {
		func(i string, v struct {
			Open bool `json:"open"`
		}) {
			total_count = 0
			if v.Open {

				ca_dir := path + i + "/resp_body/"

				dir, err := os.Open(ca_dir)
				if err != nil {
					return
				}

				defer dir.Close()

				fileInfos, err := dir.Readdir(-1)
				if err != nil {
					return
				}
				var delFile []string

				for _, fileInfo := range fileInfos {
					func(fileInfo os.FileInfo) {
						file_path := ca_dir + fileInfo.Name()
						fileinfo, err := os.Open(file_path)
						if err != nil {
							return
						}
						defer fileinfo.Close()
						scanner := bufio.NewScanner(fileinfo)
						lineCount := 0
						timestamp := 0
						cache_count := 0

						for scanner.Scan() {
							lineCount++
							if lineCount == 1 {
								cache_count, _ = strconv.Atoi(scanner.Text())
							}
							if lineCount == 2 {
								timestamp, _ = strconv.Atoi(scanner.Text())
								break
							}
						}

						if date >= timestamp {
							total_count += cache_count
							delFile = append(delFile, file_path)
						}

					}(fileInfo)
				}

				if len(delFile) > 0 {
					for _, v := range delFile {
						os.Remove(v)
					}
				}
				public.HttpGet(fmt.Sprintf("http://127.0.0.251/update_site_cache_count?server_name=%s&decount=%d", i, total_count), 2)

			}
		}(i, v)
	}

}

func (cr *cronProvider) CheckCC() {
	var ccAttack int64
	var hasCCinfo bool
	cacheKeyCount := "CCAttack__Count"
	if cache.Has(cacheKeyCount) {
		ccAttack = cache.Get(cacheKeyCount).(int64)
	} else {
		ccAttack = 0
	}
	is_over := cr.checkCCTableUnfinished()
	startTime := time.Now().Unix() - 90
	data, _, min_time := cr.getBlockingTime(startTime)
	if len(data) > 0 {
		hasCCinfo = true
	}
	if is_over {
		if hasCCinfo {
			cr.updateCCRecord()
			ccAttack = 0
		} else {
			ccAttack += 1
			if ccAttack >= 5 {
				endTime, _ := cr.getBlockingTimeMaxId()
				cr.updateCCOvertime(int64(endTime))
				if !cr.updateCCOvertime(int64(endTime)) {
					logging.Error("更新cc 结束状态 失败")
				}
				ccAttack = 0
			}
			cache.Set(cacheKeyCount, ccAttack, 60*3)
		}
	} else {
		if hasCCinfo {
			is_ok, ip_num := cr.createCCRecord(min_time)
			if is_ok {
				warning_open := true
				datas, err := public.Rconfigfile("./config/sysconfig.json")
				if err != nil {
					warning_open = true
				}
				if datas["warning_open"] == nil {
					warning_open = true
				} else {
					warning_open = datas["warning_open"].(bool)
				}
				if warning_open {
					sysinfo := public.GetSystemInfo()
					mem_percent := sysinfo.Mem.UsedPercent
					cpu_percent := sysinfo.CPU.Percent
					loadavg1 := sysinfo.Loadavg.Last1min
					loadavg5 := sysinfo.Loadavg.Last5min
					loadavg15 := sysinfo.Loadavg.Last15min
					CountInfo := cr.NginxCount()
					qps := CountInfo.Qps
					proxy_time := CountInfo.ProxyTime
					serverIp, localIp := core.GetServerIp()
					date := time.Unix(min_time, 0).Format("2006-01-02 15:04:05")
					notification.NotifyAll("堡塔云Waf 检测到CC攻击, 请及时处理", []string{
						fmt.Sprintf("> IP地址: %s (内) %s (外)", localIp, serverIp),
						fmt.Sprintf("> 攻击开始时间: %s", date),
						fmt.Sprintf("> 攻击IP数量: %d", ip_num),
						fmt.Sprintf("> 服务器内存使用率: %.2f%%", mem_percent),
						fmt.Sprintf("> 服务器CPU使用率: %.2f%%", cpu_percent),
						fmt.Sprintf("> 服务器负载: %.2f/%.2f/%.2f", loadavg1, loadavg5, loadavg15),
						fmt.Sprintf("> 服务器当前QPS: %d/s", int(qps)),
						fmt.Sprintf("> 服务器当前回源时间: %.2fms", proxy_time),
					})

				}

			}
		}
	}
}

func (cr *cronProvider) createCCRecord(startTime int64) (bool, int) {
	ip_num := 0

	data, maxid, min_time := cr.getBlockingTime(startTime)

	if len(data) == 0 {
		return false, 0
	}
	datainfo := make(map[string]types.CClog)
	datainfo = cr.handleBlockingData(data)
	var cc_log []map[string]interface{}
	for _, item := range datainfo {
		cc_log = append(cc_log, map[string]interface{}{
			"max_id":      maxid,
			"servername":  item.ServerName,
			"uri":         item.Uri,
			"host":        item.Host,
			"create_time": min_time,
			"status":      1,
			"update_time": min_time + 1,
		})
	}
	_, err := public.S("cc_log").
		InsertAll(cc_log)
	if err != nil {
		return false, 0
	}

	cc_get, err := public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Field([]string{"id", "servername", "uri"}).
		Select()
	if err != nil {
		logging.Error("查询cc记录失败：", err)
	}
	ccLogIdMap := make(map[string]int64)
	for _, item := range cc_get {
		keys := item["servername"].(string) + "~" + item["uri"].(string)

		ccLogIdMap[keys] = item["id"].(int64)
	}
	var cc_ip_log []map[string]interface{}
	for key, ccid := range ccLogIdMap {
		for _, ip := range datainfo[key].IpInfo {
			cc_ip_log = append(cc_ip_log, map[string]interface{}{
				"cc_id":       ccid,
				"ip":          ip.Ip,
				"city":        ip.City,
				"country":     ip.Country,
				"province":    ip.Province,
				"request":     ip.Request,
				"ip_type":     ip.IpType,
				"create_time": min_time,
			})
			ip_num += 1
		}

	}
	_, err = public.S("cc_ip_log").
		InsertAll(cc_ip_log)
	if err != nil {
		logging.Error("cc ip表 添加失败：", err)
	}
	return true, ip_num
}

func (cr *cronProvider) updateCCOvertime(endTime int64) bool {
	res, err := public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Update(map[string]interface{}{
			"status":      0,
			"update_time": endTime + 1,
		})
	if err != nil {
		return false
	}
	return res > 0
}

func (cr *cronProvider) updateCCRecord() {
	res, err := public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Field([]string{"max(max_id) as max_id"}).
		Find()
	if err != nil {
		logging.Error("查询cc记录max_id失败：", err)
	}
	maxid := res["max_id"].(int64)
	res2, err := public.M("blocking_ip").
		Where("id > ?", []interface{}{maxid}).
		Field([]string{"ip", "ip_city ", "ip_country", "ip_province", "uri", "server_name", "host", "block_type"}).
		Select()
	if err != nil {
		logging.Error("查询拦截表数据失败：", err)
	}
	datainfo := make(map[string]types.CClog)
	datainfo = cr.handleBlockingData(res2)
	cc_get, err := public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Field([]string{"id", "servername", "uri"}).
		Select()
	if err != nil {
		logging.Error("查询cc记录失败：", err)
	}
	ccLogIdMap := make(map[string]int64)
	for _, item := range cc_get {
		ccLogIdMap[item["servername"].(string)+"~"+item["uri"].(string)] = item["id"].(int64)
	}
	var cc_log []map[string]interface{}
	for key, item := range datainfo {
		if _, ok := ccLogIdMap[key]; !ok {

			cc_log = append(cc_log, map[string]interface{}{
				"max_id":      maxid,
				"servername":  item.ServerName,
				"uri":         item.Uri,
				"host":        item.Host,
				"create_time": time.Now().Unix(),
				"status":      1,
				"update_time": time.Now().Unix() + 1,
			})
		}
	}
	if len(cc_log) > 0 {
		_, err := public.S("cc_log").
			InsertAll(cc_log)
		if err != nil {
			logging.Error("新增cc记录失败：", err)
		}
	}

	cc_get, err = public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Field([]string{"id", "servername", "uri"}).
		Select()
	for _, item := range cc_get {
		ccLogIdMap[item["servername"].(string)+"~"+item["uri"].(string)] = item["id"].(int64)
	}

	var cc_ip_log []map[string]interface{}
	for key, ccid := range ccLogIdMap {
		for _, ip := range datainfo[key].IpInfo {
			cc_ip_log = append(cc_ip_log, map[string]interface{}{
				"cc_id":       ccid,
				"ip":          ip.Ip,
				"city":        ip.City,
				"country":     ip.Country,
				"province":    ip.Province,
				"request":     ip.Request,
				"ip_type":     ip.IpType,
				"create_time": time.Now().Unix(),
			})
		}
	}

	for _, item := range cc_ip_log {
		res, err := public.S("cc_ip_log").
			Where("cc_id = ?", []interface{}{item["cc_id"]}).
			Where("ip = ?", []interface{}{item["ip"]}).
			Field([]string{"id", "request"}).
			Find()
		if err != nil {
			logging.Error("查询cc ip记录失败：", err)
		}
		if len(res) > 0 {
			_, err := public.S("cc_ip_log").
				Where("id = ?", []interface{}{res["id"]}).
				Update(map[string]interface{}{
					"request": res["request"].(int64) + item["request"].(int64),
				})
			if err != nil {
				logging.Error("更新cc ip记录攻击数失败：", err)
			}
		} else {
			_, err := public.S("cc_ip_log").
				Insert(item)
			if err != nil {
				logging.Error("新增cc ip记录失败：", err)
			}
		}
	}
	return
}

func (cr *cronProvider) getAverageRequest() float64 {
	cacheKey := "CCAttack__AverageRequest"
	if cache.Has(cacheKey) {
		return cache.Get(cacheKey).(float64)
	}
	currentTime := time.Now()
	startDate := currentTime.Format("2006-01-02")
	res := struct {
		RequestTotal float64 `json:"request_total"`
		Total        float64 `json:"total"`
	}{}
	err := public.M("request_total").
		Where("date = ?", []interface{}{startDate}).
		Field([]string{
			"count(*) as `total`",
			"ifnull(SUM(request), 0) as `request_total`",
		}).
		FindAs(&res)

	var avgRequest float64
	if err != nil {
		logging.Info("获取平均请求失败：", err)
	}
	avgRequest = res.RequestTotal / res.Total
	cache.Set(cacheKey, avgRequest, 60*60)
	return avgRequest
}

func (cr *cronProvider) getLatestRequest() (int, int) {
	var qps int
	var proxy_time int
	currentTime := time.Now()
	startDate := currentTime.Format("2006-01-02")
	startHour := currentTime.Hour()
	startMinute := currentTime.Minute() - 5
	res := struct {
		RequestTotal int `json:"qps"`
		ProxyTime    int `json:"proxy_time"`
	}{}
	err := public.M("request_total").
		Where("date = ?", []interface{}{startDate}).
		Where("hour = ?", []interface{}{startHour}).
		Where("minute > ?", []interface{}{startMinute}).
		Field([]string{
			"round(ifnull(SUM(sec_request)/count(*), 0)) as `qps`",
			"round(ifnull(SUM(avg_proxy_time)/count(*), 0)) as `proxy_time`",
		}).
		FindAs(&res)
	if err != nil {
		logging.Info("获取平均请求失败：", err)
	}
	qps = res.RequestTotal
	proxy_time = res.ProxyTime
	return qps, proxy_time
}

func (cr *cronProvider) getBlockingTime(startTime int64) ([]map[string]interface{}, int64, int64) {
	var max_id int64
	var min_time int64
	res, err := public.M("blocking_ip").
		Where("time >= ?", []interface{}{startTime}).
		Where("block_type =?", []interface{}{"cc"}).
		Field([]string{"id", "time", "ip", "ip_city ", "ip_country", "ip_province", "uri", "server_name", "host", "block_type"}).
		Select()

	if err != nil {
		res = []map[string]interface{}{}
		max_id = 0

	} else {
		for _, item := range res {
			if item["id"].(int64) > max_id {
				max_id = item["id"].(int64)
				min_time = item["time"].(int64)
			}
			if item["time"].(int64) < min_time {
				min_time = item["time"].(int64)
			}
		}
	}
	return res, max_id, min_time
}

func (cr *cronProvider) checkCCTableUnfinished() bool {
	res, err := public.S("cc_log").
		Where("status = ?", []interface{}{1}).
		Count()

	if err != nil {

		return false
	}
	if res > 0 {

		return true
	} else {

		return false
	}

}

func (cr *cronProvider) handleBlockingData(data interface{}) map[string]types.CClog {
	var logs []types.CClog
	for _, v := range data.([]map[string]interface{}) {
		ipInfo := types.CCIpInfo{
			Ip:       v["ip"].(string),
			City:     v["ip_city"].(string),
			Country:  v["ip_country"].(string),
			Province: v["ip_province"].(string),
		}
		log := types.CClog{
			IpInfo:     []types.CCIpInfo{ipInfo},
			Uri:        v["uri"].(string),
			ServerName: v["server_name"].(string),
			Host:       v["host"].(string),
			BlockType:  v["block_type"].(string),
		}

		logs = append(logs, log)
	}

	mergedLogs := make(map[string]types.CClog)
	for _, log := range logs {
		key := log.ServerName + "~" + log.Uri
		mergedLog, ok := mergedLogs[key]
		if !ok {
			mergedLogs[key] = log
		} else {
			mergedLog.IpInfo = append(mergedLog.IpInfo, log.IpInfo...)
			mergedLogs[key] = mergedLog
		}
	}

	for key, mergedLog := range mergedLogs {
		ipInfoMap := make(map[string]*types.CCIpInfo)
		var mergedIpInfo []types.CCIpInfo

		for _, ipInfo := range mergedLog.IpInfo {
			existingIpInfo, ok := ipInfoMap[ipInfo.Ip]
			if !ok {
				var ip_type int

				if public.IsIpv4(ipInfo.Ip) {
					ip_type = 0
				} else {
					ip_type = 1
				}
				ipInfoMap[ipInfo.Ip] = &types.CCIpInfo{
					Ip:       ipInfo.Ip,
					Country:  ipInfo.Country,
					Province: ipInfo.Province,
					City:     ipInfo.City,
					Request:  1,
					IpType:   ip_type,
				}
			} else {
				existingIpInfo.Request++
			}
		}

		for _, v := range ipInfoMap {
			mergedIpInfo = append(mergedIpInfo, *v)
		}

		mergedLog.IpInfo = mergedIpInfo
		mergedLogs[key] = mergedLog
	}

	return mergedLogs

}

func (cr *cronProvider) GetSystemInfo() (types.SystemInfo, error) {
	var systemInfo types.SystemInfo
	cacheKey_sys := "OverView__sysInfo"
	if cache.Has(cacheKey_sys) {
		systemInfo = cache.Get(cacheKey_sys).(types.SystemInfo)
	} else {
		systemInfo = public.GetSystemInfo()
		cache.Set(cacheKey_sys, systemInfo, 5)
	}
	return systemInfo, nil
}

func (cr *cronProvider) NginxCount() (res1 struct {
	ProxyTime float64 `json:"proxy_time"`
	Qps       float64 `json:"qps"`
}) {
	res, err := public.HttpPostByToken(public.URL_HTTP_REQUEST+"/get_global_status", 15)
	if err != nil {
		qps, proxy_time := cr.getLatestRequest()
		res1.ProxyTime = float64(proxy_time)
		res1.Qps = float64(qps)
		return res1
	}
	file_data := make(map[string]interface{}, 0)
	err = json.Unmarshal([]byte(res), &file_data)
	if err != nil {
		qps, proxy_time := cr.getLatestRequest()
		res1.ProxyTime = float64(proxy_time)
		res1.Qps = float64(qps)

		return res1
	}
	var proxy_time float64
	var qps float64
	if v, ok := file_data["msg"]; ok {
		if c, ok := v.(map[string]interface{}); ok {
			proxy_time = c["proxy_time"].(float64)
			qps = c["qps"].(float64)
		}
	}
	res1.ProxyTime = proxy_time
	res1.Qps = qps
	return res1
}

func (cr *cronProvider) getBlockingTimeMaxId() (int, error) {
	var end_time int
	res, err := public.M("blocking_ip").
		Field([]string{"max(time) as max_time"}).
		Find()
	end_time = public.InterfaceToInt(res["max_time"])
	return end_time, err
}

func (cr *cronProvider) addSubmitBlockLogsAndUpdateMaliciousIp() {

	public.RemoveTaskByTag("SubmitBlockLogsAndUpdateMaliciousIp")

	if !public.CheckTaskByTag("SubmitBlockLogsAndUpdateMaliciousIp") {

		if _, err := public.AddTaskInterval("SubmitBlockLogsAndUpdateMaliciousIp", 1*time.Hour, func() {
			time.Sleep(1 * time.Minute)
			public.UpdateMaliciousIp()
		}, 45*time.Minute); err != nil {
			logging.Info("添加更新本地恶意IP库定时任务失败：", err)
		}
	}
}

func (cr *cronProvider) addWafRuleBackup() {
	_ = public.AddTaskOnce(public.WafRuleBackup, time.Second*1)
	if !public.CheckTaskByTag("WafRuleBackup") {

		err := error(nil)
		if clusterCommon.ClusterState() != clusterCommon.CLUSTER_DISABLED {
			_, err = public.AddTaskDayAtTime("WafRuleBackup", "00:00:30", public.WafRuleBackup, 0)
		}
		if err != nil {
			public.AppendFile(types.WafRuleLogPath, "添加WAF规则备份任务失败："+err.Error(), true)
		} else {
			public.AppendFile(types.WafRuleLogPath, "添加WAF规则备份任务成功", true)
		}
	}
}

func (cr *cronProvider) addWafRuleRestore() {
	if !public.CheckTaskByTag("WafRuleRestore") {

		_, err := public.AddTaskInterval("WafRuleRestore", 1*time.Minute, public.WafRuleRestore, 1*time.Minute)
		if err != nil {
			public.AppendFile(types.WafRuleRestoreLogPath, "添加WAF规则检测恢复任务失败："+err.Error(), true)
		} else {
			public.AppendFile(types.WafRuleRestoreLogPath, "添加WAF规则检测恢复任务成功", true)
		}
	}
}

func (cr *cronProvider) SyncDataHelpRequest(requestData []map[string]interface{}, node_id int64) bool {

	var data []map[string]interface{}
	for _, item := range requestData {
		data = append(data,
			map[string]interface{}{
				"node_id":          node_id,
				"total":            item["request"],
				"err_499":          item["err_499"],
				"err_502":          item["err_502"],
				"err_504":          item["err_504"],
				"timestamp_minute": item["timestamp"],
			})
	}
	_, err := public.M("cluster_request_trend").Duplicate(map[string]string{"total": "values(`total`)", "err_499": "values(`err_499`)", "err_502": "values(`err_502`)", "err_504": "values(`err_504`)"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) SyncDataHelpIntercept(interceptData []map[string]interface{}, node_id int64) bool {

	var data []map[string]interface{}
	for _, item := range interceptData {

		is_inland := 0
		if item["ip_country"].(string) == "中国" {
			is_inland = 1
		}
		data = append(data,
			map[string]interface{}{
				"node_id":     node_id,
				"server_name": item["server_name"],
				"ip":          item["ip"],
				"method":      item["method"],
				"request_uri": item["request_uri"],
				"uri":         item["uri"],
				"host":        item["host"],
				"risk_type":   item["risk_type"],
				"user_agent":  public.GetTableIdHelp("user_agent", item["user_agent"].(string)),
				"filter_rule": public.GetTableIdHelp("filter_rule", item["filter_rule"].(string)),

				"incoming_value": public.GetTableIdHelp("incoming_value", item["incoming_value"].(string)),
				"get_http_log":   public.GetTableIdHelp("get_http_log", item["get_http_log"].(string)),
				"http_log_path":  public.GetTableIdHelp("http_log_path", item["http_log_path"].(string)),
				"action":         public.InterfaceToInt64(item["action"]),
				"time":           public.InterfaceToInt64(item["time"]),
				"is_inland":      is_inland,
				"ip_city":        item["ip_city"],
				"ip_country":     item["ip_country"],
				"ip_province":    item["ip_province"],
				"ip_longitude":   item["ip_longitude"],
				"ip_latitude":    item["ip_latitude"],
			})

	}

	month := time.Now().Format("200601")
	tablename := "cluster_totla_log_all" + month
	_, err := public.M(tablename).Duplicate(map[string]string{"is_inland": "is_inland"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) SyncDataHelpBlock(blockData []map[string]interface{}, node_id int64) bool {
	var data []map[string]interface{}
	for _, item := range blockData {

		is_inland := 0
		if item["ip_country"].(string) == "中国" {
			is_inland = 1
		}

		data = append(data,
			map[string]interface{}{
				"node_id":     node_id,
				"server_name": item["server_name"],
				"ip":          item["ip"],
				"method":      item["method"],
				"request_uri": item["request_uri"],
				"uri":         item["uri"],
				"host":        item["host"],
				"risk_type":   item["risk_type"],
				"user_agent":  public.GetTableIdHelp("user_agent", item["user_agent"].(string)),
				"filter_rule": public.GetTableIdHelp("filter_rule", item["filter_rule"].(string)),

				"incoming_value": public.GetTableIdHelp("incoming_value", item["incoming_value"].(string)),
				"get_http_log":   public.GetTableIdHelp("get_http_log", item["get_http_log"].(string)),
				"http_log_path":  public.GetTableIdHelp("http_log_path", item["http_log_path"].(string)),
				"time":           public.InterfaceToInt64(item["time"]),
				"is_inland":      is_inland,
				"ip_city":        item["ip_city"],
				"ip_country":     item["ip_country"],
				"ip_province":    item["ip_province"],
				"ip_longitude":   item["ip_longitude"],
				"ip_latitude":    item["ip_latitude"],

				"block_type":    public.InterfaceToInt64(item["block_type"]),
				"blocking_time": public.InterfaceToInt64(item["blocking_time"]),
				"block_status":  public.InterfaceToInt64(item["block_status"]),
			})

	}

	month := time.Now().Format("200601")
	tablename := "cluster_blocking_ip_all" + month

	_, err := public.M(tablename).Duplicate(map[string]string{"is_inland": "is_inland"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) SyncDataHelpSlow(slowData []map[string]interface{}, node_id int64) bool {

	var data []map[string]interface{}

	for _, item := range slowData {
		method := public.GetTableIdHelp("method", item["method"].(string))
		ip := public.GetTableIdHelp("ip", item["ip"].(string))
		request_uri := public.GetTableIdHelp("request_uri", item["uri"].(string))

		onedata := map[string]interface{}{
			"node_id":     node_id,
			"server_name": item["server_name"],
			"domain":      item["domain"],
			"ip":          ip,
			"method":      method,
			"request_uri": request_uri,
			"times":       item["times"],
			"timestamp":   item["timestamp"],
		}
		data = append(data, onedata)
	}

	_, err := public.M("cluster_slow_log").Duplicate(map[string]string{"timestamp": "timestamp"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true
}

func (cr *cronProvider) SyncDataHelpMap(mapData map[string]interface{}, node_id int64) bool {

	g_ip_r := mapData["g_ip_r"].(map[string]interface{})
	g_ip_in := mapData["g_ip_in"].(map[string]interface{})
	g_area_r := mapData["g_area_r"].(map[string]interface{})
	g_area_in := mapData["g_area_in"].(map[string]interface{})
	_ = cr.SyncDataHelpMapIp(g_ip_r, node_id)
	_ = cr.SyncDataHelpMapIpIntercept(g_ip_in, node_id)
	_ = cr.SyncDataHelpMapArea(g_area_r, node_id)
	_ = cr.SyncDataHelpMapAreaIntercept(g_area_in, node_id)
	return true

}

func (cr *cronProvider) SyncDataHelpMapIp(mapData map[string]interface{}, node_id int64) bool {

	var data []map[string]interface{}

	list, ok := cr.dataNoTypeToArreyMap(mapData["list"])
	if !ok {
		return false
	}
	if len(list) == 0 {
		return false
	}

	for _, item := range list {
		is_inland := 0
		if country, ok := item["country"].(string); ok && country == "中国" {
			is_inland = 1
		}
		data = append(data,
			map[string]interface{}{
				"node_id":       node_id,
				"ip":            item["ip"],
				"visits":        item["visits"],
				"ip_country":    item["country"],
				"ip_city":       item["city"],
				"ip_province":   item["province"],
				"is_inland":     is_inland,
				"timestamp_day": cr.GetDayZeroTime(item["date"].(string)),
			})
	}
	_, err := public.M("cluster_request_map_ip").Duplicate(map[string]string{"visits": "values(`visits`)"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) SyncDataHelpMapIpIntercept(mapData map[string]interface{}, node_id int64) bool {
	var data []map[string]interface{}
	list, ok := cr.dataNoTypeToArreyMap(mapData["list"])
	if !ok {
		return false
	}
	if len(list) == 0 {
		return false
	}

	for _, item := range list {
		is_inland := 0
		if item["country"].(string) == "中国" {
			is_inland = 1
		}

		data = append(data,
			map[string]interface{}{
				"node_id":       node_id,
				"ip":            item["ip"],
				"visits":        item["visits"],
				"ip_country":    item["country"],
				"ip_city":       item["city"],
				"ip_province":   item["province"],
				"is_inland":     is_inland,
				"timestamp_day": cr.GetDayZeroTime(item["date"].(string)),
			})

	}
	_, err := public.M("cluster_intercept_map_ip").Duplicate(map[string]string{"visits": "values(`visits`)"}).InsertAll(data)
	if err != nil {
		return false
	}

	return true
}

func (cr *cronProvider) SyncDataHelpMapArea(mapData map[string]interface{}, node_id int64) bool {
	data := make([]map[string]interface{}, 0)
	list, ok := cr.dataNoTypeToArreyMap(mapData["list"])
	if !ok {
		return false
	}
	if len(list) == 0 {
		return false
	}

	for _, item := range list {
		onedata := make(map[string]interface{})
		timestamp_day := cr.GetDayZeroTime(item["date"].(string))
		is_inland := 0
		if item["country"].(string) == "中国" {
			is_inland = 1
		}

		onedata = map[string]interface{}{
			"node_id":       node_id,
			"ip_country":    item["country"],
			"ip_city":       item["city"],
			"ip_province":   item["province"],
			"visits":        item["visits"],
			"is_inland":     is_inland,
			"timestamp_day": timestamp_day,
		}
		data = append(data, onedata)

	}

	_, err := public.M("cluster_request_map_area").Duplicate(map[string]string{"visits": "values(`visits`)"}).InsertAll(data)
	if err != nil {
		return false
	}

	return true

}

func (cr *cronProvider) SyncDataHelpMapAreaIntercept(mapData map[string]interface{}, node_id int64) bool {
	data := make([]map[string]interface{}, 0)
	list, ok := cr.dataNoTypeToArreyMap(mapData["list"])
	if !ok {
		return false
	}
	if len(list) == 0 {
		return false
	}
	for _, item := range list {
		is_inland := 0
		if item["country"].(string) == "中国" {
			is_inland = 1
		}
		data = append(data,
			map[string]interface{}{
				"node_id":       node_id,
				"ip_country":    item["country"],
				"ip_city":       item["city"],
				"ip_province":   item["province"],
				"visits":        item["visits"],
				"is_inland":     is_inland,
				"timestamp_day": cr.GetDayZeroTime(item["date"].(string)),
			})

	}
	_, err := public.M("cluster_intercept_map_area").Duplicate(map[string]string{"visits": "values(`visits`)"}).InsertAll(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) SyncDataHelpTotal(totalData map[string]interface{}, node_id int64) bool {

	timestamp := public.ZeroTimestamp()

	var data map[string]interface{}
	data = map[string]interface{}{
		"node_id":       node_id,
		"ip":            totalData["ips_total"],
		"malicious":     totalData["malicious_total"],
		"total":         totalData["request_total"],
		"timestamp_day": timestamp,
	}
	_, err := public.M("cluster_day_counts").Duplicate(map[string]string{"ip": "values(`ip`)", "malicious": "values(`malicious`)", "total": "values(`total`)"}).Insert(data)
	if err != nil {
		return false
	}
	return true

}

func (cr *cronProvider) GetDayZeroTime(dateStr string) int64 {
	date, err := public.ParseDateStrToTime("2006-01-02", dateStr)
	if err != nil {
		fmt.Println("日期解析错误:", err)
		return 0
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Println("时区加载错误:", err)
		return 0
	}
	midnight := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, location)
	timestamp := midnight.Unix()
	return timestamp
}

func (cr *cronProvider) dataNoTypeToArreyMap(data any) ([]map[string]any, bool) {
	m := make([]map[string]any, 0)
	if err := core.MapToStruct(data, &m); err != nil {
		return nil, false
	}
	return m, true
}

func (cr *cronProvider) UpdateRealtimeHistory() {
	if _, err := public.AddTaskInterval("UpdateRealtimeHistory", 3*time.Second, func() {
		realtime := cluster_core.ToolsSingleton().RealtimeSelf()
		curTimeTruncateMinute := time.Now().Truncate(time.Minute).Unix()
		if _, err := public.M("btwaf_realtime_history").Duplicate(map[string]string{
			"cpu":      "(`cpu` + values(`cpu`)) / 2",
			"mem":      "(`mem` + values(`mem`)) / 2",
			"qps":      "(`qps` + values(`qps`)) / 2",
			"upload":   "(`upload` + values(`upload`)) / 2",
			"download": "(`download` + values(`download`)) / 2",
		}).Insert(map[string]any{
			"cpu":         realtime.CPU.Percent,
			"mem":         realtime.Mem.UsedPercent,
			"qps":         realtime.Qps,
			"download":    realtime.Download,
			"upload":      realtime.Upload,
			"create_time": curTimeTruncateMinute,
		}); err != nil {
			logging.Error("更新主机资源历史数据失败：", err)
		}
		disk := make([]map[string]any, 0, len(realtime.DiskList))
		for _, v := range realtime.DiskList {
			disk = append(disk, map[string]any{
				"mountpoint":  v.Mountpoint,
				"read":        v.ReadBytesPerSecond,
				"write":       v.WriteBytesPerSecond,
				"used":        v.Used,
				"create_time": curTimeTruncateMinute,
			})
		}

		if len(disk) > 0 {
			if _, err := public.M("btwaf_disk_realtime_history").Duplicate(map[string]string{
				"used":  "(`used` + values(`used`)) / 2",
				"read":  "(`read` + values(`read`)) / 2",
				"write": "(`write` + values(`write`)) / 2",
			}).InsertAll(disk); err != nil {
				logging.Error("更新主机资源历史数据失败：", err)
			}
		}
	}, 10*time.Second); err != nil {
		return
	}
}
