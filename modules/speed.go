package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/types"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	core.RegisterModule(&Speed{
		speed_path:      "/www/cloud_waf/nginx/conf.d/waf/rule/speed.json",
		speed_path_show: "/www/cloud_waf/nginx/conf.d/waf/rule/speed_show.json",
		form_show: map[string]string{
			"white": "不缓存规则",
			"force": "缓存规则",
		},
		obj_show: map[string]string{
			"uri":    "URI",
			"args":   "参数",
			"cookie": "Cookie",
			"ipv4":   "IPV4",
			"method": "请求方式",
			"host":   "域名",
			"ext":    "扩展",
			"type":   "响应类型",
		},
		match_show: map[string]string{
			"match":   "正则匹配",
			"prefix":  "前缀",
			"suffix":  "后缀",
			"keyword": "关键字",
			"=":       "完全匹配",
		},
	})

}

type Speed struct {
	speed_path      string
	speed_path_show string
	white_default   []types.SpeedRule
	form_show       map[string]string
	obj_show        map[string]string
	match_show      map[string]string
}

func (sp *Speed) AddRules(request *http.Request) core.Response {

	timestamp := time.Now().Unix()
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Open     bool   `json:"open"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" {
		return core.Fail("网站名称或id不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	ps := "关闭"
	if params.Open == true {
		ps = "开启"
	}
	exist := sp.is_exist(params.SiteId)
	if strings.Contains(params.SiteId, "..") {
		return core.Fail("文件路径错误")
	}
	if exist {
		ok := sp.openRuleStatus(params.SiteId, params.Open)

		if ok == false {
			public.WriteOptLog(fmt.Sprintf("网站 [%s] %s加速失败", params.SiteName, ps), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
			return core.Fail("操作失败")

		} else {
			public.WriteOptLog(fmt.Sprintf("网站 [%s] %s加速成功", params.SiteName, ps), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
		}
		if params.Open == false {
			path1 := "/www/cloud_waf/wwwroot/" + params.SiteId
			path2 := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total/" + params.SiteId
			path3 := "/www/cloud_waf/nginx/conf.d/waf/data/speed_cache/" + params.SiteId + "/count_size"

			public.DeleteFileAll(path1)
			if public.FileExists(path2) {
				err := os.RemoveAll(path2)
				if err != nil {
					logging.Error("清空网站统计失败：", err)
				}
			}
			if public.FileExists(path3) {
				err := os.Remove(path3)
				if err != nil {
					logging.Error("清空网站总缓存统计失败：", err)
				}
			}

			pss := "1"
			public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_hit?flags=%s&site=%s&info=all", pss, params.SiteId), 2)
			public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_countsize?flags=%s&site=%s", pss, params.SiteId), 2)
		}
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
		return core.Success("操作成功")
	}

	speedData := types.Speed{}
	def_whiteData := sp.def_whiteData()
	def_forceData := sp.def_forceData()
	speedData = types.Speed{
		SiteName:    params.SiteName,
		SiteId:      params.SiteId,
		Open:        true,
		Expire:      3600,
		SingleSize:  200,
		White:       def_whiteData,
		Force:       def_forceData,
		EmptyCookie: true,
		Timestamp:   timestamp,
	}
	json_data, err := public.ReadFile(sp.speed_path_show)
	if err != nil {
		speedDataSlice := make([]types.Speed, 0)
		speedDataSlice = append(speedDataSlice, speedData)
		bs, _ := json.Marshal(speedData)
		_, err = public.WriteFile(sp.speed_path_show, "["+string(bs)+"]")
		if err != nil {
			return core.Fail("写入加速配置失败")
		}
		if sp.sliceToMapLua(speedDataSlice) == false {
			return core.Fail("写入配置失败")
		} else {
			logging.Info("map同步成功")
		}
		public.WriteOptLog(fmt.Sprintf("网站 [%s] %s加速成功", params.SiteName, ps), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
		return core.Success("添加成功")
	}
	file_data := make([]types.Speed, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	file_data = append(file_data, speedData)
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i].Timestamp > file_data[j].Timestamp
	})

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail("写入专属规则失败")
	}
	if sp.sliceToMapLua(file_data) == false {
		return core.Fail("写入专属规则配置失败")
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return core.Fail("添加失败")
	}
	public.WriteOptLog(fmt.Sprintf("网站[%s]开启加速", params.SiteName), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("新增成功")
}

func (sp *Speed) UpdateRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Form     string `json:"form"`
		Key      string `json:"key"`
		Obj      string `json:"obj"`
		Type     string `json:"type"`
		Value    string `json:"value"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" || params.Key == "" || params.Type == "" || params.Value == "" {
		return core.Fail("数据不能为空")
	}
	if params.Form != "white" && params.Form != "force" {
		return core.Fail("form参数错误")
	}
	if params.Type != "match" && params.Type != "prefix" && params.Type != "suffix" && params.Type != "=" && params.Type != "keyword" {
		return core.Fail("type参数错误")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	file_data, _ := sp.getSpeedShowData2()
	for i := range file_data {
		if file_data[i].SiteId == params.SiteId {
			if params.Form == "white" {
				for j := range file_data[i].White {
					if file_data[i].White[j].Key == params.Key {
						file_data[i].White = append(file_data[i].White[:j], file_data[i].White[j+1:]...)
						file_data[i].White = append(file_data[i].White, types.SpeedRule{
							Obj:       params.Obj,
							Type:      params.Type,
							Value:     params.Value,
							Key:       public.RandomStr(20),
							Timestamp: timestamp,
						})
						sort.Slice(file_data[i].White, func(q, j int) bool {
							return file_data[i].White[q].Timestamp > file_data[i].White[j].Timestamp
						})
						break
					}
				}
			}
			if params.Form == "force" {
				for j := range file_data[i].Force {
					if file_data[i].Force[j].Key == params.Key {
						file_data[i].Force = append(file_data[i].Force[:j], file_data[i].Force[j+1:]...)
						file_data[i].Force = append(file_data[i].Force, types.SpeedRule{
							Obj:       params.Obj,
							Type:      params.Type,
							Value:     params.Value,
							Key:       public.RandomStr(20),
							Timestamp: timestamp,
						})
						sort.Slice(file_data[i].Force, func(q, j int) bool {
							return file_data[i].Force[q].Timestamp > file_data[i].Force[j].Timestamp
						})
						break
					}
				}
			}
			file_data[i].Timestamp = timestamp
		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail(err)
	}

	var data_o []types.Speed
	err = json.Unmarshal(rules_js, &data_o)
	if sp.sliceToMapLua(data_o) == false {
		return core.Fail("写入专属规则配置失败")
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return core.Fail("写入失败")
	}
	public.WriteOptLog(fmt.Sprintf("网站[%s] 加速规则变更  %s 修改: %s %s %s  ", params.SiteName, sp.form_show[params.Form], sp.obj_show[params.Obj], sp.match_show[params.Type], params.Value), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("修改成功")
}

func (sp *Speed) DelRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName string   `json:"site_name"`
		SiteId   string   `json:"site_id"`
		Form     string   `json:"form"`
		Key      []string `json:"key"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" || len(params.Key) == 0 || params.Form == "" {
		return core.Fail("数据不能为空")
	}
	if params.Form != "white" && params.Form != "force" {
		return core.Fail("form参数错误")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	isok, pss := sp.delSpeedRule(params.SiteId, params.Form, params.Key, timestamp)
	if isok == false {
		return core.Fail("删除失败")
	}

	public.WriteOptLog(fmt.Sprintf("删除网站[%s] %s 规则:  %s", params.SiteName, sp.form_show[params.Form], pss), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("删除成功")

}

func (sp *Speed) GetList(request *http.Request) core.Response {
	params := struct {
		P     int `json:"p"`
		PSize int `json:"p_size"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	data := make([]map[string]interface{}, 0)
	servers, _ := public.GetAllDomain()
	speData, _ := sp.getSpeedData()
	for _, v := range servers {
		site_, _ := public.GetSiteJson(v["name"])
		site_info := make(map[string]interface{})
		if _, ok := speData[v["name"]].(map[string]interface{}); !ok {
			hit_info := map[string]int{
				"hit":       0,
				"req":       0,
				"today_hit": 0,
				"today_req": 0,
			}
			site_info["site_name"] = v["domain"]
			site_info["site_id"] = v["name"]
			site_info["open"] = false
			site_info["expire"] = 3600
			site_info["size"] = 1024
			site_info["force"] = []string{}
			site_info["white"] = []string{}
			site_info["hit"] = hit_info
			site_info["fake"] = true
			site_info["addtime"] = site_.AddTime

		} else {

			site_info = speData[v["name"]].(map[string]interface{})
			site_info["hit"] = sp.get_site_hit(site_info["site_id"].(string))
			site_info["addtime"] = site_.AddTime

		}
		data = append(data, site_info)

	}
	sort.Slice(data, func(i, j int) bool {
		return data[i]["addtime"].(int) > data[j]["addtime"].(int)
	})
	data2 := public.PaginateData(data, params.P, params.PSize)

	return core.Success(data2)
}

func (sp *Speed) OpenRuleStatus(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Open     bool   `json:"open"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" {
		return core.Fail("网站名称或id不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	file_data, _ := sp.getSpeedShowData2()
	for i := range file_data {
		if file_data[i].SiteId == params.SiteId {
			if params.Open == false {
			} else {
			}
			file_data[i].Open = params.Open
			file_data[i].Timestamp = timestamp

		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}

	if sp.sliceToMapLua(file_data) == false {

		return core.Fail("写入配置失败")
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("修改成功")

}

func (sp *Speed) ClearCache(request *http.Request) core.Response {
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Type     string `json:"type"`
		Uri      string `json:"uri"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Type != "0" {
		if params.SiteName == "" || params.SiteId == "" {
			return core.Fail("网站名称或id不能为空")
		}
	}

	if params.Type == "2" && params.Uri == "" {
		return core.Fail("uri不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	ps := ""
	if params.Type == "0" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_cache"
		if !public.FileExists(path) {
			return core.Success("清空成功")
		}

		err := os.RemoveAll(path)
		if err != nil {
			return core.Fail("清空缓存失败")
		}

		ps = "清空全部缓存成功"

	}

	if params.Type == "1" {
		path := "/www/cloud_waf/wwwroot/" + params.SiteId + "/*"
		path1 := "/www/cloud_waf/nginx/conf.d/waf/data/speed_cache/" + params.SiteId + "/count_size"
		err := os.Remove(path1)
		if err != nil {
			logging.Error("清空缓存总统计失败：", err)
		}
		is_ok := public.DeleteFileAll(path)
		if !is_ok {
			logging.Error("清空缓存失败：", err)
		}

		ps = fmt.Sprintf("清空网站[%s]缓存成功", params.SiteName)
		public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_countsize?flags=%s&site=%s", params.Type, params.SiteId), 2)

	}

	public.WriteOptLog(ps, public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	return core.Success("清空成功")

}

func (sp *Speed) ClearCount(request *http.Request) core.Response {
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Type     string `json:"type"`
		Key      string `json:"key"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Type != "0" {
		if params.SiteName == "" || params.SiteId == "" {
			return core.Fail("网站名称或id不能为空")
		}
	}
	if params.Type == "3" && params.Key == "" {
		return core.Fail("key不能为空")
	}
	if strings.Contains(params.Key, "..") {
		return core.Fail("key不合法")
	}

	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	ps := ""
	if params.Type == "0" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total"
		if !public.FileExists(path) {
			return core.Success("清空成功")
		}

		err := os.RemoveAll(path)
		if err != nil {
			logging.Error("清空缓存失败：", err)
		}
		public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_hit?flags=%s&site=all&info=all", params.Type), 2)
		ps = "清空全部命中成功"

	}

	if params.Type == "1" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total/" + params.SiteId + "/"
		if !public.FileExists(path) {
			return core.Success("清空全部缓存成功")
		}
		err := os.RemoveAll(path)
		if err != nil {
			logging.Error("清空缓存失败：", err)
		}
		public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_hit?flags=%s&site=%s&info=all", params.Type, params.SiteId), 2)
		ps = fmt.Sprintf("清空网站[%s]命中成功", params.SiteName)

	}
	if params.Type == "2" {
		date := time.Now().Format("2006-01-02")
		path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total/" + params.SiteId + "/hit/" + date + ".json"
		if !public.FileExists(path) {
			return core.Success("清空成功")
		}
		fi, err := os.Stat(path)
		if err != nil {
			return core.Fail("清空命中失败")

		}
		if fi.IsDir() {
			os.RemoveAll(path)
		} else {
			os.Remove(path)

		}
		public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_hit?flags=%s&site=%s&info=%s", params.Type, params.SiteId, date), 2)
		ps = fmt.Sprintf("清空网站[%s] 今日命中成功", params.SiteName)

	}

	if params.Type == "3" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total/" + params.SiteId + "/hit/" + params.Key + ".json"
		if !public.FileExists(path) {
			return core.Success("清空命中成功")
		}
		fi, err := os.Stat(path)
		if err != nil {
			return core.Fail("清空命中失败")

		}
		if fi.IsDir() {
			os.RemoveAll(path)
		} else {
			os.Remove(path)
		}
		public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_speed_hit?flags=%s&site=%s&info=%s", params.Type, params.SiteId, params.Key), 2)
		ps = fmt.Sprintf("清空网站[%s] 规则命中成功", params.SiteName)
	}

	public.WriteOptLog(ps, public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	return core.Success("清空命中成功")

}

func (sp *Speed) UpdateSite(request *http.Request) core.Response {
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Expire   int64  `json:"expire"`
		Size     int64  `json:"size"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" {
		return core.Fail("网站名称或id不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	file_data, _ := sp.getSpeedShowData2()
	for i := range file_data {
		if file_data[i].SiteId == params.SiteId {
			file_data[i].Expire = params.Expire
			file_data[i].SingleSize = params.Size

		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	if sp.sliceToMapLua(file_data) == false {
		return core.Fail("写入配置失败")
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.WriteOptLog(fmt.Sprintf("修改网站[%s] 加速配置过期时间为%d 秒, 单条缓存大小为 %d MB ", params.SiteName, params.Expire, params.Size), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("修改成功")
}

func (sp *Speed) AddRulesInfo(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Form     string `json:"form"`
		Obj      string `json:"obj"`
		Type     string `json:"type"`
		Value    string `json:"value"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" || params.Type == "" || params.Value == "" {
		return core.Fail("数据不能为空")
	}
	if params.Form != "white" && params.Form != "force" {
		return core.Fail("form参数错误")
	}
	if params.Type != "match" && params.Type != "prefix" && params.Type != "suffix" && params.Type != "=" && params.Type != "keyword" && public.IsIpv4(params.Type) != true {
		return core.Fail("type参数错误")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}

	file_data, _ := sp.getSpeedShowData2()
	for i := range file_data {
		if file_data[i].SiteId == params.SiteId {
			if params.Form == "white" {
				file_data[i].White = append(file_data[i].White, types.SpeedRule{
					Obj:       params.Obj,
					Type:      params.Type,
					Value:     params.Value,
					Key:       public.RandomStr(20),
					Timestamp: timestamp,
				})
				sort.Slice(file_data[i].White, func(q, j int) bool {
					return file_data[i].White[q].Timestamp > file_data[i].White[j].Timestamp
				})
			}
			if params.Form == "force" {
				file_data[i].Force = append(file_data[i].Force, types.SpeedRule{
					Obj:       params.Obj,
					Type:      params.Type,
					Value:     params.Value,
					Key:       public.RandomStr(20),
					Timestamp: timestamp,
				})
				sort.Slice(file_data[i].Force, func(q, j int) bool {
					return file_data[i].Force[q].Timestamp > file_data[i].Force[j].Timestamp
				})

			}
			file_data[i].Timestamp = timestamp
		}
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return core.Fail(err)
	}

	var data_o []types.Speed
	err = json.Unmarshal(rules_js, &data_o)
	if sp.sliceToMapLua(data_o) == false {
		return core.Fail("写入专属规则配置失败")
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return core.Fail("写入失败")
	}
	public.WriteOptLog(fmt.Sprintf("添加网站[%s] %s 规则:  %s %s %s", params.SiteName, sp.form_show[params.Form], sp.obj_show[params.Obj], sp.match_show[params.Type], params.Value), public.OPT_LOG_TYPE_SITE_SPEED, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("修改成功")
}

func (sp *Speed) GetRulesInfo(request *http.Request) core.Response {
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
		Form     string `json:"form"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteName == "" || params.SiteId == "" {
		return core.Fail("网站名称或id不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	file_data, _ := sp.getSpeedShowData()

	list := make([]interface{}, 0)
	for _, dataMap := range file_data {
		if dataMap["site_id"] == params.SiteId {
			if params.Form == "force" {
				list = append(list, dataMap["force"])
			}
			if params.Form == "white" {
				list = append(list, dataMap["white"])
			}

			break
		}

	}
	sort.Slice(list, func(q, j int) bool {
		return list[q].(map[string]interface{})["timestamp"].(float64) > list[j].(map[string]interface{})["timestamp"].(float64)
	})
	return core.Success(list)
}

func (sp *Speed) ClusterGetList(request *http.Request) core.Response {
	params := struct {
		P     int `json:"p"`
		PSize int `json:"p_size"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	data := make([]map[string]interface{}, 0)
	servers, _ := public.GetMasterSiteIdAndName()
	speData, _ := sp.getSpeedData()
	for _, v := range servers {
		site_info := make(map[string]interface{})
		if _, ok := speData[v.SiteId].(map[string]interface{}); !ok {
			hit_info := map[string]int{
				"hit":       0,
				"req":       0,
				"today_hit": 0,
				"today_req": 0,
			}
			site_info["site_name"] = v.SiteName
			site_info["site_id"] = v.SiteId
			site_info["open"] = false
			site_info["expire"] = 3600
			site_info["size"] = 1024
			site_info["force"] = []string{}
			site_info["white"] = []string{}
			site_info["hit"] = hit_info
			site_info["fake"] = true
			site_info["addtime"] = v.CreateTime

		} else {
			site_info = speData[v.SiteId].(map[string]interface{})
			site_info["hit"] = sp.get_site_hit(site_info["site_id"].(string))
			site_info["addtime"] = v.CreateTime
		}
		data = append(data, site_info)

	}
	sort.Slice(data, func(i, j int) bool {
		return data[i]["addtime"].(int) > data[j]["addtime"].(int)
	})
	data2 := public.PaginateData(data, params.P, params.PSize)
	return core.Success(data2)
}

func (sp *Speed) openRuleStatus(site_id string, open bool) bool {
	file_data, _ := sp.getSpeedShowData2()
	for i := range file_data {
		if file_data[i].SiteId == site_id {
			file_data[i].Open = open
		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}

	if sp.sliceToMapLua(file_data) == false {
		logging.Error("map同步失败")
		return false
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return false
	}

	return true
}

func (sp *Speed) getSpeedData() (map[string]interface{}, error) {

	json_data, err := public.ReadFile(sp.speed_path)
	if err != nil {
		return nil, err
	}
	file_data := make(map[string]interface{})
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return nil, err
	}

	return file_data, nil
}

func (sp *Speed) getSpeedShowData() ([]map[string]interface{}, error) {

	json_data, err := public.ReadFile(sp.speed_path_show)
	if err != nil {
		return nil, err
	}
	file_data := []map[string]interface{}{}
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return nil, err
	}

	return file_data, nil
}

func (sp *Speed) getSpeedShowData2() ([]types.Speed, error) {
	json_data, err := public.ReadFile(sp.speed_path_show)
	if err != nil {
		return nil, err
	}

	file_data := make([]types.Speed, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return nil, err
	}
	return file_data, nil
}

func (sp *Speed) delSpeedRule(site_id string, form string, key []string, timestamp int64) (bool, []string) {
	file_data, _ := sp.getSpeedShowData2()
	var updatedData []types.SpeedRule
	var pss []string
	for i := range file_data {
		if file_data[i].SiteId == site_id {
			if form == "white" {
				for j := range file_data[i].White {
					removeRule := false
					for _, k := range key {
						if file_data[i].White[j].Key == k {
							ps := sp.obj_show[file_data[i].White[j].Obj] + " " + sp.obj_show[file_data[i].White[j].Type] + " " + file_data[i].White[j].Value
							pss = append(pss, ps)
							removeRule = true
							break
						}
					}
					if !removeRule {
						updatedData = append(updatedData, file_data[i].White[j])
					}
				}
				file_data[i].White = updatedData
			}
			if form == "force" {
				for j := range file_data[i].Force {
					removeRule := false
					for _, k := range key {
						if file_data[i].Force[j].Key == k {
							ps := sp.obj_show[file_data[i].White[j].Obj] + " " + sp.obj_show[file_data[i].White[j].Type] + " " + file_data[i].White[j].Value
							pss = append(pss, ps)
							removeRule = true
							break
						}
					}
					if !removeRule {
						updatedData = append(updatedData, file_data[i].Force[j])
					}
				}
				file_data[i].Force = updatedData
			}
			file_data[i].Timestamp = timestamp
		}
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		return false, nil
	}

	var data_o []types.Speed
	err = json.Unmarshal(rules_js, &data_o)
	if sp.sliceToMapLua(data_o) == false {
		return false, nil
	} else {
		logging.Info("map同步成功")
	}
	_, err = public.WriteFile(sp.speed_path_show, string(rules_js))
	if err != nil {
		return false, nil
	}
	return true, pss
}

func (sp *Speed) get_site_today_total(siteid string) int {
	startDate := time.Now().Format("2006-01-02")
	query_ip := public.M("request_total")
	res, _ := query_ip.Where("date = ?", []interface{}{startDate}).
		Where("server_name = ?", []interface{}{siteid}).
		Field([]string{"ifnull(SUM(request), 0) as `request_total`"}).
		Find()

	request_total := int(res["request_total"].(float64))
	return request_total

}

func (sp *Speed) is_exist(server_id string) bool {

	file_data, err := sp.getSpeedData()
	if err != nil {
		return false
	}
	if _, ok := file_data[server_id]; ok {
		return true
	}
	return false
}

func (sp *Speed) get_site_hit(siteid string) map[string]int {
	date := time.Now().Format("2006-01-02")
	path1 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/speed_total/%s/hit.json", siteid)
	path2 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/speed_total/%s/hit/%s.json", siteid, date)
	path3 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/speed_total/%s/total.json", siteid)
	path4 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/speed_total/%s/request/%s.json", siteid, date)
	hit := sp.get_site_hit_file(path1)
	today := sp.get_site_hit_file(path2)
	total_req := sp.get_site_hit_file(path3)
	today_req := sp.get_site_hit_file(path4)
	if total_req < hit {
		total_req = hit
	}
	if today_req < today {
		today_req = today
	}

	total := make(map[string]int)
	total["hit"] = hit
	total["req"] = total_req
	total["today_hit"] = today
	total["today_req"] = today_req
	return total
}

func (sp *Speed) get_site_rule_hit(siteid string, rule_key string) int {
	path1 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/speed_total/%s/hit/%s.json", siteid, rule_key)
	hit := sp.get_site_hit_file(path1)
	return hit

}

func (sp *Speed) get_site_hit_file(path string) (num int) {
	if !public.FileExists(path) {
		return 0
	}
	bod, err := public.ReadFile(path)
	if err != nil {
		return 0
	}
	num, err = strconv.Atoi(bod)
	return num

}

func (sp *Speed) def_whiteData() []types.SpeedRule {
	type1 := []string{"json", "xml", "html"}
	method := []string{"POST", "PUT", "DELETE", "OPTIONS"}

	timestamp := time.Now().Unix()
	white := make([]types.SpeedRule, 0)
	for _, v := range type1 {
		white = append(white, types.SpeedRule{
			Obj:       "type",
			Type:      "match",
			Value:     v,
			Key:       public.RandomStr(20),
			Timestamp: timestamp,
		})
	}
	for _, v := range method {
		white = append(white, types.SpeedRule{
			Obj:       "method",
			Type:      "=",
			Value:     v,
			Key:       public.RandomStr(20),
			Timestamp: timestamp,
		})
	}
	return white
}

func (sp *Speed) def_forceData() []types.SpeedRule {
	ext := []string{"gif", "jpg", "jpeg", "png", "bmp", "sw", "js", "css"}

	timestamp := time.Now().Unix()
	force := make([]types.SpeedRule, 0)
	for _, v := range ext {
		force = append(force, types.SpeedRule{
			Obj:       "ext",
			Type:      "suffix",
			Value:     v,
			Key:       public.RandomStr(20),
			Timestamp: timestamp,
		})
	}
	return force
}

func (sp *Speed) ruleDataHelpa(ruless map[string]interface{}) []types.SpeedRule {
	timestamp := time.Now().Unix()
	datas := make([]types.SpeedRule, 0)
	for obj, rules := range ruless {
		ruleSlice, ok := rules.([]interface{})
		if !ok || len(ruleSlice) == 0 {
			continue
		}
		for _, rule := range ruleSlice {
			ruleMap, ok := rule.(map[string]interface{})
			if !ok {
				continue
			}
			speedRule := types.SpeedRule{
				Obj:       obj,
				Type:      ruleMap["type"].(string),
				Value:     ruleMap["value"].(string),
				Key:       public.RandomStr(20),
				Timestamp: timestamp,
			}
			datas = append(datas, speedRule)
		}
	}
	return datas
}

func (sp *Speed) sliceToMapLua(data []types.Speed) bool {

	result := sp.sliceToMapLua1(data)
	rules_js, err := json.Marshal(result)
	if err != nil {
		return false
	}
	if err != nil {
		return false
	}
	_, err = public.WriteFile(sp.speed_path, string(rules_js))
	if err != nil {
		return false
	}
	return true

}

func (sp *Speed) sliceToMapLua1(data []types.Speed) map[string]interface{} {
	all := make(map[string]interface{}, 0)
	for _, speed := range data {
		result := make(map[string]interface{})
		result["force"] = sp.classifyRules(speed.Force)
		result["white"] = sp.classifyRules(speed.White)
		result["site_name"] = speed.SiteName
		result["site_id"] = speed.SiteId
		result["open"] = speed.Open
		result["expire"] = speed.Expire
		result["size"] = speed.SingleSize
		result["empty_cookie"] = speed.EmptyCookie
		result["timestamp"] = speed.Timestamp
		all[speed.SiteId] = result

	}
	return all

}

func (sp *Speed) classifyRules(rules []types.SpeedRule) map[string][]types.SpeedRule {
	ruleMap := make(map[string][]types.SpeedRule)
	for _, rule := range rules {
		ruleMap[rule.Obj] = append(ruleMap[rule.Obj], rule)
	}
	return ruleMap
}
