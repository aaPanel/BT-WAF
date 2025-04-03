package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/types"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

func init() {
	core.RegisterModule(&Replace{
		replace_path: "/www/cloud_waf/nginx/conf.d/waf/rule/replacement.json",

		form_show: map[string]string{
			"site_rules": "网站规则",
			"uri_rules":  "网站URI规则",
		},
	})

}

type Replace struct {
	replace_path string
	form_show    map[string]string
}

func (re *Replace) AddRules(request *http.Request) core.Response {
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
	exist := re.is_exist(params.SiteId)
	if exist {
		ok := re.openRuleStatus(params.SiteId, params.Open)
		if ok == false {
			public.WriteOptLog(fmt.Sprintf("网站 [%s] %s关键词替换失败", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
			return core.Fail("操作失败")
		} else {
			public.WriteOptLog(fmt.Sprintf("网站 [%s] %s关键词替换成功", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
		}
		if params.Open == false {
			path1 := "/www/cloud_waf/nginx/conf.d/waf/data/replace_count/" + params.SiteId + "/"
			if public.FileExists(path1) {
				err := os.RemoveAll(path1)
				if err != nil {
					logging.Error("清空缓存失败：", err)
				}
			}
			public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_replace_hit?site=%s", params.SiteId), 2)

		}
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
		return core.Success("操作成功")
	}
	rules := map[string][]types.ReplaceRule{
		"site_rules": {},
	}
	replaceData := types.Replace{
		SiteName: params.SiteName,
		SiteId:   params.SiteId,
		Open:     true,
		Rules:    rules,
	}
	oneData := make(map[string]types.Replace)
	oneData[params.SiteId] = replaceData
	json_data, err := public.ReadFile(re.replace_path)

	if err != nil {
		buf := &bytes.Buffer{}
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(oneData)
		if err != nil {
			return core.Fail(err)
		}
		_, err = public.WriteFile(re.replace_path, buf.String())
		if err != nil {
			return core.Fail("写入加速配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("网站 [%s] %s关键词替换成功", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
		return core.Success("开启成功")
	}
	file_data := make(map[string]types.Replace)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	file_data[params.SiteId] = replaceData
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(file_data)
	if err != nil {
		return core.Fail(err)
	}
	_, err = public.WriteFile(re.replace_path, buf.String())
	if err != nil {
		return core.Fail("写入加速配置失败")
	}
	public.WriteOptLog(fmt.Sprintf("网站[%s]开启 关键词替换", params.SiteName), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
	return core.Success("新增成功")
}

func (re *Replace) GetRules(request *http.Request) core.Response {
	params := struct {
		SiteName string `json:"site_name"`
		SiteId   string `json:"site_id"`
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

	file_data, _ := re.getSpeedData()
	if file_data == nil {
		return core.Success([]interface{}{})
	}
	all := file_data[params.SiteId]
	if all == nil {
		return core.Success([]interface{}{})
	}
	data := make([]map[string]any, 0)
	if siteRule, ok := all.(map[string]interface{})["rules"]; ok {
		for _, v := range siteRule.(map[string]interface{}) {
			if v2, ok := v.([]interface{}); ok {
				for _, v3 := range v2 {
					if v4, ok := v3.(map[string]any); ok {
						data = append(data, v4)
					}
				}
			}
		}
	}
	for _, v := range data {
		v["hit"] = re.get_site_rule_hit(params.SiteId, v["key"].(string))
	}
	sort.Slice(data, func(q, j int) bool {
		return data[q]["timestamp"].(float64) > data[j]["timestamp"].(float64)
	})
	return core.Success(data)

}

func (re *Replace) AddRulesInfo(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName   string `json:"site_name"`
		SiteId     string `json:"site_id"`
		MatchType  string `json:"match_type"`
		MatchValue string `json:"match_value"`
		Keyward    string `json:"keyward"`
		ReValue    string `json:"re_value"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteId == "" || params.MatchType == "" || params.ReValue == "" || params.Keyward == "" {
		return core.Fail("数据不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}

	if params.MatchType != "site_rules" && params.MatchType != "uri_rules" {
		return core.Fail("form参数错误")
	}
	new_rule := types.ReplaceRule{
		MatchType:  params.MatchType,
		MatchValue: params.MatchValue,
		Keyword:    params.Keyward,
		ReValue:    params.ReValue,
		Key:        public.RandomStr(20),
		Timestamp:  timestamp,
	}

	file_data, _ := re.getSpeedDatastruct()
	if file_data == nil {
		file_data = make(map[string]types.Replace)
	}

	rule_data := file_data[params.SiteId].Rules[params.MatchType]
	if rule_data == nil {
		is_ok := re.addRulesCof(&file_data, params.SiteName, params.SiteId, false, new_rule)
		if is_ok == false {
			public.WriteOptLog(fmt.Sprintf("网站[%s] 添加替换规则失败", params.SiteName), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
			return core.Fail("添加失败")
		}

	} else {
		rule_data = append(rule_data, new_rule)
		file_data[params.SiteId].Rules[params.MatchType] = rule_data
		buf := &bytes.Buffer{}
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(file_data)
		if err != nil {
			return core.Fail(err)
		}
		_, err = public.WriteFile(re.replace_path, buf.String())
		if err != nil {
			return core.Fail("写入失败")
		}
	}

	ps := re.form_show[params.MatchType] + " " + params.MatchValue + " 将 [" + params.Keyward + "] 替换为 [" + params.ReValue + "]"
	public.WriteOptLog(fmt.Sprintf("网站[%s] 添加替换规则:  %s", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
	return core.Success("添加成功")
}

func (re *Replace) UpdateRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params := struct {
		SiteName   string `json:"site_name"`
		SiteId     string `json:"site_id"`
		MatchType  string `json:"match_type"`
		Key        string `json:"key"`
		MatchValue string `json:"match_value"`
		Keyward    string `json:"keyward"`
		ReValue    string `json:"re_value"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteId == "" || params.Key == "" || params.MatchType == "" || params.ReValue == "" || params.Keyward == "" {
		return core.Fail("数据不能为空")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}

	if params.MatchType != "site_rules" && params.MatchType != "uri_rules" {
		return core.Fail("form参数错误")
	}
	file_data, _ := re.getSpeedDatastruct()
	if file_data == nil {
		return core.Fail("无数据")
	}

	rule_data := file_data[params.SiteId].Rules[params.MatchType]
	var oldRule types.ReplaceRule
	var flag = false
	for i := range rule_data {
		if rule_data[i].Key == params.Key {
			flag = true
			oldRule = rule_data[i]
			rule_data[i].MatchValue = params.MatchValue
			rule_data[i].Keyword = params.Keyward
			rule_data[i].ReValue = params.ReValue
			rule_data[i].Timestamp = timestamp
			break
		}
	}
	if !flag {
		return core.Fail("没有该数据")
	}
	file_data[params.SiteId].Rules[params.MatchType] = rule_data
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(file_data)
	if err != nil {
		return core.Fail(err)
	}
	_, err = public.WriteFile(re.replace_path, buf.String())
	if err != nil {
		return core.Fail("修改失败")
	}
	ps := re.form_show[params.MatchType] + " " + params.MatchValue + " (" + oldRule.Keyword + " 替换 " + oldRule.ReValue + ") 修改为" + " (" + params.Keyward + " 替换 " + params.ReValue + ")"
	public.WriteOptLog(fmt.Sprintf("网站[%s] 修改替换规则:  %s", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
	return core.Success("修改成功")
}

func (re *Replace) DeleteRules(request *http.Request) core.Response {
	params := struct {
		SiteName   string `json:"site_name"`
		SiteId     string `json:"site_id"`
		MatchType  string `json:"match_type"`
		Key        string `json:"key"`
		MatchValue string `json:"match_value"`
		Keyward    string `json:"keyward"`
		ReValue    string `json:"re_value"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteId == "" || params.Key == "" || params.MatchType == "" {
		return core.Fail("数据不能为空")
	}

	if params.MatchType != "site_rules" && params.MatchType != "uri_rules" {
		return core.Fail("form参数错误")
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId, params.SiteName).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}

	file_data, _ := re.getSpeedDatastruct()
	if file_data == nil {
		return core.Fail("无数据")
	}

	var flag = false
	rule_data := file_data[params.SiteId].Rules[params.MatchType]
	for i := range rule_data {
		if rule_data[i].Key == params.Key {
			rule_data = append(rule_data[:i], rule_data[i+1:]...)
			flag = true
			break
		}
	}
	if !flag {
		return core.Fail("没有该数据")
	}
	file_data[params.SiteId].Rules[params.MatchType] = rule_data
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(file_data)
	if err != nil {
		return core.Fail(err)
	}
	_, err = public.WriteFile(re.replace_path, buf.String())
	if err != nil {
		return core.Fail("删除失败")
	}

	ps := re.form_show[params.MatchType] + " " + params.MatchValue + " [" + params.Keyward + "] 替换 [" + params.ReValue + "]"
	path := "/www/cloud_waf/nginx/conf.d/waf/data/replace_total/" + params.SiteId + "/count/" + params.Key
	if !public.FileExists(path) {
		return core.Success("清空命中成功")
	}
	err = os.Remove(path)
	if err != nil {
		logging.Error("清除命中失败：", err)
	}
	public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_replace_hit?flags=%s&site=%s&info=%s", "1", params.SiteId, params.Key), 2)

	public.WriteOptLog(fmt.Sprintf("网站[%s] 删除替换规则:  %s", params.SiteName, ps), public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 10)
	return core.Success("删除成功")
}

func (re *Replace) ClearHit(request *http.Request) core.Response {
	params := struct {
		SiteId string `json:"site_id"`
		Key    string `json:"key"`
		Type   string `json:"type"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteId == "" || params.Type == "" || params.Key == "" {
		return core.Fail("参数错误")
	}
	count, err := public.M("site_info").Where("site_id=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	if params.Type == "0" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/replace_total/" + params.SiteId + "/"
		os.RemoveAll(path)
	}
	if params.Type == "1" {
		path := "/www/cloud_waf/nginx/conf.d/waf/data/replace_total/" + params.SiteId + "/count/"
		if !public.FileExists(path) {
			return core.Fail("清除成功")
		}
		files, err := os.ReadDir(path)
		var flag = false
		if err != nil {
			return core.Fail("清除成功")
		}
		for _, file := range files {
			if file.Name() == params.Key {
				flag = true
				break
			}
			if flag {
				path2 := path + params.Key
				os.Remove(path2)
				return core.Fail("清除成功")
			}
		}
	}
	public.HttpPostByToken(fmt.Sprintf("http://127.0.0.251/clear_replace_hit?flags=%s&site=%s&info=%s", params.Type, params.SiteId, params.Key), 2)
	ps := fmt.Sprintf("清空网站[%s] 命中数成功", params.SiteId)
	public.WriteOptLog(ps, public.OPT_LOG_TYPE_REPLACEMENT, public.GetUid(request))
	return core.Success("清除成功")
}

func (re *Replace) addRulesCof(file_data *map[string]types.Replace, site_name string, site_id string, open bool, new_rule types.ReplaceRule) bool {

	if *file_data == nil {
		*file_data = make(map[string]types.Replace)
	}

	rules := make(map[string][]types.ReplaceRule)
	rules["site_rules"] = []types.ReplaceRule{new_rule}
	replaceData := types.Replace{
		SiteName: site_name,
		SiteId:   site_id,
		Open:     open,
		Rules:    rules,
	}
	(*file_data)[site_id] = replaceData
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(file_data)
	if err != nil {
		return false
	}
	_, err = public.WriteFile(re.replace_path, buf.String())
	if err != nil {
		return false
	}
	return true

}

func (re *Replace) is_exist(server_id string) bool {

	file_data, err := re.getSpeedData()
	if err != nil {
		return false
	}
	if _, ok := file_data[server_id]; ok {
		return true
	}

	return false
}

func (re *Replace) getSpeedData() (map[string]interface{}, error) {

	json_data, err := public.ReadFile(re.replace_path)
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

func (re *Replace) getSpeedDatastruct() (map[string]types.Replace, error) {
	json_data, err := public.ReadFile(re.replace_path)
	if err != nil {
		return nil, err
	}
	file_data := make(map[string]types.Replace)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return nil, err
	}

	return file_data, nil
}

func (re *Replace) openRuleStatus(site_id string, open bool) bool {
	file_data, err := re.getSpeedData()
	if err != nil {
		return false
	}
	if _, ok := file_data[site_id]; ok {
		file_data[site_id].(map[string]interface{})["open"] = open
	}
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(file_data)
	if err != nil {
		return false
	}
	_, err = public.WriteFile(re.replace_path, buf.String())
	if err != nil {
		return false
	}
	return true
}

func (re *Replace) get_site_rule_hit(siteid string, rule_key string) int {
	path1 := fmt.Sprintf("/www/cloud_waf/nginx/conf.d/waf/data/replace_total/%s/count/%s", siteid, rule_key)
	hit := re.get_site_hit_file(path1)
	return hit

}

func (re *Replace) get_site_hit_file(path string) (num int) {
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
