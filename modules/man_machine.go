package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/types"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {

	core.RegisterModule(&Manm{
		manm_path:        "/www/cloud_waf/nginx/conf.d/waf/rule/cc.json",
		manm_path_backup: "/www/cloud_waf/nginx/conf.d/waf/rule/cc_backup.json",
		type_info: map[string]string{
			"huadong": "滑动验证",
			"js":      "无感验证",
			"renji":   "等待5s验证",
		},
	})

}

type Manm struct {
	manm_path        string
	manm_path_backup string
	type_info        map[string]string
}

func (m *Manm) AddRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["open"].(float64); !ok {
		return core.Fail("open parameter error")
	}
	if _, ok := params["auth_type"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["rules"]; !ok {
		return core.Fail("rules parameter error")
	}
	if _, ok := params["ps"].(string); !ok {
		params["ps"] = ""
	}

	rule := make(map[string]interface{})
	rule["open"] = params["open"]
	rule["auth_type"] = params["auth_type"]
	rule["ps"] = params["ps"]

	merged_rule, s, rule_log, err := m.mergeRules(params["rules"])

	if s == false && err != nil {
		return core.Fail(err)
	}
	sort_ := m.calcRulesSort(params["rules"])
	if c, ok := params["allsites"]; ok {
		if c, ok := c.(float64); ok && c == 1 {
			merged_rule = append(merged_rule.([]interface{}), map[string]interface{}{
				"sites": map[string]int{
					"allsite": 1,
				},
			})
		}
	}
	if len(merged_rule.([]interface{})) == 0 {
		return core.Fail("规则不能为空")
	}

	manData := types.ManData{
		Open:      params["open"].(float64),
		Sort_:     sort_.(int),
		Timestamp: timestamp,
		AuthType:  params["auth_type"].(string),
		PS:        params["ps"].(string),
		Rules:     merged_rule.([]interface{}),
		Count:     0,
		RuleLog:   rule_log,
		Key:       public.RandomStr(20),
	}
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		buf, err := m.unescapeOne(manData)
		if err != nil {
			return core.Fail("JSON编码失败")
		}

		_, err = public.WriteFile(m.manm_path, "["+buf.String()+"]")
		if err != nil {
			return core.Fail("写入人机验证配置失败2")
		}

		return core.Success("添加成功")
	}
	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	if m.backupManm(file_data) == false {
		logging.Error("备份人机验证配置失败")
	} else {
		logging.Info("备份人机验证配置成功")
	}

	file_data = append(file_data, manData)
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i].Timestamp > file_data[j].Timestamp
	})

	buf, err := m.unescape(file_data)
	if err != nil {

		return core.Fail("JSON编码失败")
	}

	_, err = public.WriteFile(m.manm_path, buf.String())
	if err != nil {
		if m.backspaceManm() == false {
			logging.Error("回退人机验证配置失败")
		} else {
			logging.Info("回退人机验证配置成功")
		}

		return core.Fail("写入人机验证配置失败")
	}

	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	rule_log = rule_log + "【" + m.type_info[public.InterfaceToString(rule["auth_type"])] + "】"
	public.WriteOptLog(fmt.Sprintf("添加人机验证规则成功: %s 备注: %s", rule_log, params["ps"].(string)), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("添加成功")
}

func (m *Manm) DelRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"key"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	keysToDelete := public.InterfaceArray_To_StringArray(params["key"].([]interface{}))
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		return core.Fail(err)
	}
	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	if m.backupManm(file_data) == false {
		logging.Error("备份人机验证配置失败")
	} else {
		logging.Info("备份人机验证配置成功")
	}
	del_rules := make([]types.ManData, 0)
	for i := len(file_data) - 1; i >= 0; i-- {
		if m.contains(keysToDelete, file_data[i].Key) {
			del_rules = append(del_rules, file_data[i])
			file_data = append(file_data[:i], file_data[i+1:]...)
		}
	}
	var rule_log string
	for _, rule := range del_rules {
		auth_type := rule.AuthType
		rules := rule.RuleLog
		rule_log += rules + "【" + m.type_info[auth_type] + "】"
	}

	buf, err := m.unescape(file_data)
	if err != nil {
		return core.Fail("JSON编码失败")
	}
	_, err = public.WriteFile(m.manm_path, buf.String())
	if err != nil {
		if m.backspaceManm() == false {
			logging.Error("回退人机验证配置失败")
		} else {
			logging.Info("回退人机验证配置成功")
		}
		return core.Fail("写入人机验证配置失败2")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("删除人机验证规则成功: %s", rule_log), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("删除成功")

}

func (m *Manm) GetList(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		json_data = string([]byte("[]"))
	}
	file_data := make([]types.RecaptchaRuleItem, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	for i, data := range file_data {
		if rules, ok := data.Rules.([]interface{}); ok {
			for _, rule := range rules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if sites, ok := ruleMap["sites"].(map[string]interface{}); ok {
						if _, ok := sites["allsite"]; ok {
							sites["server_name"] = "所有网站"
						} else {
							site_id := ""
							for k, _ := range sites {
								if k != "allsite" && k != "server_name" {
									site_id = k
									break
								}
							}
							server_name, _ := public.GetSiteNameBySiteId(site_id)
							if server_name == "" {
								server_name = site_id
							}
							sites["server_name"] = server_name
						}
					}
					if ip, ok := ruleMap["ip"].(map[string]interface{}); ok {
						if ip["type"] != "ip_group" && ip["type"] != "ip_group_r" {
							typeinfo := ""
							if info, ok := ip["type"].(string); ok {
								typeinfo = info
							} else {
								typeinfo = "ip_section"
							}
							ruleMap["ip"] = map[string]interface{}{
								"start": public.LongToIp(uint32(ip["start"].(float64))),
								"end":   public.LongToIp(uint32(ip["end"].(float64))),
								"type":  typeinfo,
							}
						}
					}
				}
			}
		}
		file_data[i] = data
	}
	if search, ok := params["keyword"].(string); ok && search != "" {
		filteredData := make([]types.RecaptchaRuleItem, 0, len(file_data))
		for _, data := range file_data {
			if m.containsKeyword(core.StructToMap(data), search) {
				filteredData = append(filteredData, data)
			}
		}
		file_data = filteredData
	}
	var p int
	var p_size int
	if c, ok := params["p"]; ok {
		if v, ok := c.(float64); ok {
			p = int(v)
		} else {
			return core.Fail("p parameter error")
		}
	}
	if c, ok := params["p_size"]; ok {
		if v, ok := c.(float64); ok {
			p_size = int(v)
		} else {
			return core.Fail("p_size parameter error")
		}
	}
	data2 := public.PaginateData(file_data, p, p_size)
	return core.Success(data2)

}

func (m *Manm) OffAuthtype(request *http.Request) core.Response {
	var log string
	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["key"].(string); !ok {
		return core.Fail("key parameter error")
	}
	key := params["key"].(string)
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		return core.Fail(err)
	}

	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	var rule_log string

	var open float64
	var auth_type string
	if v, ok := params["open"]; ok {
		if c, ok := v.(float64); ok {
			open = c

		}
	}
	if v, ok := params["auth_type"]; ok {
		if c, ok := v.(string); ok {
			auth_type = c

		}
	}
	for i := range file_data {
		if file_data[i].Key == key {
			rule_log = file_data[i].RuleLog
			if file_data[i].Open != open {
				if open == 0 {
					log = "禁用规则"
				} else {
					log = "启用规则"
				}
				file_data[i].Open = open
			}
			if file_data[i].AuthType != auth_type {
				file_data[i].AuthType = auth_type
				log = "修改验证方式为 " + m.type_info[auth_type]
			}
			file_data[i].Timestamp = timestamp
			break
		}
	}

	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	_, err = public.WriteFile(m.manm_path, string(rules_js))
	if err != nil {
		return core.Fail("写入人机验证配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s  %s 成功", log, rule_log), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("修改成功")

}

func (m *Manm) ClearCount(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["key"].(string); !ok {
		return core.Fail("key parameter error")
	}
	key := params["key"].(string)
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		return core.Fail(err)
	}

	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	var rule_log string
	for i := range file_data {
		if file_data[i].Key == key {
			rule_log = file_data[i].RuleLog
			file_data[i].Count = 0
			break
		}
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	_, err = public.WriteFile(m.manm_path, string(rules_js))
	if err != nil {

		return core.Fail("写入人机验证配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("清空人机验证命中次数成功: %s", rule_log), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("清空成功")

}

func (m *Manm) UpdateRules(request *http.Request) core.Response {
	timestamp := time.Now().Unix()
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["key"].(string); !ok {
		return core.Fail("key parameter error")
	}
	key := params["key"].(string)
	json_data, err := public.ReadFile(m.manm_path)
	if err != nil {
		return core.Fail(err)
	}
	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return core.Fail(err)
	}
	if m.backupManm(file_data) == false {
		logging.Error("备份人机验证配置失败")
	} else {
		logging.Info("备份人机验证配置成功")
	}

	del_rules := make([]types.ManData, 0)
	for i := len(file_data) - 1; i >= 0; i-- {
		if file_data[i].Key == key {
			del_rules = append(del_rules, file_data[i])
			file_data = append(file_data[:i], file_data[i+1:]...)
			break
		}
	}
	var rule_log_del string
	for _, rule := range del_rules {
		auth_type := rule.AuthType
		rules := rule.RuleLog
		rule_log_del += rules + "【" + m.type_info[auth_type] + "】"
	}
	if _, ok := params["open"].(float64); !ok {
		return core.Fail("open parameter error")
	}
	if _, ok := params["auth_type"].(string); !ok {
		return core.Fail("auth_type parameter error")
	}
	if _, ok := params["rules"]; !ok {
		return core.Fail("rules parameter error")
	}
	if _, ok := params["ps"].(string); !ok {
		params["ps"] = ""
	}
	rule := make(map[string]interface{})
	rule["open"] = params["open"]
	rule["auth_type"] = params["auth_type"]
	rule["ps"] = params["ps"]

	merged_rule, s, rule_log, err := m.mergeRules(params["rules"])
	if s == false && err != nil {
		return core.Fail(err)
	}
	sort_ := m.calcRulesSort(params["rules"])
	if c, ok := params["allsites"]; ok {
		if c, ok := c.(float64); ok && c == 1 {
			merged_rule = append(merged_rule.([]interface{}), map[string]interface{}{
				"sites": map[string]int{
					"allsite": 1,
				},
			})
		}
	}
	if len(merged_rule.([]interface{})) == 0 {
		return core.Fail("规则不能为空")
	}

	manData := types.ManData{
		Open:      params["open"].(float64),
		Sort_:     sort_.(int),
		Timestamp: timestamp,
		AuthType:  params["auth_type"].(string),
		PS:        params["ps"].(string),
		Rules:     merged_rule.([]interface{}),
		RuleLog:   rule_log,
		Key:       public.RandomStr(20),
	}
	file_data = append(file_data, manData)
	sort.Slice(file_data, func(i, j int) bool {
		return file_data[i].Timestamp > file_data[j].Timestamp
	})

	buf, err := m.unescape(file_data)
	if err != nil {

		return core.Fail("JSON编码失败")
	}
	_, err = public.WriteFile(m.manm_path, buf.String())
	if err != nil {
		if m.backspaceManm() == false {
			logging.Error("回退人机验证配置失败")
		} else {
			logging.Info("回退人机验证配置成功")
		}
		return core.Fail("写入人机验证配置失败2")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	rule_log = rule_log + "【" + m.type_info[public.InterfaceToString(rule["auth_type"])] + "】"
	public.WriteOptLog(fmt.Sprintf("编辑人机验证规则成功: %s 修改为 %s", rule_log_del, rule_log), public.OPT_LOG_TYPE_MAN_MACHINE, public.GetUid(request))
	return core.Success("修改成功")
}

func (m *Manm) mergeRules(rules interface{}) (interface{}, bool, string, error) {
	sites := make(map[string]interface{})
	urldata := make([]interface{}, 0)
	ip := make([]interface{}, 0)
	ipv6 := make([]interface{}, 0)
	city := make(map[string]interface{})
	success := true
	errStr := ""
	log_sites := ""
	rule_log := ""
	rule_log += "【全部网站】"
	for _, rule := range rules.([]interface{}) {
		if v, ok := rule.(map[string]interface{}); ok {
			switch v["t"].(string) {

			case "sites":
				sites[v["value"].(string)] = 1
				log_sites = v["value"].(string)
				rule_log += fmt.Sprintf("【网站: %s】", v["value"])

			case "url":
				if v["value"] == "" {
					success = false
					errStr += fmt.Sprintf("url为空: %s\n", v["value"])
				}

				if v["value"] == "/" {
					success = false
					errStr += fmt.Sprintf("url不能添加: / ")
				}
				url := html.UnescapeString(public.InterfaceToString(v["value"]))
				url = public.EscapeSymbols(url, []string{"?", "&"})
				if v["match"] == "param" {
					urldata = append(urldata, map[string]interface{}{
						"url":   url,
						"type":  v["match"],
						"param": v["sub_v"],
					})
					rule_log += fmt.Sprintf("【url[%s]-参数匹配-[%s]】", url, v["sub_v"])
				} else {
					urldata = append(urldata, map[string]interface{}{
						"url":  url,
						"type": v["match"],
					})
					match_type := map[string]string{
						"keyword": "关键词匹配",
						"prefix":  "前缀匹配",
						"suffix":  "后缀匹配",
						"=":       "完全匹配",
						"match":   "正则匹配",
					}
					rule_log += fmt.Sprintf("【url-%s-[%s]】", match_type[v["match"].(string)], url)
				}
			case "city":
				if v["value"] != "中国" && v["value"] != "海外" && v["value"] != "香港" && v["value"] != "台湾" && v["value"] != "澳门" {
					success = false
					errStr += fmt.Sprintf("地区格式错误: %s\n", v["value"])
				}
				city[v["value"].(string)] = 1
				rule_log += fmt.Sprintf("【地区-完全匹配-[%s]】", v["value"])

			case "ipv6":
				parts := strings.Split(v["value"].(string), "/")
				if len(parts) > 1 && public.IsIpv6(parts[0]) {
					l, ok := strconv.Atoi(parts[1])
					if ok != nil {
						success = false
						errStr += fmt.Sprintf("IPV6格式错误: %s\n ", v["value"])
					}
					if l < 5 || l > 128 {
						success = false
						errStr += fmt.Sprintf("子网掩码范围不正确: %s\n ", v["value"])
					}
				} else {
					if !public.IsIpv6(parts[0]) {
						success = false
						errStr += fmt.Sprintf("IPV6格式错误: %s\n ", v["value"])
					}
				}

				ipv6 = append(ip, map[string]interface{}{
					"ipv6": map[string]interface{}{
						"data": v["value"].(string),
					},
				})
			case "ip":
				flags := ""
				if v["match"] == "ip_group" || v["match"] == "ip_group_r" {
					ip = append(ip, map[string]interface{}{
						"ip": map[string]interface{}{
							"type":     v["match"],
							"ip_group": v["value"].(string),
						},
					})
					if v["match"] == "ip_group_r" {
						flags = "不"
					}
					rule_log += fmt.Sprintf("【源ip- %s匹配ip组-[%s]】", flags, v["value"])
				}

				if v["match"] == "ip" || v["match"] == "ip_r" {
					if !public.IsIpv4(v["value"].(string)) || !public.IsIpv4(v["sub_v"].(string)) {
						success = false
						errStr += fmt.Sprintf("IP格式错误: %s\n", v["value"])
					}
					if public.IpToLong(v["value"].(string)) > public.IpToLong(v["sub_v"].(string)) {
						success = false
						errStr += fmt.Sprintf("IP范围错误:起始IP %s > 结束IP %s \n", v["value"], v["sub_v"])
					}

					ip = append(ip, map[string]interface{}{
						"ip": map[string]interface{}{
							"type":  v["match"],
							"start": public.IpToLong(v["value"].(string)),
							"end":   public.IpToLong(v["sub_v"].(string)),
						},
					})
					if v["match"] == "ip_r" {
						flags = "不"
					}
					rule_log += fmt.Sprintf("【源ip- %s匹配ip-[%s-%s]】", flags, v["value"], v["sub_v"])
				}
				if v["match"] == "ip_section" || v["match"] == "ip_section_r" {
					if !public.IsIpv4(v["value"].(string)) || !public.IsIpv4(v["sub_v"].(string)) {
						success = false
						errStr += fmt.Sprintf("IP格式错误: %s\n", v["value"])
					}
					if public.IpToLong(v["value"].(string)) > public.IpToLong(v["sub_v"].(string)) {
						success = false
						errStr += fmt.Sprintf("IP范围错误:起始IP %s > 结束IP %s \n", v["value"], v["sub_v"])
					}

					ip = append(ip, map[string]interface{}{
						"ip": map[string]interface{}{
							"type":  "ip_section",
							"start": public.IpToLong(v["value"].(string)),
							"end":   public.IpToLong(v["sub_v"].(string)),
						},
					})
					if v["match"] == "ip_section_r" {
						flags = "不"
					}
					rule_log += fmt.Sprintf("【源ip-%s匹配ip区间-[%s-%s]】", flags, v["value"], v["sub_v"])

				}

			}
		}
	}
	res := make([]interface{}, 0)
	if len(sites) > 0 {
		res = append(res, map[string]interface{}{
			"sites": sites,
		})
	}
	if len(city) > 0 {
		res = append(res, map[string]interface{}{
			"city": city,
		})
	}
	res = append(res, ip...)
	res = append(res, ipv6...)
	res = append(res, urldata...)
	var err error
	if errStr != "" {
		err = fmt.Errorf("错误信息:\n%s", errStr)
	}
	if log_sites == "" {
		log_sites = "全部网站"
	} else {
		rule_log = rule_log[18:]
	}
	return res, success, rule_log, err
}

func (m *Manm) calcRulesSort(rules interface{}) interface{} {
	sort_ := 0

	for _, rule := range rules.([]interface{}) {
		if v, ok := rule.(map[string]interface{}); ok {
			switch v["t"].(string) {

			case "sites":
				sort_ += 1

			case "url":
				if v["match"] == "param" {
					sort_ += 3
				} else {
					sort_ += 2
				}

			case "city":
				sort_ += 4

			case "ip":
				sort_ += 5

			case "ipv6":
				sort_ += 5
			}
		}
	}
	return sort_
}

func (m *Manm) containsKeyword(data map[string]interface{}, keyword string) bool {
	for _, value := range data {
		switch v := value.(type) {
		case string:
			if strings.Contains(v, keyword) {
				return true
			}
		case []interface{}:
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if m.containsKeyword(itemMap, keyword) {
						return true
					}
				}
			}
		case map[string]interface{}:
			if m.containsKeyword(v, keyword) {
				return true
			}
		}
	}
	return false
}

func (m *Manm) unescape(data []types.ManData) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(data)
	return buf, err
}

func (m *Manm) unescapeOne(data types.ManData) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(data)
	return buf, err
}

func (m *Manm) backspaceManm() bool {

	json_data, err := public.ReadFile(m.manm_path_backup)
	if err != nil {
		logging.Error("读备份文件失败：", err)
		return false
	}
	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return false
	}

	buf, err := m.unescape(file_data)
	if err != nil {
		return false
	}
	_, err = public.WriteFile(m.manm_path, buf.String())
	if err != nil {
		logging.Error("回退人机验证配置失败", err)
		return false
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return true
}

func (m *Manm) backupManm(data []types.ManData) bool {
	buf, err := m.unescape(data)
	if err != nil {
		return false
	}
	_, err = public.WriteFile(m.manm_path_backup, buf.String())
	if err != nil {
		return false
	}

	return true
}

func (m *Manm) isJSON(data []byte) bool {
	var jsonData interface{}
	err := json.Unmarshal(data, &jsonData)
	return err == nil

}

func (m *Manm) contains(slice []string, element string) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}
	return false
}
