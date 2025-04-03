package modules

import (
	"CloudWaf/core"
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
	core.RegisterModule(&Limit{
		ipWhite:  "/www/cloud_waf/nginx/conf.d/waf/rule/ip_white.json",
		ipBlack:  "/www/cloud_waf/nginx/conf.d/waf/rule/ip_black.json",
		uaWhite:  "/www/cloud_waf/nginx/conf.d/waf/rule/ua_white.json",
		uaBlack:  "/www/cloud_waf/nginx/conf.d/waf/rule/ua_black.json",
		urlWhite: "/www/cloud_waf/nginx/conf.d/waf/rule/url_white.json",
		urlBlack: "/www/cloud_waf/nginx/conf.d/waf/rule/url_black.json",
		log_type: map[string]int{
			"0": public.OPT_LOG_TYPE_IP_WHITE,
			"1": public.OPT_LOG_TYPE_IP_BLACK,
			"2": public.OPT_LOG_TYPE_UA_WHITE,
			"3": public.OPT_LOG_TYPE_UA_BLACK,
			"4": public.OPT_LOG_TYPE_URL_WHITE,
			"5": public.OPT_LOG_TYPE_URL_BLACK,
		},
	})

}

type Limit struct {
	ipWhite  string
	ipBlack  string
	uaWhite  string
	uaBlack  string
	urlWhite string
	urlBlack string
	log_type map[string]int
}

func (limit *Limit) f(ip1, ip2 string) string {
	if ip2 == "" {
		return ip1
	}
	if ip1 == ip2 {
		return ip1
	}
	return ip1 + "-" + ip2
}

func (limit *Limit) SetIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少types参数")
	}
	if _, ok := params["ip_type"]; !ok {
		return core.Fail("缺少ip_type参数")
	}
	uid := public.GetUid(request)
	startIP := params["start"]
	endIP := params["end"]
	createTime := time.Now().Unix()
	open := 1
	var log_flag string

	if _, ok := params["start"]; !ok {
		return core.Fail("起始IP不能为空")
	}
	notes := ""
	if _, ok := params["notes"]; ok {
		notes = public.InterfaceToString(params["notes"])
	}
	endLog := params["end"]
	ipType := "v4"
	if public.InterfaceToInt(params["ip_type"]) == 0 {
		if !public.IsIpv4(startIP.(string)) {
			return core.Fail("IP格式不正确")
		}
		startIP = public.IpToLong(startIP.(string))
		if _, ok := params["end"]; ok && endIP.(string) != "" {
			if !public.IsIpv4(endIP.(string)) {
				return core.Fail("IP格式不合法")
			}
			if public.IpToLong(params["start"].(string)) > public.IpToLong(params["end"].(string)) {
				return core.Fail("起始IP不能大于结束IP")
			}
			endIP = public.IpToLong(endIP.(string))
		} else {
			endIP = startIP
			endLog = params["start"].(string)
		}
	}
	if public.InterfaceToInt(params["ip_type"]) == 1 {
		parts := strings.Split(public.InterfaceToString(startIP.(string)), "/")
		if len(parts) > 1 && public.IsIpv6(parts[0]) {
			l, ok := strconv.Atoi(parts[1])
			if ok != nil {
				return core.Fail(ok)
			}
			if l < 5 || l > 128 {
				return core.Fail("IP格式不合法")
			}
		} else {
			if !public.IsIpv6(parts[0]) {
				return core.Fail("IP格式不正确")
			}
		}
		startIP = params["start"].(string)
		endIP = ""
		endLog = ""
		ipType = "v6"
	}
	if public.InterfaceToInt(params["ip_type"]) == 2 {
		startIP = params["start"].(string)
		endIP = ""
		endLog = ""
		ipType = "ip_group"
	}
	path := ""
	name := ""
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"

	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}

	for _, values := range fileData {
		if public.InterfaceToInt(params["ip_type"]) == 0 && public.InterfaceToString(values[6]) == "v4" {
			if uint32(values[0].(float64)) == startIP && uint32(values[1].(float64)) == endIP {
				return core.Fail("IP已添加")
			}
		}
		if public.InterfaceToInt(params["ip_type"]) == 1 && public.InterfaceToString(values[6]) == "v6" {
			if strings.Contains(values[0].(string), startIP.(string)) {
				return core.Fail("IP已添加")
			}
		}
		if public.InterfaceToInt(params["ip_type"]) == 2 && public.InterfaceToString(values[6]) == "ip_group" {
			if strings.Contains(values[0].(string), startIP.(string)) {
				return core.Fail("IP组已添加")
			}
		}

	}

	ipIndex := public.RandomStr(20)
	count := 0
	ranges := make([]interface{}, 0)
	ranges = append(ranges, startIP, endIP, notes, createTime, open, count, ipType, ipIndex)
	fileData = append(fileData, ranges)
	sort.Slice(fileData, func(i, j int) bool {
		return public.InterfaceToInt(fileData[i][3]) > public.InterfaceToInt(fileData[j][3])
	})
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}

	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	ipLog := limit.f(params["start"].(string), endLog.(string))
	public.WriteOptLog(fmt.Sprintf("%s设置【%s】成功", name, ipLog), limit.log_type[log_flag], uid)
	return core.Success(name + "设置成功")
}

func (limit *Limit) SetUa(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少types参数")
	}
	notes := ""
	if _, ok := params["notes"]; ok {
		notes = public.InterfaceToString(params["notes"])
	}
	uid := public.GetUid(request)
	if _, ok := params["data"]; !ok {
		return core.Fail("缺少data参数")
	}
	path := ""
	name := ""
	ua := params["data"].(string)
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
	case 1:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	for _, values := range fileData {
		if values.Ua == ua {
			return core.Fail("UA已存在")
		}
	}
	uaIndex := public.RandomStr(20)
	fileData = append(fileData, types.UARule{
		Ua:    ua,
		Open:  1,
		Time:  time.Now().Unix(),
		Notes: notes,
		Count: 0,
		Index: uaIndex,
	})
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)

	public.WriteOptLog(fmt.Sprintf("%s设置【匹配关键字-[%s]】成功", name, ua), limit.log_type[log_flag], uid)
	return core.Success(name + "设置成功")
}

func (limit *Limit) SetUrl(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少types参数")
	}
	uid := public.GetUid(request)
	if _, ok := params["url"]; !ok {
		return core.Fail("缺少url参数")
	}
	if params["url"].(string) == "/" {
		return core.Fail("根目录不能添加")
	}
	if _, ok := params["type"]; !ok {
		return core.Fail("缺少type参数")
	}
	notes := ""
	if _, ok := params["notes"]; ok {
		notes = public.InterfaceToString(params["notes"])
	}
	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
	case 1:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		return core.Fail("参数不合法!")
	}
	url := public.InterfaceToString(params["url"])
	match := public.InterfaceToString(params["type"])
	param := public.InterfaceToString(params["param"])
	urlIndex := public.RandomStr(20)
	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	for _, values := range fileData {
		if values.URL == url && values.Type == match {
			return core.Fail("URI已存在")
		}
		if values.URL == url && values.Type == match && values.Param == param {
			return core.Fail("URI已存在")
		}
	}
	check := []string{
		"?",
		"&",
	}
	if match != "=" {
		url = public.EscapeSymbols(url, check)
	}
	if match == "param" {
		fileData = append(fileData, types.URLRule{
			URL:   html.UnescapeString(url),
			Type:  match,
			Param: param,
			Open:  1,
			Time:  time.Now().Unix(),
			Notes: notes,
			Count: 0,
			Index: urlIndex,
		})

	} else {
		fileData = append(fileData, types.URLRule{
			URL:   html.UnescapeString(url),
			Type:  match,
			Open:  1,
			Time:  time.Now().Unix(),
			Notes: notes,
			Count: 0,
			Index: urlIndex,
		})
	}
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(fileData)
	if err != nil {
		public.WriteFile(path, "[]")
		return core.Fail("JSON编码失败")
	}
	_, err = public.WriteFile(path, buf.String())
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	matchType := map[string]string{
		"=":       "完全相等",
		"param":   "匹配参数",
		"keyword": "关键字",
		"prefix":  "匹配开头",
		"suffix":  "匹配结尾",
		"match":   "正则匹配",
	}
	public.WriteOptLog(fmt.Sprintf("%s设置【%s-[%s]】成功", name, matchType[match], url), limit.log_type[log_flag], uid)
	return core.Success(name + "设置成功")
}

func (limit *Limit) SetInto(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["data"]; !ok {
		return core.Fail("缺少参数data")
	}
	uid := public.GetUid(request)
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		name = "IP白名单"
		log_flag = "0"
		limit.handleIPList(params["data"], limit.ipWhite)
	case 1:
		name = "IP黑名单"
		log_flag = "1"
		limit.handleIPList(params["data"], limit.ipBlack)
	case 2:
		name = "UA白名单"
		log_flag = "2"
		limit.handleUAList(params["data"], limit.uaWhite)
	case 3:
		name = "UA黑名单"
		log_flag = "3"
		limit.handleUAList(params["data"], limit.uaBlack)
	case 4:
		name = "URI白名单"
		log_flag = "4"
		limit.handleURList(params["data"], limit.urlWhite)
	case 5:
		name = "URI黑名单"
		log_flag = "5"
		limit.handleURList(params["data"], limit.urlBlack)

	default:
		return core.Fail("参数不合法!")
	}

	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	if _, ok := params["action"]; ok {
		if public.InterfaceToInt(params["action"]) == 1 {
			public.WriteOptLog(fmt.Sprintf("批量拉黑成功"), limit.log_type[log_flag], uid)
			return core.Success("批量拉黑成功")
		}
	}
	public.WriteOptLog(fmt.Sprintf("导入%s成功", name), limit.log_type[log_flag], uid)
	return core.Success("导入设置成功")
}

func (limit *Limit) handleIPList(content interface{}, path string) core.Response {
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	string_array := make([]interface{}, 0)
	for _, v := range fileData {
		string_array = append(string_array, v...)
	}
	createTime := time.Now().Unix()
	open := 1
	count := 0
	for _, v := range content.([]interface{}) {
		v = strings.TrimSpace(public.InterfaceToString(v))
		if len(public.InterfaceToString(v)) > 0 {
			parts := strings.Split(public.InterfaceToString(v), "/")
			if len(parts) > 1 && public.IsIpv6(parts[0]) {
				l, ok := strconv.Atoi(parts[1])
				if ok != nil {
					return core.Fail(ok)
				}
				if l < 5 || l > 128 {
					return core.Fail("IP格式不合法")
				}
			}

			if !public.IsIpAddr(public.InterfaceToString(v)) && !public.IsIpNetwork(public.InterfaceToString(v)) && !public.IsIpRange(public.InterfaceToString(v)) && !public.IsIpv6(parts[0]) {
				return core.Fail("IP格式不正确")
			}
			if !public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(v)) {
				ipIndex := public.RandomStr(20)
				if public.IsIpv6(public.InterfaceToString(v)) {
					data := make([]interface{}, 0)
					data = append(data, public.InterfaceToString(v), "", "", createTime, open, count, "v6", ipIndex)
					fileData = append(fileData, data)
				}
				if len(parts) > 1 && public.IsIpv6(parts[0]) {
					data := make([]interface{}, 0)
					data = append(data, parts[0]+"/"+parts[1], "", "", createTime, open, count, "v6", ipIndex)
					fileData = append(fileData, data)
				}
				if public.IsIpv4(public.InterfaceToString(v)) {
					data, err := limit.address(public.InterfaceToString(v), public.InterfaceToString(v), "", createTime, open, count, "v4", ipIndex)
					if err != nil {
						return core.Fail(err)
					}

					if !public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(data[0])) {
						fileData = append(fileData, data)
					}
				}
				if public.IsIpNetwork(public.InterfaceToString(v)) {
					ipNet := strings.Split(public.InterfaceToString(v), "/")

					l, err := strconv.Atoi(ipNet[1])

					if err != nil {
						return core.Fail(err)
					}
					ipaddr := ipNet[0]
					ipStart := public.IpToLong(ipNet[0])
					ipEnd := ipStart | ((1 << (33 - l)) - 1)
					ipEnds := public.LongToIp(ipEnd)
					data, err := limit.address(ipaddr, ipEnds, "", createTime, open, count, "v4", ipIndex)
					if err != nil {
						return core.Fail(err)
					}
					if !public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(data[0])) &&
						!public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(data[1])) {
						fileData = append(fileData, data)
					}
				}
				if public.IsIpRange(public.InterfaceToString(v)) {
					ipRange := strings.Split(public.InterfaceToString(v), "-")
					startIP := ipRange[0]
					endIP := ipRange[1]
					data, err := limit.address(startIP, endIP, "", createTime, open, count, "v4", ipIndex)
					if err != nil {
						return core.Fail(err)
					}
					if !public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(data[0])) &&
						!public.Is_Array_ByString(public.InterfaceArray_To_StringArray(string_array), public.InterfaceToString(data[1])) {
						fileData = append(fileData, data)
					}
				}
			}
		}
	}
	sort.Slice(fileData, func(i, j int) bool {
		return public.InterfaceToInt(fileData[i][3]) > public.InterfaceToInt(fileData[j][3])
	})
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "["+string_array[0].(string)+"]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail(err)
	}
	return nil
}

func (limit *Limit) handleUAList(content interface{}, path string) core.Response {
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	checkList := content.([]interface{})
	for _, ua := range checkList {
		flags := true
		ua = strings.TrimSpace(ua.(string))
		if len(ua.(string)) > 0 {
			for _, values := range fileData {
				if values.Ua == ua {
					flags = false
					break
				}
			}
			if flags == false {
				continue
			}
			uaIndex := public.RandomStr(20)
			fileData = append(fileData, types.UARule{
				Ua:    ua.(string),
				Open:  1,
				Time:  time.Now().Unix(),
				Notes: "",
				Count: 0,
				Index: uaIndex,
			})
		}
	}
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail(err)
	}
	return nil
}

func (limit *Limit) handleURList(content interface{}, path string) core.Response {
	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	record := limit.urlData(content.([]interface{}))
	for _, temp := range record {
		flags := true
		url := temp.URL
		match := temp.Type
		param := temp.Param
		if url == "/" {
			return core.Fail("根目录不能添加")
		}
		for _, values := range fileData {
			if values.URL == url && values.Type == match {
				flags = false
				break
			}
			if values.URL == url && values.Type == match && values.Param == param {
				flags = false
				break
			}
		}
		if flags == false {
			continue
		}
		urlIndex := public.RandomStr(20)
		check := []string{
			"?",
			"&",
		}
		if match != "=" {
			url = public.EscapeSymbols(url, check)
		}
		if match == "param" {
			fileData = append(fileData, types.URLRule{
				URL:   html.UnescapeString(url),
				Type:  match,
				Param: param,
				Open:  1,
				Time:  time.Now().Unix(),
				Notes: "",
				Count: 0,
				Index: urlIndex,
			})

		} else {
			fileData = append(fileData, types.URLRule{
				URL:   html.UnescapeString(url),
				Type:  match,
				Open:  1,
				Time:  time.Now().Unix(),
				Notes: "",
				Count: 0,
				Index: urlIndex,
			})
		}
	}
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(fileData)
	if err != nil {
		public.WriteFile(path, "[]")
		return core.Fail("JSON编码失败")
	}
	_, err = public.WriteFile(path, buf.String())
	if err != nil {
		return core.Fail(err)
	}
	return nil
}

func (limit *Limit) urlData(content []interface{}) []types.URLRule {
	var result []types.URLRule
	for _, rule := range content {
		parts := strings.Split(public.InterfaceToString(rule), "||")
		url := parts[0]
		match := parts[1]
		r := types.URLRule{
			URL:  url,
			Type: match,
		}
		if len(parts) > 2 {
			r.Param = parts[2]
		}
		result = append(result, r)
	}
	return result
}

func (limit *Limit) SetOut(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["type"]; !ok {
		return core.Fail("缺少参数type")
	}
	uid := public.GetUid(request)
	name := ""
	var log_flag string
	defer func() {
		public.WriteOptLog(fmt.Sprintf("导出%s成功", name), limit.log_type[log_flag], uid)
	}()
	switch public.InterfaceToInt(params["type"]) {
	case 0:
		name = "IP白名单"
		log_flag = "0"
		return limit.ipList(limit.ipWhite, "ip_white")
	case 1:
		name = "IP黑名单"
		log_flag = "1"
		return limit.ipList(limit.ipBlack, "ip_black")
	case 2:
		name = "UA白名单"
		log_flag = "2"
		return limit.uaList(limit.uaWhite, "ua_white")
	case 3:
		name = "UA黑名单"
		log_flag = "3"
		return limit.uaList(limit.uaBlack, "ua_black")
	case 4:
		name = "URI白名单"
		log_flag = "4"
		return limit.urList(limit.urlWhite, "url_white")
	case 5:
		name = "URI黑名单"
		log_flag = "5"
		return limit.urList(limit.urlBlack, "url_black")
	default:
		return core.Fail("参数不合法!")
	}
}

func (limit *Limit) address(startIP string, endIP string, notes string, times int64, open int, count int, types string, index string) ([]interface{}, error) {
	return []interface{}{
		public.IpToLong(startIP),
		public.IpToLong(endIP),
		notes,
		times,
		open,
		count,
		types,
		index,
	}, nil
}

func (limit *Limit) rFile(path string) (map[string][]types.Group, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("{}"))
	}
	fileData := make(map[string][]types.Group, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (limit *Limit) ipList(path, filename string) core.Response {
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	if len(fileData) == 0 {
		return core.Fail("暂无数据导出")
	}
	var lines []string
	s := ""
	for _, values := range fileData {
		if values[6].(string) == "v6" {
			s = values[0].(string)
			lines = append(lines, s)
			continue
		}
		switch values[0].(type) {
		case string:
			ipGroupName := values[0].(string)
			ipData := "/www/cloud_waf/nginx/conf.d/waf/rule/ip_group.json"
			fileData, err := limit.rFile(ipData)
			if err != nil {
				return core.Fail("读取文件失败!")
			}
			_, ok := fileData[ipGroupName]
			if ok {
				lines = append(lines, "\n#ip_group:"+ipGroupName)
			}
			for key, item := range fileData {
				if key == ipGroupName {
					for _, v := range item {
						lines = append(lines, v.IP)
					}

				}
			}
		case float64:
			ipOne := uint32(public.InterfaceToFloat64(values[0]))
			ipTwo := uint32(public.InterfaceToFloat64(values[1]))
			if ipOne == ipTwo {
				s = public.LongToIp(ipOne)
			} else {
				s = public.LongToIp(ipOne)
				s += "-" + public.LongToIp(ipTwo)
			}
			lines = append(lines, s)
		}
	}
	result := strings.Join(lines, "\n")
	response := core.Download(filename, []byte(result))
	if err != nil {
		return core.Fail(err)
	}
	return response
}

func (limit *Limit) uaList(path, filename string) core.Response {
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	if len(fileData) == 0 {
		return core.Fail("暂无数据导出")
	}
	result := make([]string, len(fileData))
	for i, item := range fileData {
		result[i] = fmt.Sprintf("%s", item.Ua)
	}
	resultStr := strings.Join(result, "\n")
	response := core.Download(filename, []byte(resultStr))
	if err != nil {
		return core.Fail(err)
	}
	return response
}

func (limit *Limit) urList(path, filename string) core.Response {
	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail(err)
	}
	if len(fileData) == 0 {
		return core.Fail("暂无数据导出")
	}
	result := make([]string, len(fileData))
	for i, item := range fileData {
		if item.Param == "" {
			result[i] = fmt.Sprintf("%s||%s", item.URL, item.Type)
		} else {
			result[i] = fmt.Sprintf("%s||%s||%s", item.URL, item.Type, item.Param)
		}
	}
	resultStr := strings.Join(result, "\n")
	response := core.Download(filename, []byte(resultStr))
	return response
}

func (limit *Limit) ClearData(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["type"]; !ok {
		return core.Fail("缺少参数type")
	}
	uid := public.GetUid(request)
	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["type"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"
	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
	case 2:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
	case 3:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
	case 4:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
	case 5:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		return core.Fail("参数不合法!")
	}
	_, err = public.WriteFile(path, "[]")
	if err != nil {
		return core.Fail(err)
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("清空%s成功", name), limit.log_type[log_flag], uid)
	return core.Success("清空成功")
}

func (limit *Limit) DelData(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数type")
	}
	if _, ok := params["index"].([]interface{}); !ok {
		return core.Fail("index parameter error")
	}
	index := public.InterfaceArray_To_StringArray(params["index"].([]interface{}))
	uid := public.GetUid(request)
	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"
		fileData, err := limit.rIPFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		del_rules := make([][]interface{}, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i][7].(string)) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		start := ""
		end := ""
		for _, rule := range del_rules {
			if rule[6].(string) == "v6" {
				start = rule[0].(string)
				end = ""
			}
			if rule[6].(string) == "v4" {
				start = public.LongToIp(uint32(rule[0].(float64)))
				end = public.LongToIp(uint32(rule[1].(float64)))
			}

			delContent := limit.f(start, end)
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")

		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入IP白名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)

	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
		fileData, err := limit.rIPFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		del_rules := make([][]interface{}, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i][7].(string)) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		start := ""
		end := ""
		for _, rule := range del_rules {
			if rule[6].(string) == "v6" {
				start = rule[0].(string)
				end = ""
			}
			if rule[6].(string) == "v4" {
				start = public.LongToIp(uint32(rule[0].(float64)))
				end = public.LongToIp(uint32(rule[1].(float64)))
			}
			delContent := limit.f(start, end)
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")
		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入IP黑名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)

	case 2:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
		fileData, err := limit.rUAFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		del_rules := make([]types.UARule, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i].Index) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		for _, rule := range del_rules {
			delContent := rule.Ua
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")

		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入UA白名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)

	case 3:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
		fileData, err := limit.rUAFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		del_rules := make([]types.UARule, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i].Index) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		for _, rule := range del_rules {
			delContent := rule.Ua
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")
		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入UA黑名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)
	case 4:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
		fileData, err := limit.rURLFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		matchType := map[string]string{
			"=":       "完全相等",
			"param":   "匹配参数",
			"keyword": "关键字",
			"prefix":  "匹配开头",
			"suffix":  "匹配结尾",
			"match":   "正则匹配",
		}
		del_rules := make([]types.URLRule, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i].Index) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		for _, rule := range del_rules {
			delContent := rule.URL
			match := rule.Type
			if len(del_rules) > 1 {
				rule_log_del += matchType[match] + "-[" + delContent + "],"
			} else {
				rule_log_del += matchType[match] + "-[" + delContent + "]"
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")

		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail(err)
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入URL白名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)

	case 5:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
		fileData, err := limit.rURLFile(path)
		if err != nil {
			return core.Fail("读取文件失败!")
		}
		matchType := map[string]string{
			"=":       "完全相等",
			"param":   "匹配参数",
			"keyword": "关键字",
			"prefix":  "匹配开头",
			"suffix":  "匹配结尾",
			"match":   "正则匹配",
		}
		del_rules := make([]types.URLRule, 0)
		for i := len(fileData) - 1; i >= 0; i-- {
			if public.Is_Array_ByString(index, fileData[i].Index) {
				del_rules = append(del_rules, fileData[i])
				fileData = append(fileData[:i], fileData[i+1:]...)
			}
		}
		var rule_log_del string
		for _, rule := range del_rules {
			delContent := rule.URL
			match := rule.Type
			if len(del_rules) > 1 {
				rule_log_del += matchType[match] + "-[" + delContent + "],"
			} else {
				rule_log_del += matchType[match] + "-[" + delContent + "]"
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")
		rules_js, err := json.Marshal(fileData)
		if err != nil {
			return core.Fail(err)
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			return core.Fail("写入URL黑名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), limit.log_type[log_flag], uid)
	default:
		return core.Fail("参数不合法!")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	return core.Success("删除成功")
}

func (limit *Limit) EditIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := public.GetUid(request)
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}
	if _, ok := params["ip_type"]; !ok {
		return core.Fail("缺少ip_type参数")
	}
	if _, ok := params["count"]; !ok {
		return core.Fail("count")
	}
	if _, ok := params["times"]; !ok {
		return core.Fail("times")
	}
	createTime := params["times"].(float64)
	count := params["count"].(float64)
	index := params["index"].(string)
	startIP := params["start"]
	endIP := params["end"]
	if _, ok := params["start"]; !ok {
		return core.Fail("起始IP不能为空")
	}
	if public.InterfaceToInt(params["ip_type"]) == 0 {
		if !public.IsIpv4(startIP.(string)) {
			return core.Fail("IP格式不正确")
		}
		if _, ok := params["end"]; ok {
			if !public.IsIpAddr(endIP.(string)) {
				return core.Fail("IP格式不合法")
			}
			if public.IpToLong(params["start"].(string)) > public.IpToLong(params["end"].(string)) {
				return core.Fail("起始IP不能大于结束IP")
			}
		}
	}
	if public.InterfaceToInt(params["ip_type"]) == 1 {
		parts := strings.Split(public.InterfaceToString(startIP.(string)), "/")
		if len(parts) > 1 && public.IsIpv6(parts[0]) {
			l, ok := strconv.Atoi(parts[1])
			if ok != nil {
				return core.Fail(ok)
			}

			if l < 5 || l > 128 {
				return core.Fail("IP格式不合法")
			}
		} else {
			if !public.IsIpv6(parts[0]) {
				return core.Fail("IP格式不正确")
			}
		}
	}
	notes := ""
	if _, ok := params["notes"]; ok {
		notes = public.InterfaceToString(params["notes"])
	}
	open := 1
	if _, ok := params["open"]; ok {
		open = public.InterfaceToInt(params["open"])
	}
	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"
	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	del_rules := make([][]interface{}, 0)
	for i := range fileData {
		if fileData[i][7].(string) == index {
			del_rules = append(del_rules, fileData[i])
			fileData = append(fileData[:i], fileData[i+1:]...)
			break
		}
	}
	var rule_log_del string
	start := ""
	end := ""
	for _, rule := range del_rules {
		if rule[6].(string) == "v6" || rule[6].(string) == "ip_group" {
			start = rule[0].(string)
			end = ""
		}

		if rule[6].(string) == "v4" {
			start = public.LongToIp(uint32(rule[0].(float64)))
			end = public.LongToIp(uint32(rule[1].(float64)))
		}
		delContent := limit.f(start, end)
		rule_log_del += delContent
	}

	ranges := make([]interface{}, 0)
	endLog := params["end"]
	if public.InterfaceToInt(params["ip_type"]) == 0 && public.IsIpv4(startIP.(string)) {
		startIP = public.IpToLong(startIP.(string))
		if endIP != nil {
			endIP = public.IpToLong(endIP.(string))
		} else {
			endIP = startIP
			endLog = params["start"].(string)
		}
		ranges = append(ranges, startIP, endIP, notes, createTime, open, count, "v4", index)
	}
	if public.InterfaceToInt(params["ip_type"]) == 1 {
		ranges = append(ranges, params["start"].(string), "", notes, createTime, open, count, "v6", index)
		endLog = ""
	}
	if public.InterfaceToInt(params["ip_type"]) == 2 {
		ranges = append(ranges, params["start"].(string), "", notes, createTime, open, count, "ip_group", index)
		endLog = ""
	}
	fileData = append(fileData, ranges)
	sort.Slice(fileData, func(i, j int) bool {
		return public.InterfaceToInt(fileData[i][3]) > public.InterfaceToInt(fileData[j][3])
	})

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}

	ipLog := limit.f(params["start"].(string), endLog.(string))
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)

	if rule_log_del == ipLog {
		return core.Success("编辑成功")
	}
	public.WriteOptLog(fmt.Sprintf("%s【%s】修改为【%s】", name, rule_log_del, ipLog), limit.log_type[log_flag], uid)
	return core.Success("编辑成功")

}

func (limit *Limit) EditUa(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := public.GetUid(request)
	if _, ok := params["index"]; !ok {
		return core.Fail("缺少index参数")
	}
	if _, ok := params["data"]; !ok {
		return core.Fail("缺少data参数")
	}
	if _, ok := params["open"]; !ok {
		return core.Fail("缺少open参数")
	}
	if _, ok := params["notes"]; !ok {
		return core.Fail("缺少notes参数")
	}
	if _, ok := params["count"]; !ok {
		return core.Fail("缺少count参数")
	}
	if _, ok := params["times"]; !ok {
		return core.Fail("times")
	}
	createTime := params["times"].(float64)
	count := params["count"].(float64)
	index := params["index"].(string)
	path := ""
	name := ""
	ua := public.InterfaceToString(params["data"])
	open := public.InterfaceToFloat64(params["open"])
	notes := public.InterfaceToString(params["notes"])
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
	case 1:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	del_rules := make([]types.UARule, 0)
	for i := range fileData {
		if fileData[i].Index == index {
			del_rules = append(del_rules, fileData[i])
			fileData = append(fileData[:i], fileData[i+1:]...)
			break
		}
	}
	var rule_log_del string
	for _, rule := range del_rules {
		content := rule.Ua
		rule_log_del += content
	}
	for _, values := range fileData {
		if values.Ua == ua {
			return core.Fail("UA已存在")
		}
	}
	fileData = append(fileData, types.UARule{
		Ua:    ua,
		Open:  open,
		Time:  int64(createTime),
		Notes: notes,
		Count: int(count),
		Index: index,
	})
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s【%s】修改为【%s】", name, rule_log_del, ua), limit.log_type[log_flag], uid)
	return core.Success("编辑成功")
}

func (limit *Limit) EditUrl(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}

	if _, ok := params["url"]; !ok {
		return core.Fail("缺少url参数")
	}

	if _, ok := params["type"]; !ok {
		return core.Fail("缺少type参数")
	}

	if _, ok := params["open"]; !ok {
		return core.Fail("缺少open参数")
	}

	if _, ok := params["notes"]; !ok {
		return core.Fail("缺少notes参数")
	}

	if _, ok := params["index"]; !ok {
		return core.Fail("缺少index参数")
	}

	if _, ok := params["count"]; !ok {
		return core.Fail("缺少count参数")
	}

	count := params["count"].(float64)

	if _, ok := params["times"]; !ok {
		return core.Fail("times")
	}
	createTime := params["times"].(float64)
	index := params["index"].(string)
	uid := public.GetUid(request)
	path := ""
	name := ""

	url := public.InterfaceToString(params["url"])
	match := public.InterfaceToString(params["type"])
	param := public.InterfaceToString(params["param"])
	open := public.InterfaceToFloat64(params["open"])
	notes := public.InterfaceToString(params["notes"])

	if url == "/" {
		return core.Fail("URI不能为/")
	}
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
	case 1:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		return core.Fail("参数不合法!")
	}

	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	matchType := map[string]string{
		"=":       "完全相等",
		"param":   "匹配参数",
		"keyword": "关键字",
		"prefix":  "匹配开头",
		"suffix":  "匹配结尾",
		"match":   "正则匹配",
	}
	del_rules := make([]types.URLRule, 0)
	for i := range fileData {
		if fileData[i].Index == index {
			del_rules = append(del_rules, fileData[i])
			fileData = append(fileData[:i], fileData[i+1:]...)
			break
		}
	}
	var rule_log_del string

	content := ""
	method := ""
	for _, rule := range del_rules {
		content = rule.URL
		method = rule.Type
		rule_log_del += matchType[method] + "-[" + content + "]"
	}
	flags := true
	for _, values := range fileData {
		if values.URL == url && values.Type == match {
			return core.Fail("URI已存在")
		}
		if values.URL == url && values.Type == match && values.Param == param {
			return core.Fail("URI已存在")
		}
	}
	check := []string{
		"?",
		"&",
	}
	if match != "=" {
		url = public.EscapeSymbols(url, check)
	}
	if match == "param" {
		fileData = append(fileData, types.URLRule{
			URL:   html.UnescapeString(url),
			Type:  match,
			Param: param,
			Open:  open,
			Time:  int64(createTime),
			Notes: notes,
			Count: int(count),
			Index: index,
		})

	} else {
		fileData = append(fileData, types.URLRule{
			URL:   html.UnescapeString(url),
			Type:  match,
			Open:  open,
			Time:  int64(createTime),
			Notes: notes,
			Count: int(count),
			Index: index,
		})
	}
	sort.Slice(fileData, func(i, j int) bool {
		return fileData[i].Time > fileData[j].Time
	})
	if flags {
		buf := &bytes.Buffer{}
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(fileData)
		if err != nil {
			public.WriteFile(path, "[]")
			return core.Fail("JSON编码失败")
		}
		_, err = public.WriteFile(path, buf.String())
		if err != nil {
			return core.Fail("写入URI白名单配置失败")
		}
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	logData := matchType[match] + "-[" + url + "]"
	if logData == rule_log_del {
		return core.Success("编辑成功")
	}
	public.WriteOptLog(fmt.Sprintf("%s【%s】修改为【%s】", name, rule_log_del, logData), limit.log_type[log_flag], uid)
	return core.Success("编辑成功")
}

func (limit *Limit) GetIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["p"]; !ok {
		return core.Fail("缺少参数p")
	}
	if _, ok := params["p_size"]; !ok {
		return core.Fail("缺少参数p_size")
	}
	path := ""
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
	case 1:
		path = limit.ipBlack
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	keyword := params["keyword"].(string)
	var lines [][]any
	for _, values := range fileData {
		if values[6].(string) == "v6" || values[6].(string) == "ip_group" {
			lines = append(lines, values)
			continue
		}

		values[0] = public.LongToIp(uint32(values[0].(float64)))
		values[1] = public.LongToIp(uint32(values[1].(float64)))
		lines = append(lines, values)
	}
	if keyword != "" {
		keyData := make([][]any, 0, len(lines))
		for _, v := range lines {
			record := public.InterfaceArray_To_StringArray(v)
			if strings.Contains(record[0], keyword) || strings.Contains(record[1], keyword) || strings.Contains(record[2], keyword) {
				keyData = append(keyData, v)
			}
		}
		lines = keyData
	}
	p := public.InterfaceToInt(params["p"])
	p_size := public.InterfaceToInt(params["p_size"])
	res := public.PaginateData(lines, p, p_size)
	return core.Success(res)
}

func (limit *Limit) GetUa(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["p"]; !ok {
		return core.Fail("缺少参数p")
	}
	if _, ok := params["p_size"]; !ok {
		return core.Fail("缺少参数p_size")
	}
	path := ""
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.uaWhite
	case 1:
		path = limit.uaBlack
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	keyword := params["keyword"].(string)
	if keyword != "" {
		keyResult := make([]types.UARule, 0, len(fileData))
		for _, item := range fileData {
			if strings.Contains(item.Ua, keyword) || strings.Contains(item.Notes, keyword) || strings.Contains(item.Index, keyword) {
				keyResult = append(keyResult, item)
			}
		}
		fileData = keyResult
	}
	p := public.InterfaceToInt(params["p"])
	p_size := public.InterfaceToInt(params["p_size"])
	res := public.PaginateData(fileData, p, p_size)
	return core.Success(res)
}

func (limit *Limit) GetUrl(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["p"]; !ok {
		return core.Fail("缺少参数p")
	}
	if _, ok := params["p_size"]; !ok {
		return core.Fail("缺少参数p_size")
	}
	path := ""
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.urlWhite
	case 1:
		path = limit.urlBlack
	default:
		return core.Fail("参数不合法!")
	}
	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	keyword := params["keyword"].(string)
	if keyword != "" {
		keyResult := make([]types.URLRule, 0, len(fileData))
		for _, item := range fileData {
			if strings.Contains(item.URL, keyword) || strings.Contains(item.Notes, keyword) || strings.Contains(item.Index, keyword) {
				keyResult = append(keyResult, item)
			}
		}
		fileData = keyResult
	}

	p := public.InterfaceToInt(params["p"])
	p_size := public.InterfaceToInt(params["p_size"])
	res := public.PaginateData(fileData, p, p_size)
	return core.Success(res)

}

func (limit *Limit) rIPFile(path string) ([][]interface{}, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("[]"))
	}
	fileData := make([][]interface{}, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (limit *Limit) rUAFile(path string) ([]types.UARule, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("[]"))
	}
	fileData := make([]types.UARule, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (limit *Limit) rURLFile(path string) ([]types.URLRule, error) {
	jsonData, err := public.ReadFile(path)
	if err != nil {
		jsonData = string([]byte("[]"))
	}
	fileData := make([]types.URLRule, 0)
	err = json.Unmarshal([]byte(jsonData), &fileData)
	if err != nil {
		return nil, err
	}
	return fileData, nil
}

func (limit *Limit) search(data []interface{}, keyword string) []interface{} {
	results := []interface{}{}
	for _, item := range data {
		if strings.Contains(item.(string), keyword) {
			results = append(results, item.(string))
		}
	}

	return results
}

func (limit *Limit) OffIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	if _, ok := params["open"]; !ok {
		return core.Fail("缺少open参数")
	}
	uid := public.GetUid(request)
	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"
	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
	default:
		return core.Fail("参数不合法!")
	}
	index := params["index"].(string)
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	var log string
	start := ""
	end := ""
	delContent := ""
	for i := range fileData {
		if fileData[i][7].(string) == index {
			if v, ok := params["open"]; ok {
				if c, ok := v.(float64); ok {
					if fileData[i][4] != c {
						if c == 0 {
							log = "禁用规则"
						} else {
							log = "启用规则"
						}
					}
					fileData[i][4] = c
					if fileData[i][6].(string) == "v6" {
						start = fileData[i][0].(string)
						end = ""
					}
					if fileData[i][6].(string) == "v4" {
						start = public.LongToIp(uint32(fileData[i][0].(float64)))
						end = public.LongToIp(uint32(fileData[i][1].(float64)))
					}
					delContent = limit.f(start, end)
				}
			}
			break
		}
	}
	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s】成功", name, log, delContent), limit.log_type[log_flag], uid)
	return core.Success(log + "成功")

}

func (limit *Limit) OffUa(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}

	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}

	if _, ok := params["open"]; !ok {
		return core.Fail("缺少open参数")
	}

	uid := public.GetUid(request)

	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
	case 1:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
	default:
		return core.Fail("参数不合法!")
	}
	index := params["index"].(string)
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	var log string
	content := ""

	for i := range fileData {
		if fileData[i].Index == index {
			if v, ok := params["open"]; ok {
				if c, ok := v.(float64); ok {
					if fileData[i].Open != c {
						if c == 0 {
							log = "禁用规则"
						} else {
							log = "启用规则"
						}
					}

					fileData[i].Open = c
					content = fileData[i].Ua
				}
			}
			break
		}
	}

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s】成功", name, log, content), limit.log_type[log_flag], uid)
	return core.Success(log + "成功")
}

func (limit *Limit) OffUrl(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}

	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}

	if _, ok := params["open"]; !ok {
		return core.Fail("缺少open参数")
	}

	uid := public.GetUid(request)

	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
	case 1:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		return core.Fail("参数不合法!")
	}

	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	index := params["index"].(string)

	var log string

	content := ""
	match := ""
	matchType := map[string]string{
		"=":       "完全相等",
		"param":   "匹配参数",
		"keyword": "关键字",
		"prefix":  "匹配开头",
		"suffix":  "匹配结尾",
		"match":   "正则匹配",
	}
	for i := range fileData {
		if fileData[i].Index == index {
			if v, ok := params["open"]; ok {
				if c, ok := v.(float64); ok {
					if fileData[i].Open != c {
						if c == 0 {
							log = "禁用规则"
						} else {
							log = "启用规则"
						}
					}
					fileData[i].Open = c
					content = fileData[i].URL
					match = matchType[fileData[i].Type]
				}
			}
			break
		}
	}

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s-[%s]】成功", name, log, match, content), limit.log_type[log_flag], uid)
	return core.Success(log + "成功")
}

func (limit *Limit) ClearIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}
	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}
	uid := public.GetUid(request)

	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.ipWhite
		name = "IP白名单"
		log_flag = "0"
	case 1:
		path = limit.ipBlack
		name = "IP黑名单"
		log_flag = "1"
	default:
		return core.Fail("参数不合法!")
	}
	index := params["index"].(string)
	fileData, err := limit.rIPFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	var log string
	start := ""
	end := ""
	delContent := ""

	for i := range fileData {
		if fileData[i][7].(string) == index {
			fileData[i][5] = 0
			if fileData[i][6].(string) == "v6" {
				start = fileData[i][0].(string)
				end = ""
			}
			if fileData[i][6].(string) == "v4" {
				start = public.LongToIp(uint32(fileData[i][0].(float64)))
				end = public.LongToIp(uint32(fileData[i][1].(float64)))
			}
			break
		}
	}

	delContent = limit.f(start, end)

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}

	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s】清空命中次数成功", name, log, delContent), limit.log_type[log_flag], uid)
	return core.Success("清空命中次数成功")
}

func (limit *Limit) ClearUa(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}

	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}

	uid := public.GetUid(request)

	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.uaWhite
		name = "UA白名单"
		log_flag = "2"
	case 1:
		path = limit.uaBlack
		name = "UA黑名单"
		log_flag = "3"
	default:
		return core.Fail("参数不合法!")
	}
	index := params["index"].(string)
	fileData, err := limit.rUAFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	var log string
	content := ""
	for i := range fileData {
		if fileData[i].Index == index {

			fileData[i].Count = 0
			content = fileData[i].Ua
			break
		}
	}

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s】清空命中次数成功", name, log, content), limit.log_type[log_flag], uid)
	return core.Success("清空命中次数成功")
}

func (limit *Limit) ClearUrl(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["index"]; !ok {
		return core.Fail("缺少参数index")
	}

	if _, ok := params["types"]; !ok {
		return core.Fail("缺少参数types")
	}

	uid := public.GetUid(request)

	path := ""
	name := ""
	var log_flag string
	switch public.InterfaceToInt(params["types"]) {
	case 0:
		path = limit.urlWhite
		name = "URI白名单"
		log_flag = "4"
	case 1:
		path = limit.urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		return core.Fail("参数不合法!")
	}

	fileData, err := limit.rURLFile(path)
	if err != nil {
		return core.Fail("读取文件失败!")
	}
	index := params["index"].(string)
	var log string
	content := ""
	match := ""
	matchType := map[string]string{
		"=":       "完全相等",
		"param":   "匹配参数",
		"keyword": "关键字",
		"prefix":  "匹配开头",
		"suffix":  "匹配结尾",
		"match":   "正则匹配",
	}

	for i := range fileData {
		if fileData[i].Index == index {
			fileData[i].Count = 0
			content = fileData[i].URL
			match = matchType[fileData[i].Type]
			break
		}
	}

	text, status := json.Marshal(fileData)
	if status != nil {
		public.WriteFile(path, "[]")
		return core.Fail(status)
	}
	_, err = public.WriteFile(path, string(text))
	if err != nil {
		return core.Fail("写入配置失败")
	}
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("%s-%s【%s-[%s]】清空命中次数成功", name, log, match, content), limit.log_type[log_flag], uid)
	return core.Success("清空命中次数成功")
}
