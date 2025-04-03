package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	WafPath        = public.NginxPath + "/conf.d/waf"
	GlobalConfig   = WafPath + "/config/config.json"
	SiteConfig     = WafPath + "/config/site.json"
	DomainConfig   = WafPath + "/config/domains.json"
	CityConfig     = WafPath + "/rule/city.json"
	ProvinceConfig = WafPath + "/rule/province.json"
	CitysConfig    = core.AbsPath("./config/citys.json")
	SiteidConfig   = public.NginxPath + "/conf.d/other/siteid.json"

	RegionalRestrictionsPaths = []string{ProvinceConfig, CityConfig}
)

type Wait struct {
	Open bool    `json:"open"`
	Time float64 `json:"time"`
	User float64 `json:"user"`
	Qps  float64 `json:"qps"`
	Type string  `json:"type"`
	Text string  `json:"text"`
}

type Crawler struct {
	Encryption struct {
		Open bool   `json:"open"`
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"encryption"`
	Watermark struct {
		Open bool   `json:"open"`
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"watermark"`
}

func init() {
	core.RegisterModule(&Wafrules{})
}

type Wafrules struct{}

func (w *Wafrules) GetGlobalRules(request *http.Request) core.Response {
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}

	return core.Success(jsonData)

}

func (w *Wafrules) GetRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	resultSlice := make(map[string]interface{})
	for k, v := range jsonData.(map[string]interface{}) {
		if k == siteId {
			resultSlice = v.(map[string]interface{})
		}
	}
	return core.Success(resultSlice)

}

func (w *Wafrules) SetSiteRunMode(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "mode"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	mode := public.InterfaceToInt(params["mode"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["mode"] = mode
	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteName+"网站设置"+public.SiteMode[mode]+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetSmartCcRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "open"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	open := public.InterfaceToBool(params["open"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	prrintStr := "开启"
	if open {
		if public.GetAuthInfo() < 1 {
			return core.Fail("授权网站数量不足").SetCode(403)
		}
	}
	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; !ok {
		return core.Fail("siteId不存在")
	}
	if _, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["smart_cc"]; ok {
		accessCc := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["smart_cc"].(map[string]interface{})
		accessCc["open"] = open
	} else {
		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["smart_cc"] = map[string]interface{}{"open": open, "status": 444,
				"max_avg_proxy_time": 2000,
				"max_err_count":      5,
				"expire":             120,
				"max_qps":            10,
				"ip_drop_time":       360,
				"ps":                 "智能CC防护"}
		}

	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteName+"网站"+prrintStr+"动态CC成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetCcRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "status", "cycle", "open", "limit", "endtime", "cc_type_status", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))

	ccTypeStatus := public.InterfaceToInt(params["cc_type_status"].(interface{}))
	limit := public.InterfaceToInt(params["limit"].(interface{}))
	endTime := public.InterfaceToInt(params["endtime"].(interface{}))
	cycle := public.InterfaceToInt(params["cycle"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	open := public.InterfaceToBool(params["open"].(interface{}))
	isCcUrl := false
	if params["is_cc_url"] != nil {
		isCcUrl = public.InterfaceToBool(params["is_cc_url"].(interface{}))
	}
	filePathS := map[string]string{"global": GlobalConfig, "not_global": SiteConfig, "site": SiteConfig}

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "开启"

	if !open {
		printStr = "关闭"
	}
	printStr = printStr + "CC防御成功"

	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}
	logType := public.OPT_LOG_TYPE_SITE_LIST
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr

		accessCc := jsonData.(map[string]interface{})["cc"].(map[string]interface{})
		accessCc["status"] = status
		accessCc["cc_type_status"] = ccTypeStatus
		accessCc["limit"] = limit
		accessCc["endtime"] = endTime
		accessCc["open"] = open
		accessCc["cycle"] = cycle
		accessCc["is_cc_url"] = isCcUrl
		jsonData.(map[string]interface{})["cc"] = accessCc
	case "not_global":
		logType = public.OPT_LOG_TYPE_SITE_RULE
		printStr = siteName + "网站" + printStr

		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			accessCc := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"].(map[string]interface{})
			accessCc["status"] = status
			accessCc["cc_type_status"] = ccTypeStatus
			accessCc["limit"] = limit
			accessCc["endtime"] = endTime
			accessCc["open"] = open
			accessCc["cycle"] = cycle
			accessCc["is_cc_url"] = isCcUrl

			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"] = accessCc
		}
	case "site":
		printStr = siteName + "网站" + printStr

		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			accessCc := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"].(map[string]interface{})
			accessCc["open"] = open

			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"] = accessCc
		}
	}
	if types == "global" {
		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	} else {
		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}

	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetRetryRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "retry_cycle", "retry", "retry_time"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	retryCycle := public.InterfaceToInt(params["retry_cycle"].(interface{}))
	retry := public.InterfaceToInt(params["retry"].(interface{}))
	retryTime := public.InterfaceToInt(params["retry_time"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	filePathS := map[string]string{"global": GlobalConfig, "not_global": SiteConfig}

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "设置攻击次数拦截成功"
	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}
	logType := public.OPT_LOG_TYPE_SITE_RULE
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE

		numberAttacks := jsonData.(map[string]interface{})["number_attacks"].(map[string]interface{})
		numberAttacks["retry_cycle"] = retryCycle
		numberAttacks["retry"] = retry
		numberAttacks["retry_time"] = retryTime

		jsonData.(map[string]interface{})["number_attacks"] = numberAttacks
	case "not_global":

		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			numberAttacks := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["number_attacks"].(map[string]interface{})
			numberAttacks["retry_cycle"] = retryCycle
			numberAttacks["retry"] = retry
			numberAttacks["retry_time"] = retryTime

			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["number_attacks"] = numberAttacks
		}
	}
	if types == "global" {
		printStr = "全局" + printStr
		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}

	} else {
		printStr = siteName + "站点" + printStr
		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetCdnHeaders(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "cdn_header", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	cdnHeader := public.InterfaceToString(params["cdn_header"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "添加"
	jsonData, err := public.ReadInterfaceFileBytes(SiteConfig)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_header"]; !ok {
		return core.Fail("cdn_header不存在")
	}
	cdnHeaders := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_header"].([]interface{})
	switch types {
	case "add":
		for _, v := range cdnHeaders {
			if v.(string) == cdnHeader {
				return core.Fail("该cdn_header已存在")
			}
		}
		cdnHeaders = append(cdnHeaders, cdnHeader)
		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_header"] = cdnHeaders
	case "del":
		printStr = "删除"
		for k, v := range cdnHeaders {
			if v.(string) == cdnHeader {
				cdnHeaders = append(cdnHeaders[:k], cdnHeaders[k+1:]...)
				jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_header"] = cdnHeaders
				break
			}
		}
	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	printStr = siteName + printStr + cdnHeader + "成功"
	public.WriteOptLog(fmt.Sprintf(printStr), public.OPT_LOG_TYPE_SITE_RULE, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetCdnRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "cdn", "cdn_baidu", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	cdn := public.InterfaceToBool(params["cdn"].(interface{}))
	cdnBaidu := public.InterfaceToBool(params["cdn_baidu"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	siteJson, err := GetSiteJson(siteId)
	if err != nil {
		return core.Fail(errors.New("站点配置获取败：" + err.Error()))
	}
	siteName := siteJson.SiteName
	printStr := siteName + "设置CDN状态为："
	if cdn {
		printStr += "开启，"
	} else {
		printStr += "关闭，"
	}
	if cdnBaidu {
		printStr += "并兼容百度CDN"
	} else {
		printStr += "不兼容百度CDN"
	}
	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	logType := public.OPT_LOG_TYPE_SITE_LIST
	switch types {
	case "not_global":
		logType = public.OPT_LOG_TYPE_SITE_RULE
		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"] = cdn
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_baidu"] = cdnBaidu
		}

	case "site":
		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"] = cdn
		}
	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}

	err = ParseSiteJson(siteJson)
	if err != nil {
		return core.Fail(errors.New("站点配置生成失败：" + err.Error()))
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetModeRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "mode", "modename", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	mode := public.InterfaceToInt(params["mode"].(interface{}))
	modeName := public.InterfaceToString(params["modename"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	filePathS := map[string]string{"global": GlobalConfig, "site": SiteConfig}

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "设置" + public.SiteWafMode[mode] + "成功"
	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}

	logType := public.OPT_LOG_TYPE_SITE_RULE
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr
		modeNameV := jsonData.(map[string]interface{})[modeName].(map[string]interface{})
		modeNameV["mode"] = mode
		jsonData.(map[string]interface{})[modeName] = modeNameV

	case "site":
		printStr = siteName + "站点" + printStr
		if err != nil {
			return core.Fail(err)
		}
		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})[modeName].(map[string]interface{})["mode"] = mode
		}
	}
	if types == "global" {
		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	} else {
		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetFileUploadRules(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "status", "mode", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))
	mode := public.InterfaceToInt(params["mode"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))

	filePathS := map[string]string{"global": GlobalConfig, "site": SiteConfig}
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "设置文件上传防护为" + public.SiteWafMode[mode] + "成功"
	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}
	logType := public.OPT_LOG_TYPE_SITE_RULE

	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr
		modeNameV := jsonData.(map[string]interface{})["file_upload"].(map[string]interface{})
		modeNameV["mode"] = mode
		modeNameV["status"] = status
		jsonData.(map[string]interface{})["file_upload"] = modeNameV

	case "site":
		printStr = siteName + "网站" + printStr
		if err != nil {
			return core.Fail(err)
		}
		if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
			modeNameV := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["file_upload"].(map[string]interface{})
			modeNameV["mode"] = mode
			modeNameV["status"] = status
			jsonData.(map[string]interface{})[siteId].(map[string]interface{})["file_upload"] = modeNameV
		}
	}

	if types == "global" {
		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}

	} else {
		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetFileScanRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"mode", "limit", "cycle"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	limit := public.InterfaceToInt(params["limit"].(interface{}))
	mode := public.InterfaceToInt(params["mode"].(interface{}))
	cycle := public.InterfaceToInt(params["cycle"].(interface{}))
	jsonData, err := public.ReadInterfaceFileBytes(GlobalConfig)
	if err != nil {
		return core.Fail(err)
	}
	modeNameV := jsonData.(map[string]interface{})["file_scan"].(map[string]interface{})
	modeNameV["mode"] = mode
	modeNameV["cycle"] = cycle
	modeNameV["limit"] = limit
	jsonData.(map[string]interface{})["file_scan"] = modeNameV

	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("全局设置目录扫描防御成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) ApplyAll(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	types := public.InterfaceToString(params["type"].(interface{}))
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	SiteJsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	siteIdData, err := public.ReadInterfaceFileBytes(SiteidConfig)
	if err != nil {
		return core.Fail(err)
	}
	if siteIdData == nil {
		return core.Fail("没有站点")
	}
	printStr := "基础cc防护规则"
	switch types {
	case "cc":
		globalV := interface{}(nil)
		if _, ok := jsonData.(map[string]interface{})["cc"]; ok {
			globalV = jsonData.(map[string]interface{})["cc"]
		} else {
			return core.Fail("没有全局规则")
		}

		for _, v := range siteIdData.(map[string]interface{}) {
			siteId := v.(string)
			if _, ok := SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
				cc := SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"].(map[string]interface{})
				cc["status"] = globalV.(map[string]interface{})["status"]
				cc["cc_type_status"] = globalV.(map[string]interface{})["cc_type_status"]
				cc["limit"] = globalV.(map[string]interface{})["limit"]
				cc["endtime"] = globalV.(map[string]interface{})["endtime"]
				cc["open"] = globalV.(map[string]interface{})["open"]
				cc["cycle"] = globalV.(map[string]interface{})["cycle"]
				SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"] = cc
			}
		}
	case "number_attacks":
		printStr = "攻击次数拦截防护规则"
		globalV := interface{}(nil)
		if _, ok := jsonData.(map[string]interface{})["number_attacks"].(map[string]interface{}); ok {
			globalV = jsonData.(map[string]interface{})["number_attacks"].(map[string]interface{})
		} else {
			return core.Fail("没有全局规则")
		}

		for _, v := range siteIdData.(map[string]interface{}) {
			siteId := v.(string)
			if _, ok := SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
				numberAttacks := SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{})["number_attacks"].(map[string]interface{})
				numberAttacks["retry_cycle"] = globalV.(map[string]interface{})["retry_cycle"]

				numberAttacks["retry"] = globalV.(map[string]interface{})["retry"]
				numberAttacks["retry_time"] = globalV.(map[string]interface{})["retry_time"]
				SiteJsonData.(map[string]interface{})[siteId].(map[string]interface{})["number_attacks"] = numberAttacks
			}

		}
	}
	err = public.WriteSiteConfig(SiteJsonData)
	if err != nil {
		return core.Fail(err)
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("全局"+printStr+"应用到所有网站成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) GetHttpMethodTypeRules(request *http.Request) core.Response {
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := jsonData.(map[string]interface{})["method_type"]; ok {
		return core.Success(jsonData.(map[string]interface{})["method_type"])
	}
	return core.Success("获取数据为空")

}

func (w *Wafrules) SetHttpMethodTypeRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"type", "status"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	types := public.InterfaceToString(params["type"].(interface{}))
	status := public.InterfaceToBool(params["status"].(interface{}))

	statusStr := "开启"
	if !status {
		statusStr = "关闭"
	}

	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})["method_type"]; ok {
		jsonData.(map[string]interface{})["method_type"].(map[string]interface{})[types] = status
	}

	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("全局设置请求头"+types+"为"+statusStr+"状态"), public.OPT_LOG_TYPE_USER_OPERATION, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) GetHttpHeaderLenRules(request *http.Request) core.Response {

	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})["header_len"]; ok {
		return core.Success(jsonData.(map[string]interface{})["header_len"])
	}

	return core.Success("获取数据为空")

}

func (w *Wafrules) AddHttpHeaderLenRules(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"type", "length"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	types := public.InterfaceToString(params["type"].(interface{}))
	length := public.InterfaceToInt(params["length"].(interface{}))

	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})["header_len"].(map[string]interface{})[types]; ok {
		return core.Fail("该类型已存在")
	} else {
		jsonData.(map[string]interface{})["header_len"].(map[string]interface{})[types] = length
	}

	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("全局添加请求头"+types+"长度为"+public.IntToString(length)+"成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) ModifyHttpHeaderLenRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"type", "length"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	types := public.InterfaceToString(params["type"].(interface{}))
	length := public.InterfaceToInt(params["length"].(interface{}))

	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := jsonData.(map[string]interface{})["header_len"]; ok {
		jsonData.(map[string]interface{})["header_len"].(map[string]interface{})[types] = length
	}
	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("编辑请求头"+types+"长度为"+public.IntToString(length)+"成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) DelHttpHeaderLenRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	types := public.InterfaceToString(params["type"].(interface{}))
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := jsonData.(map[string]interface{})["header_len"].(map[string]interface{})[types]; ok {

		delete(jsonData.(map[string]interface{})["header_len"].(map[string]interface{}), types)
	}
	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("删除请求头"+types+"成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) GetSpiderRules(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"spider_type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	spider_type := public.InterfaceToString(params["spider_type"].(interface{}))
	if spider_type == "" {
		return core.Fail("参数错误")
	}
	rule_path := WafPath + "/inc/" + params["spider_type"].(string) + ".json"

	jsonData, err := public.ReadInterfaceFileBytes(rule_path)
	if err != nil {
		return core.Fail(err)
	}

	return core.Success(jsonData)

}

func (w *Wafrules) UpdateSpiderRules(request *http.Request) core.Response {
	spiderType := []string{"1", "2", "3", "4", "5", "6", "7", "8"}
	for _, v := range spiderType {
		fileURL := "https://www.bt.cn/api/panel/get_spider_segment?spider=" + v
		filePath := WafPath + "/inc/" + v + ".json"

		response, err := http.Get(fileURL)
		if err != nil {
			continue
		}
		defer response.Body.Close()

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			continue
		}

		var remoteArray []string
		err = json.Unmarshal(data, &remoteArray)
		if err != nil {
			continue
		}

		localData, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var localArray []string
		err = json.Unmarshal(localData, &localArray)
		if err != nil {
			continue
		}

		resultArray := public.UnionArrays(remoteArray, localArray)

		resultData, err := json.Marshal(resultArray)
		if err != nil {
			continue
		}

		err = os.WriteFile(filePath, resultData, 0644)
		if err != nil {
			continue
		}
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.WriteOptLog(fmt.Sprintf("全局更新蜘蛛池成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SimulatedAttack(request *http.Request) core.Response {
	jsonData, err := public.ReadInterfaceFileBytes(DomainConfig)
	if err != nil {
		return core.Fail(err)
	}
	if jsonData == nil {
		return core.Fail("没有站点")
	}
	var result []string
	for _, v := range jsonData.([]interface{}) {

		if _, ok := v.(map[string]interface{})["name"]; ok {

			name := strings.Replace(v.(map[string]interface{})["name"].(string), "*.", "", -1)
			result = append(result, "http://"+name+"/?id=1'union select user(),1,3--")
		}
	}
	return core.Success(result)
}

func (w *Wafrules) GetRegionalRestrictions(request *http.Request) core.Response {
	jsonData, err := public.ReadInterfaceFileBytes(CitysConfig)
	if err != nil {
		return core.Fail(err)
	}

	return core.Success(jsonData)

}

func (w *Wafrules) GetRegionalRestrictionsRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"searchStr", "p", "p_size"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	searchStr := public.InterfaceToString(params["searchStr"].(interface{}))
	p := public.InterfaceToInt(params["p"].(interface{}))
	pSize := public.InterfaceToInt(params["p_size"].(interface{}))
	var resultSlice []interface{}
	for _, filepath := range RegionalRestrictionsPaths {

		resultSlice = public.GetAllRegionRules(resultSlice, filepath, searchStr)
	}
	res := public.PaginateData(resultSlice, p, pSize)
	return core.Success(res)

}

func (w *Wafrules) AddRegionalRestrictionsRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_ids", "type", "region", "add_type", "uri"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteIdS := public.InterfaceArray_To_StringArray(params["site_ids"].([]interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	uri := public.InterfaceToString(params["uri"].(interface{}))
	region := public.InterfaceArray_To_StringArray(params["region"].([]interface{}))
	addType := public.InterfaceToString(params["add_type"].(interface{}))

	siteIdStr := strings.Join(siteIdS, ", ")
	typeStr := "拦截"
	if types != "refuse" {
		typeStr = "只允许"
	}
	siteName := "全部"
	if siteIdStr != "allsite" {
		res, err := public.M("site_info").Where("site_id=?", siteIdStr).Field([]string{"site_name"}).Find()
		if err != nil {
			return core.Fail(err)
		}
		siteName = res["site_name"].(string)
	}
	logString := siteName + "网站" + "添加" + strings.Join(region, ",") + "地区" + typeStr + "规则成功"

	if addType != "site_city" {

		if public.GetAuthInfo() < 1 {
			return core.Fail("授权网站数量不足").SetCode(403)
		}
	} else {
		if public.S("region_free").Where("site_id = ? and label=?", []any{siteIdS[0], "overseas"}).Exists() {
			_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
				conn.Begin()
				defer func() {
					if err != nil {
						conn.Rollback()
						return
					}
					conn.Commit()
				}()
				_, err = conn.NewQuery().Table("region_free").Where("site_id = ? and label=?", []any{siteIdS[0], "overseas"}).Delete()
				if err != nil {
					return nil, err
				}
				return nil, nil
			})
			if err != nil {
				return core.Fail("地区限制禁止海外访问[" + siteIdS[0] + "已存在")
			}
		}
		type RegionFree struct {
			SiteId     string `json:"site_id"`
			Label      string `json:"label"`
			CreateTime int64  `json:"create_time"`
		}
		inDnsData := RegionFree{
			SiteId:     siteIdS[0],
			Label:      "overseas",
			CreateTime: time.Now().Unix(),
		}

		updateData := public.StructToMap(inDnsData)
		_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
			conn.Begin()
			defer func() {
				if err != nil {
					conn.Rollback()
					return
				}
				conn.Commit()
			}()
			_, err = conn.NewQuery().Table("region_free").Insert(updateData)
			if err != nil {
				return nil, err
			}
			return nil, nil
		})
		if err != nil {
			return core.Fail(fmt.Errorf("添加规则失败：数据库插入失败 %w", err))
		}
		logString = siteName + "网站" + "添加" + "海外规则成功"
		addType = "city"
	}
	regionId := public.RandomStr(20)
	switch addType {
	case "province":
		err = public.AddSpecifyRegionRules(siteIdS, types, region, regionId, ProvinceConfig, uri)
		if err != nil {
			return core.Fail(err)
		}
	case "city":
		err = public.AddSpecifyRegionRules(siteIdS, types, region, regionId, CityConfig, uri)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_AREA, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetRegionalRestrictionsRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"region_id", "status"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	regionId := public.InterfaceToString(params["region_id"].(interface{}))
	status := public.InterfaceToBool(params["status"].(interface{}))
	siteId, _, err := public.GetSiteNameByRegionId(regionId)
	if err != nil {
		return core.Fail(err)
	}
	statusStr := "关闭"
	if status {
		statusStr = "启用"
		if public.GetAuthInfo() < 1 {
			return core.Fail("授权网站数量不足").SetCode(403)
		}
	}
	for _, filepath := range RegionalRestrictionsPaths {
		err = public.SetSpecifyRegionStatus(regionId, status, filepath)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteId+"网站"+statusStr+"地区限制规则成功"), public.OPT_LOG_TYPE_SITE_AREA, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) DelRegionalRestrictionsRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"region_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	regionId := public.InterfaceArray_To_StringArray(params["region_id"].([]interface{}))
	siteIdS := make([]string, 0)
	delSqliteData := false
	delSiteId := ""
	for _, v := range regionId {
		siteId, overseas, err := public.GetSiteNameByRegionId(v)
		if err != nil {
			return core.Fail(err)
		}
		siteId = strings.Replace(siteId, "allsite", "全部网站", -1)
		siteIdS = append(siteIdS, siteId)
		if siteId != "allsite" && overseas {
			if public.S("region_free").Where("site_id = ? and label=?", []any{siteId, "overseas"}).Exists() {
				delSqliteData = true
				delSiteId = siteId
				continue
			}
		}
	}
	types, regionList, err := public.DelRegionalRestrictionsRules(regionId, ProvinceConfig)
	if err != nil {
		return core.Fail(err)
	}
	types, regionList, err = public.DelRegionalRestrictionsRules(regionId, CityConfig)
	if err != nil {
		return core.Fail(err)
	}
	if delSqliteData {
		_, err = public.SqliteWithClose(func(conn *db.Sqlite) (res any, err error) {
			conn.Begin()
			defer func() {
				if err != nil {
					conn.Rollback()
					return
				}
				conn.Commit()
			}()
			_, err = conn.NewQuery().Table("region_free").Where("site_id = ? and label=?", []any{delSiteId, "overseas"}).Delete()
			if err != nil {
				return nil, err
			}
			return nil, nil
		})
		if err != nil {
			return core.Fail(fmt.Errorf("添加规则失败：数据库插入失败 %w", err))
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	typesMap := map[string]string{"refuse": "拦截", "allow": "只允许"}
	public.WriteOptLog(fmt.Sprintf("删除以下规则成功：规则ID【"+strings.Join(regionId, ",")+"】 "+"网站【"+strings.Join(siteIdS, ",")+"】"+typesMap[types]+"【"+regionList)+"】", public.OPT_LOG_TYPE_SITE_AREA, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) ResetRegionalCountryRules(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"region_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	regionId := public.InterfaceToString(params["region_id"].(interface{}))
	siteId, _, err := public.GetSiteNameByRegionId(regionId)
	if err != nil {
		return core.Fail(err)
	}
	for _, filepath := range RegionalRestrictionsPaths {
		err = public.ResetSpecifyRegionCount(regionId, filepath)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteId+"网站重置命中次数成功"), public.OPT_LOG_TYPE_SITE_AREA, public.GetUid(request))
	return core.Success("操作成功")

}

func (w *Wafrules) SetSingleUri(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"uri", "cycle", "frequency", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	uri := public.InterfaceToString(params["uri"].(interface{}))
	cycle := public.InterfaceToInt(params["cycle"].(interface{}))
	frequency := public.InterfaceToInt(params["frequency"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	result, err := public.SetSingleUriRules(uri, cycle, frequency, types)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	typeStr := ""
	switch types {
	case "add":
		typeStr = "添加"
	case "del":
		typeStr = "删除"
	case "modify":
		typeStr = "编辑"
	}
	if types == "add" {

	}
	public.WriteOptLog(fmt.Sprintf("全局"+typeStr+"单URL CC防御规则"+uri+"成功"), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success(result)

}

func (w *Wafrules) ApplyGlobalRulesToSite(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"type", "site_id_list"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteIdList := public.InterfaceArray_To_StringArray(params["site_id_list"].([]interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	argsTypes := map[string]string{"cc": "基础CC防护", "cookie": "cookie头攻击防御", "download": "恶意下载防御", "scan": "扫描器防御", "file_import": "文件包含防御", "file_upload": "拦截恶意文件上传", "from_data": "畸形文件上传协议检测", "number_attacks": "攻击次数拦截", "sql": "SQL注入拦截", "xss": "XSS注入拦截", "ssrf": "ssrf代码执行检测", "user_agent": "恶意爬虫防御", "php_eval": "PHP代码执行检测", "idc": "禁用IDC", "rce": "命令执行拦截"}

	if len(siteIdList) == 0 {
		return core.Fail("请至少选择一个网站")
	}
	if _, ok := argsTypes[types]; !ok {
		return core.Fail("参数错误")
	}
	specifyGlobalRules, err := public.GetSpecifyGlobalConfigRules(types)
	if err != nil {
		return core.Fail(err)
	}
	sucessSiteNameList := make([]string, 0)
	errorSiteNameList := make([]string, 0)
	for _, v := range siteIdList {

		data, err := GetSiteJson(v)
		if err != nil {
			continue
		}
		SiteJsonData, err := public.GetWafSiteConfigRules()
		if err != nil {
			errorSiteNameList = append(errorSiteNameList, data.SiteName)
			continue
		}
		if _, ok := SiteJsonData.(map[string]interface{})[v].(map[string]interface{}); ok {
			count := 0
			if types != "rce" {
				if _, ok := SiteJsonData.(map[string]interface{})[v].(map[string]interface{})[types]; ok {

					if _, ok := SiteJsonData.(map[string]interface{})[v].(map[string]interface{})[types].(map[string]interface{})["count"].(int); ok {
						count = SiteJsonData.(map[string]interface{})[v].(map[string]interface{})[types].(map[string]interface{})["count"].(int)
					}

				}
			}
			SiteJsonData.(map[string]interface{})[v].(map[string]interface{})[types] = specifyGlobalRules
			SiteJsonData.(map[string]interface{})[v].(map[string]interface{})[types].(map[string]interface{})["count"] = count
			err = public.WriteSiteConfig(SiteJsonData)
			if err != nil {
				errorSiteNameList = append(errorSiteNameList, data.SiteName)
				continue
			}
			sucessSiteNameList = append(sucessSiteNameList, data.SiteName)
		}

	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	errlog := ""
	writeErrorLog := ""
	if len(errorSiteNameList) != 0 {
		errlog = "，应用到以下网站失败：<br/>" + strings.Join(errorSiteNameList, "<br/>")
		writeErrorLog = "，应用到以下网站失败：【" + strings.Join(errorSiteNameList, "，") + "】"
	}
	printStr := "全局规则【" + argsTypes[types] + "】应用到以下网站成功：<br/>" + strings.Join(sucessSiteNameList, "<br/>") + errlog
	writeLog := "全局规则【" + argsTypes[types] + "】应用到以下网站成功：【" + strings.Join(sucessSiteNameList, "，") + "】" + writeErrorLog
	public.WriteOptLog(writeLog, public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success(printStr)

}

func (w *Wafrules) SetIdcDeny(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "open"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	open := public.InterfaceToInt(params["open"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	types := public.InterfaceToString(params["type"].(interface{}))
	printStr := "开启IDC限制成功"
	filePathS := map[string]string{"global": GlobalConfig, "not_global": SiteConfig, "site": SiteConfig}

	if open == 0 {
		printStr = "关闭IDC限制成功"
	}

	if open == 1 {
		if public.GetAuthInfo() < 1 {
			return core.Fail("授权网站数量不足").SetCode(403)
		}
	}

	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}

	logType := public.OPT_LOG_TYPE_SITE_LIST
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr

		if v, ok := jsonData.(map[string]interface{}); ok {
			v["idc"] = map[string]any{
				"mode": open,
				"ps":   "IDC限制",
			}
		}
	case "not_global":
		logType = public.OPT_LOG_TYPE_SITE_RULE
		printStr = siteName + "网站" + printStr

		if v, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
			v["idc"] = map[string]any{
				"mode": open,
				"ps":   "IDC限制",
			}
		}
	case "site":
		printStr = siteName + "网站" + printStr

		if v, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
			v["idc"] = map[string]any{
				"mode": open,
				"ps":   "IDC限制",
			}
		}
	}

	if types == "global" {

		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	} else {

		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetMaliciousIp(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "open"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	open := public.InterfaceToInt(params["open"].(interface{}))
	types := public.InterfaceToString(params["type"].(interface{}))
	printStr := "开启云端恶意IP库成功"
	filePathS := map[string]string{"global": GlobalConfig, "not_global": SiteConfig, "site": SiteConfig}

	if open == 0 {
		printStr = "关闭云端恶意IP库成功"
	}

	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}

	logType := public.OPT_LOG_TYPE_SITE_LIST
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr

		if v, ok := jsonData.(map[string]interface{}); ok {
			v["malicious_ip"] = map[string]any{
				"mode": open,
				"ps":   "云端恶意IP库",
			}
		}
	}

	if types == "global" {

		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	} else {

		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetHvv(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "open"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	open := public.InterfaceToBool(params["open"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	types := public.InterfaceToString(params["type"].(interface{}))
	printStr := "开启护网防护成功"
	filePathS := map[string]string{"global": GlobalConfig, "not_global": SiteConfig, "site": SiteConfig}

	if !open {
		printStr = "关闭护网防护成功"
	}

	if open {
		if public.GetAuthInfo() < 1 {
			return core.Fail("授权网站数量不足").SetCode(403)
		}
	}

	jsonData, err := public.ReadInterfaceFileBytes(filePathS[types])
	if err != nil {
		return core.Fail(err)
	}

	logType := public.OPT_LOG_TYPE_SITE_LIST
	switch types {
	case "global":
		logType = public.OPT_LOG_TYPE_SITE_GLOBAL_RULE
		printStr = "全局" + printStr

		if v, ok := jsonData.(map[string]interface{}); ok {
			v["readonly"] = map[string]any{
				"open": open,
				"ps":   "只读模式,请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能",
			}
		}
	case "not_global":
		logType = public.OPT_LOG_TYPE_SITE_RULE
		printStr = siteName + "网站" + printStr

		if v, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
			v["readonly"] = map[string]any{
				"open": open,
				"ps":   "只读模式,请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能",
			}
		}
	case "site":
		printStr = siteName + "网站" + printStr

		if v, ok := jsonData.(map[string]interface{})[siteId].(map[string]interface{}); ok {
			v["readonly"] = map[string]any{
				"open": open,
				"ps":   "只读模式,请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能",
			}
		}
	}

	if types == "global" {

		err = public.WriteGlobalConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	} else {

		err = public.WriteSiteConfig(jsonData)
		if err != nil {
			return core.Fail(err)
		}
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) RecoverDefaultConfig(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "type"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	typeString := public.InterfaceToString(params["type"].(interface{}))
	logString := "一键恢复全局默认配置"
	switch typeString {
	case "global":
		logString = "全局规则" + logString
	case "site":
		logString = "网站" + siteId + logString
		siteConfig := types.SiteConfigRules{}

		siteConfig.Mode = 2

		siteConfig.Cc.Open = true
		siteConfig.Cc.Cycle = 60
		siteConfig.Cc.CcTypeStatus = 2
		siteConfig.Cc.Endtime = 300
		siteConfig.Cc.Limit = 120
		siteConfig.Cc.Ps = "基础CC防护"
		siteConfig.Cc.Status = 444
		siteConfig.NumberAttacks.Ps = "攻击次数拦截"
		siteConfig.NumberAttacks.Retry = 10
		siteConfig.NumberAttacks.RetryCycle = 120
		siteConfig.NumberAttacks.RetryTime = 600
		siteConfig.DisableUploadExt = []string{"php", "jsp"}
		siteConfig.DisableExt = []string{"sql", "bak", "swp"}
		siteConfig.DisablePhpPath = []string{"^/cache/", "^/config/", "^/runtime/", "^/application/", "^/temp/", "^/logs/", "^/log/"}
		siteConfig.CdnHeader = []string{"x-forwarded-for", "x-real-ip", "x-forwarded", "forwarded-for", "forwarded", "true-client-ip", "client-ip", "ali-cdn-real-ip", "cdn-src-ip", "cdn-real-ip", "cf-connecting-ip", "x-cluster-client-ip", "wl-proxy-client-ip", "proxy-client-i"}
		siteConfig.AdminProtect = make([]interface{}, 0)
		siteConfig.Cookie.Mode = 2
		siteConfig.Cookie.Ps = "cookie头攻击防御"
		siteConfig.Download.Mode = 2
		siteConfig.Download.Ps = "恶意下载防御"
		siteConfig.Scan.Mode = 2
		siteConfig.Scan.Ps = "扫描器防御"
		siteConfig.FileImport.Mode = 2
		siteConfig.FileImport.Ps = "文件包含防御"
		siteConfig.FileUpload.Mode = 3
		siteConfig.FileUpload.Ps = "拦截恶意文件上传"
		siteConfig.FileUpload.Status = 444
		siteConfig.FromData.Mode = 3
		siteConfig.FromData.Ps = "畸形文件上传协议检测"
		siteConfig.Sql.Mode = 3
		siteConfig.Sql.Ps = "SQL注入拦截"
		siteConfig.Xss.Mode = 3
		siteConfig.Xss.Ps = "XSS注入拦截"
		siteConfig.Ssrf.Mode = 2
		siteConfig.Ssrf.Ps = "ssrf代码执行检测"
		siteConfig.UserAgent.Mode = 2
		siteConfig.UserAgent.Ps = "恶意爬虫防御"
		siteConfig.PhpEval.Mode = 2
		siteConfig.PhpEval.Ps = "PHP代码执行检测"
		siteConfig.ReadOnly.Open = false
		siteConfig.ReadOnly.Ps = "只读模式,请勿在非攻防演练时开启,开启后将会影响用户登录、支付、搜索、注册、评论等功能"
		siteConfig.Rce.Mode = 1
		siteConfig.Rce.Ps = "命令执行拦截"
		siteConfig.Idc.Mode = 0
		siteConfig.Idc.Ps = "禁止IDC"
		siteConfig.SmartCc.Expire = 120
		siteConfig.SmartCc.IpDropTime = 3600
		siteConfig.SmartCc.MaxQps = 10
		siteConfig.SmartCc.MaxAvgProxyTime = 200
		siteConfig.SmartCc.MaxErrCount = 10
		siteConfig.SmartCc.Open = false
		siteConfig.SmartCc.Ps = "智能CC防御"
		siteConfig.SmartCc.Status = 444
		siteConfig.Cdn = false
		siteConfig.CdnBaidu = false
		siteConfigData, err := public.GetWafSiteConfigRules()
		if err == nil {
			if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{}); ok {

				if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["idc"]; ok {
					siteConfig.Idc.Mode = siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["idc"].(map[string]interface{})["mode"].(float64)
				}
				if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["smart_cc"]; ok {
					tmp_v := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["smart_cc"].(map[string]interface{})
					siteConfig.SmartCc.Expire = tmp_v["expire"].(float64)
					siteConfig.SmartCc.IpDropTime = tmp_v["ip_drop_time"].(float64)
					siteConfig.SmartCc.MaxQps = tmp_v["max_qps"].(float64)
					siteConfig.SmartCc.MaxAvgProxyTime = tmp_v["max_avg_proxy_time"].(float64)
					siteConfig.SmartCc.MaxErrCount = tmp_v["max_err_count"].(float64)
					siteConfig.SmartCc.Open = tmp_v["open"].(bool)
					siteConfig.SmartCc.Ps = tmp_v["ps"].(string)
					siteConfig.SmartCc.Status = tmp_v["status"].(float64)
				}
				if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"]; ok {
					siteConfig.Cdn = siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"].(bool)
				}
				if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_baidu"]; ok {
					siteConfig.CdnBaidu = siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["cdn_baidu"].(bool)
				}
				if _, ok := siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["readonly"]; ok {
					siteConfig.ReadOnly.Open = siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["readonly"].(map[string]interface{})["open"].(bool)
					siteConfig.ReadOnly.Ps = siteConfigData.(map[string]interface{})[siteId].(map[string]interface{})["readonly"].(map[string]interface{})["ps"].(string)
				}
			}

		}

		siteConfigData.(map[string]interface{})[siteId] = siteConfig
		err = public.WriteSiteConfig(siteConfigData)
		if err != nil {
			return core.Fail(err)
		}
		return core.Success("操作成功")
	}

	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_GLOBAL_RULE, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SetRewriteUrl(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "old_url", "rewrite_url"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	old_url := public.InterfaceToString(params["old_url"].(interface{}))
	rewrite_url := public.InterfaceToString(params["rewrite_url"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	printStr := "添加url重写成功 [" + old_url + "] 重写为 [" + rewrite_url + "]"

	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}

	logType := public.OPT_LOG_TYPE_SITE_LIST
	printStr = siteName + "网站" + printStr

	if jsonData, ok := jsonData.(map[string]interface{}); ok {
		if v, ok := jsonData[siteId].(map[string]interface{}); ok {
			if re_url, ok := v["rewrite_url"].(map[string]interface{}); ok {
				if len(re_url) > 4 {
					return core.Fail("只允许五个url重写")
				}
				re_url[rewrite_url] = old_url
			} else {
				v["rewrite_url"] = map[string]interface{}{
					rewrite_url: old_url,
				}
			}
		}
	}

	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) DelRewriteUrl(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "old_url", "rewrite_url"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	old_url := public.InterfaceToString(params["old_url"].(interface{}))
	new_url := public.InterfaceToString(params["rewrite_url"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)

	printStr := "删除url重写成功 删除原url:[" + old_url + "] 重写url:[" + new_url + "]"

	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return core.Fail(err)
	}
	logType := public.OPT_LOG_TYPE_SITE_LIST
	printStr = siteName + "网站" + printStr
	new_map := make(map[string]interface{})
	if jsonData, ok := jsonData.(map[string]interface{}); ok {
		if v, ok := jsonData[siteId].(map[string]interface{}); ok {
			if re_url, ok := v["rewrite_url"].(map[string]interface{}); ok {
				for k, v1 := range re_url {
					if v1 != old_url {
						new_map[k] = v1
					}
				}
				v["rewrite_url"] = new_map
			}
		}
	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(printStr), logType, public.GetUid(request))
	return core.Success("操作成功")
}

func (w *Wafrules) SimulateAttack(request *http.Request) core.Response {
	siteList := make([]types.EntrySiteJson, 0)
	res, err := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time"}).
		Order("create_time", "desc").
		Select()
	if err != nil {
		return core.Fail(err)
	}
	if err = public.MapToStruct(res, &siteList); err != nil {
		return core.Fail(err)
	}
	type SimulateAttack struct {
		SiteId string `json:"site_id"`
		Url    string `json:"url"`
		Mode   int    `json:"mode"`
	}
	result := make([]interface{}, 0)
	for _, site := range siteList {

		siteJson, err := entryToSiteJson(site)
		if err == nil {

			runMode := public.GetRunMode(site.SiteID)
			if siteJson.Server.ServerName == nil || len(siteJson.Server.ServerName) == 0 {
				continue
			}
			if siteJson.Server.ServerName[0] == "_" {
				continue
			}
			serverName := siteJson.Server.ServerName[0]
			if strings.HasPrefix(serverName, "*.") {
				serverName = strings.Replace(serverName, "*.", "", 1)
			}
			if serverName == "" {
				continue
			}
			addData := SimulateAttack{
				SiteId: site.SiteID,
				Url:    "http://" + serverName + "/?id=ls /etc/passwd",
				Mode:   runMode,
			}
			result = append(result, addData)
		}

	}
	return core.Success(result)
}

func (w *Wafrules) SetCrawlerInfos(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"encryption", "watermark", "site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	crawler := Crawler{}
	crawler.Encryption.Open = params["encryption"].(map[string]interface{})["open"].(bool)
	crawler.Encryption.Type = params["encryption"].(map[string]interface{})["type"].(string)
	crawler.Encryption.Text = params["encryption"].(map[string]interface{})["text"].(string)
	crawler.Watermark.Open = params["watermark"].(map[string]interface{})["open"].(bool)
	crawler.Watermark.Type = params["watermark"].(map[string]interface{})["type"].(string)
	crawler.Watermark.Text = params["watermark"].(map[string]interface{})["text"].(string)

	if crawler.Encryption.Type != "default" && crawler.Encryption.Type != "text" {
		return core.Fail("加密类型错误")
	}

	if crawler.Watermark.Type != "default" && crawler.Watermark.Type != "text" {
		return core.Fail("水印类型错误")
	}

	jsonData, err := public.ReadInterfaceFileBytes(SiteConfig)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["crawler"] = crawler
	} else {
		return core.Fail("站点ID不存在")
	}

	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	return core.Success("操作成功")
}

func (w *Wafrules) SetCcRulesWait(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "open", "wait"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	open := public.InterfaceToBool(params["open"].(interface{}))

	wait := Wait{}
	wait.Open = params["wait"].(map[string]interface{})["open"].(bool)
	wait.Time = params["wait"].(map[string]interface{})["time"].(float64)
	wait.Qps = params["wait"].(map[string]interface{})["qps"].(float64)
	wait.User = params["wait"].(map[string]interface{})["user"].(float64)
	wait.Type = params["wait"].(map[string]interface{})["type"].(string)
	wait.Text = params["wait"].(map[string]interface{})["text"].(string)

	if wait.Type != "default" && wait.Type != "text" {
		return core.Fail("等待室类型错误")
	}

	if wait.Time < 1 {
		return core.Fail("等待时间必须大于1")
	}

	if wait.User < 1 {
		return core.Fail("用户数必须大于1")
	}

	if wait.Qps < 0 {
		return core.Fail("QPS必须大于0")
	}

	jsonData, err := public.ReadInterfaceFileBytes(SiteConfig)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		accessCc := jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"].(map[string]interface{})
		accessCc["open"] = open

		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"] = accessCc

		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["wait"] = wait

	}
	err = public.WriteSiteConfig(jsonData)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	return core.Success("操作成功")

}

func (w *Wafrules) GetUserLimit(request *http.Request) core.Response {

	nulljsonData := make([]interface{}, 0)
	var err error

	userLimit := WafPath + "/rule/limit.json"

	if !public.FileExists(userLimit) {
		return core.Success(nulljsonData)
	}

	jsonData, err := public.ReadInterfaceFileBytes(userLimit)
	if err != nil {
		return core.Success(nulljsonData)
	}
	return core.Success(jsonData)
}

type UserLimit struct {
	Name      string         `json:"name"`
	Site      map[string]int `json:"site"`
	Types     string         `json:"types"`
	Url       string         `json:"url"`
	Condition int            `json:"condition"`
	Return    string         `json:"return"`
	Status    int            `json:"status"`
	Id        string         `json:"id"`
	Open      bool           `json:"open"`
	Region    struct {
		Req   int `json:"req,omitempty"`
		Count struct {
			Time  int `json:"time,omitempty"`
			Count int `json:"count,omitempty"`
		} `json:"count,omitempty"`
	} `json:"region"`
	Action string `json:"action"`
}

func (w *Wafrules) AddUserLimit(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"name", "site", "types", "url", "condition", "region", "action"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	if public.InterfaceToString(params["site"].(interface{})) == "" {
		return core.Fail("site不能为空")
	}
	siteList := strings.Split(public.InterfaceToString(params["site"].(interface{})), ",")
	if len(siteList) == 0 {
		return core.Fail("site不能为空")
	}
	userLimit := UserLimit{}
	userLimit.Name = public.InterfaceToString(params["name"].(interface{}))
	userLimit.Types = public.InterfaceToString(params["types"].(interface{}))
	userLimit.Url = public.InterfaceToString(params["url"].(interface{}))
	userLimit.Condition = public.InterfaceToInt(params["condition"].(interface{}))
	userLimit.Action = public.InterfaceToString(params["action"].(interface{}))

	if userLimit.Action != "status" && userLimit.Action != "content" && userLimit.Action != "drop" && userLimit.Action != "status_404" && userLimit.Action != "status_403" && userLimit.Action != "status_502" && userLimit.Action != "status_503" {
		return core.Fail("操作选项设置错误")
	}
	var regFlag = false
	if _, ok := params["region"].(map[string]interface{})["req"]; ok {

		regFlag = true
		userLimit.Region.Req = public.InterfaceToInt(params["region"].(map[string]interface{})["req"].(interface{}))
	}
	var countFlag = false
	if _, ok := params["region"].(map[string]interface{})["count"]; ok {
		countFlag = true

		if _, ok := params["region"].(map[string]interface{})["count"].(map[string]interface{})["time"]; !ok {
			return core.Fail("时间访问限制-时间不能小于30秒")
		}
		if _, ok := params["region"].(map[string]interface{})["count"].(map[string]interface{})["count"]; !ok {
			return core.Fail("时间访问限制次数不能小于20次")
		}
		userLimit.Region.Count.Time = public.InterfaceToInt(params["region"].(map[string]interface{})["count"].(map[string]interface{})["time"].(interface{}))
		userLimit.Region.Count.Count = public.InterfaceToInt(params["region"].(map[string]interface{})["count"].(map[string]interface{})["count"].(interface{}))
	}

	if !regFlag && !countFlag {
		return core.Fail("请选择一个限制方式")
	}

	if userLimit.Action == "status_503" || userLimit.Action == "status_502" || userLimit.Action == "status_403" || userLimit.Action == "status_404" || userLimit.Action == "drop" {
		userLimit.Return = "html"
	}

	if userLimit.Return == "" {
		return core.Fail("返回内容不能为空")
	}

	if userLimit.Types != "all" && userLimit.Types != "url" {
		return core.Fail("请选择一个路径类型")
	}

	if userLimit.Types == "all" {
		userLimit.Url = "/"
	}

	if strings.Contains(userLimit.Name, "<") || strings.Contains(userLimit.Name, ">") || strings.Contains(userLimit.Name, "\"") {
		return core.Fail("名称不能包含特殊字符")
	}

	if userLimit.Types == "url" {

		if len(userLimit.Url) == 0 || userLimit.Url == "" || userLimit.Url == " " {
			return core.Fail("参数错误,url不能为空")
		}
		if userLimit.Url == "/" {
			return core.Fail("指定URL不能为 /  不然会全站都会限流")
		}
		if !strings.HasPrefix(userLimit.Url, "/") {
			return core.Fail("参数错误,url必须以/开头")
		}
	}

	if regFlag && userLimit.Region.Req < 1 {
		return core.Fail("每秒访问限制-请求数不能小于1")
	}
	if countFlag {

		if userLimit.Region.Count.Time < 1 {
			return core.Fail("时间访问限制-时间不能小于30秒")
		}

		if userLimit.Region.Count.Count < 1 {
			return core.Fail("时间访问限制次数不能小于20次")
		}
	}

	if userLimit.Condition != 1 && userLimit.Condition != 2 && userLimit.Condition != 3 {
		return core.Fail("访问限制条件错误")
	}
	userLimit.Status = 403
	userLimit.Id = public.RandomStr(16)
	userLimit.Open = true

	if userLimit.Return != "html" && userLimit.Return != "json" && userLimit.Return != "444" {
		return core.Fail("返回内容错误类型错误")
	}
	userLimit.Site = make(map[string]int)

	for _, v := range siteList {
		if v == "" {
			continue
		}
		userLimit.Site[v] = 1
	}

	userLimitPath := WafPath + "/rule/limit.json"
	FileBytes, err := public.ReadFileBytes(userLimitPath)
	if err != nil {
		nulljsonData := make([]interface{}, 0)
		nulljsonData = append(nulljsonData, userLimit)
		marshal, _ := json.Marshal(nulljsonData)
		public.WriteFile(userLimitPath, string(marshal))
		return core.Success("添加成功")
	}

	var userLimitList []UserLimit
	err = json.Unmarshal(FileBytes, &userLimitList)
	if err != nil {
		nulljsonData := make([]interface{}, 0)
		nulljsonData = append(nulljsonData, userLimit)
		marshal, _ := json.Marshal(nulljsonData)
		public.WriteFile(userLimitPath, string(marshal))
		return core.Success("添加成功")
	}

	for _, v := range userLimitList {

		if v.Name == userLimit.Name {
			return core.Fail("名称已存在")
		}

		if v.Site["allsite"] == 1 && userLimit.Site["allsite"] == 1 {
			if v.Types == userLimit.Types && v.Url == userLimit.Url {

				return core.Fail("此条规则已经存在")
			}
		}
		tmp := 0

		if len(siteList) == len(v.Site) {
			for _, v2 := range siteList {
				if v2 == "" {
					continue
				}
				if v.Site[v2] == 1 {
					tmp += 1
				}
			}

			if tmp == len(siteList) {
				if v.Types == userLimit.Types && v.Url == userLimit.Url {
					return core.Fail("此条规则已经存在")
				}
			}
		}
	}

	userLimitList = append(userLimitList, userLimit)
	marshal, _ := json.Marshal(userLimitList)
	public.WriteFile(userLimitPath, string(marshal))

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("添加流量限制成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("添加成功")
}

func (w *Wafrules) EditUserLimit(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"id", "name", "site", "types", "url", "condition", "region", "action"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	id := public.InterfaceToString(params["id"].(string))
	userLimitPath := WafPath + "/rule/limit.json"
	FileBytes, err := public.ReadFileBytes(userLimitPath)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var userLimitList []UserLimit
	err = json.Unmarshal(FileBytes, &userLimitList)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var Idflag = false
	for _, v := range userLimitList {
		if v.Id == id {
			Idflag = true
		}
	}
	if !Idflag {
		return core.Success("没有此条规则")
	}

	if public.InterfaceToString(params["site"].(interface{})) == "" {
		return core.Fail("site不能为空")
	}

	siteList := strings.Split(public.InterfaceToString(params["site"].(interface{})), ",")

	if len(siteList) == 0 {
		return core.Fail("site不能为空")
	}
	userLimit := UserLimit{}
	userLimit.Name = public.InterfaceToString(params["name"].(interface{}))
	userLimit.Types = public.InterfaceToString(params["types"].(interface{}))
	userLimit.Url = public.InterfaceToString(params["url"].(interface{}))
	userLimit.Condition = public.InterfaceToInt(params["condition"].(interface{}))
	userLimit.Action = public.InterfaceToString(params["action"].(interface{}))

	if userLimit.Action != "status" && userLimit.Action != "content" && userLimit.Action != "drop" && userLimit.Action != "status_404" && userLimit.Action != "status_403" && userLimit.Action != "status_502" && userLimit.Action != "status_503" {
		return core.Fail("操作选项设置错误")
	}

	var regFlag = false
	if _, ok := params["region"].(map[string]interface{})["req"]; ok {

		regFlag = true
		userLimit.Region.Req = public.InterfaceToInt(params["region"].(map[string]interface{})["req"].(interface{}))
	}
	var countFlag = false
	if _, ok := params["region"].(map[string]interface{})["count"]; ok {
		countFlag = true

		if _, ok := params["region"].(map[string]interface{})["count"].(map[string]interface{})["time"]; !ok {
			return core.Fail("时间访问限制-时间不能小于30秒")
		}
		if _, ok := params["region"].(map[string]interface{})["count"].(map[string]interface{})["count"]; !ok {
			return core.Fail("时间访问限制次数不能小于20次")
		}
		userLimit.Region.Count.Time = public.InterfaceToInt(params["region"].(map[string]interface{})["count"].(map[string]interface{})["time"].(interface{}))
		userLimit.Region.Count.Count = public.InterfaceToInt(params["region"].(map[string]interface{})["count"].(map[string]interface{})["count"].(interface{}))
	}

	if !regFlag && !countFlag {
		return core.Fail("请选择一个限制方式")
	}

	if userLimit.Action == "status_503" || userLimit.Action == "status_502" || userLimit.Action == "status_403" || userLimit.Action == "status_404" || userLimit.Action == "drop" {
		userLimit.Return = "html"
	}

	if userLimit.Return == "" {
		return core.Fail("返回内容不能为空")
	}

	if userLimit.Types != "all" && userLimit.Types != "url" {
		return core.Fail("请选择一个路径类型")
	}

	if userLimit.Types == "all" {
		userLimit.Url = "/"
	}

	if strings.Contains(userLimit.Name, "<") || strings.Contains(userLimit.Name, ">") || strings.Contains(userLimit.Name, "\"") {
		return core.Fail("名称不能包含特殊字符")
	}

	if userLimit.Types == "url" {

		if len(userLimit.Url) == 0 || userLimit.Url == "" || userLimit.Url == " " {
			return core.Fail("参数错误,url不能为空")
		}
		if userLimit.Url == "/" {
			return core.Fail("指定URL不能为 /  不然会全站都会限流")
		}
		if !strings.HasPrefix(userLimit.Url, "/") {
			return core.Fail("参数错误,url必须以/开头")
		}
	}

	if regFlag && userLimit.Region.Req < 1 {
		return core.Fail("每秒访问限制-请求数不能小于1")
	}
	if countFlag {

		if userLimit.Region.Count.Time < 1 {
			return core.Fail("时间访问限制-时间不能小于30秒")
		}

		if userLimit.Region.Count.Count < 1 {
			return core.Fail("时间访问限制次数不能小于20次")
		}
	}

	if userLimit.Condition != 1 && userLimit.Condition != 2 && userLimit.Condition != 3 {
		return core.Fail("访问限制条件错误")
	}
	userLimit.Site = make(map[string]int)

	for _, v := range siteList {
		if v == "" {
			continue
		}
		userLimit.Site[v] = 1
	}

	for _, v := range userLimitList {
		if v.Id == id {
			continue
		}

		if v.Name == userLimit.Name {
			return core.Fail("名称已经被其他规则使用")
		}

		if v.Site["allsite"] == 1 && userLimit.Site["allsite"] == 1 {
			if v.Types == userLimit.Types && v.Url == userLimit.Url {

				return core.Fail("此条规则已经存在")
			}
		}
		tmp := 0

		if len(siteList) == len(v.Site) {
			for _, v2 := range siteList {
				if v2 == "" {
					continue
				}
				if v.Site[v2] == 1 {
					tmp += 1
				}
			}

			if tmp == len(siteList) {
				if v.Types == userLimit.Types && v.Url == userLimit.Url {
					return core.Fail("此条规则已经存在")
				}
			}
		}
	}

	for k, v := range userLimitList {
		if v.Id == id {
			userLimitList[k].Name = userLimit.Name
			userLimitList[k].Types = userLimit.Types
			userLimitList[k].Url = userLimit.Url
			userLimitList[k].Condition = userLimit.Condition
			userLimitList[k].Action = userLimit.Action
			userLimitList[k].Region = userLimit.Region
			userLimitList[k].Return = userLimit.Return
			userLimitList[k].Site = userLimit.Site
		}
	}
	marshal, _ := json.Marshal(userLimitList)
	public.WriteFile(userLimitPath, string(marshal))

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("修改流量限制成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("修改成功")

}

func (w *Wafrules) DelUserLimit(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	id := public.InterfaceToString(params["id"].(string))
	userLimitPath := WafPath + "/rule/limit.json"
	FileBytes, err := public.ReadFileBytes(userLimitPath)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var userLimitList []UserLimit
	err = json.Unmarshal(FileBytes, &userLimitList)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var Idflag = false
	for _, v := range userLimitList {
		if v.Id == id {
			Idflag = true
		}
	}
	if !Idflag {
		return core.Success("没有此条规则")
	}

	for k, v := range userLimitList {
		if v.Id == id {
			userLimitList = append(userLimitList[:k], userLimitList[k+1:]...)
			break
		}
	}
	marshal, _ := json.Marshal(userLimitList)
	public.WriteFile(userLimitPath, string(marshal))

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("删除流量限制成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("删除成功")
}

func (w *Wafrules) SetUserLimit(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	id := public.InterfaceToString(params["id"].(string))
	userLimitPath := WafPath + "/rule/limit.json"
	FileBytes, err := public.ReadFileBytes(userLimitPath)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var userLimitList []UserLimit
	err = json.Unmarshal(FileBytes, &userLimitList)
	if err != nil {
		return core.Success("没有此条规则")
	}

	var Idflag = false
	for _, v := range userLimitList {
		if v.Id == id {
			Idflag = true
		}
	}
	if !Idflag {
		return core.Success("没有此条规则")
	}

	for k, v := range userLimitList {
		if v.Id == id {

			userLimitList[k].Open = !userLimitList[k].Open
			break
		}
	}
	marshal, _ := json.Marshal(userLimitList)
	public.WriteFile(userLimitPath, string(marshal))

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.BackupWebWafConfig()

	public.WriteOptLog(fmt.Sprintf("设置流量限制开关成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("设置成功")

}
