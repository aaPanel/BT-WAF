package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	updateLock = sync.RWMutex{}
)

func init() {
	core.RegisterModule(&Nginx{})
}

type Nginx struct{}

func (n *Nginx) CreateSite(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"privkey", "fullchain", "sitename", "polling_algorithm", "cdn", "ip_list", "domain", "is_https", "host"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	domain := public.InterfaceArray_To_StringArray(params["domain"].([]interface{}))
	ip_list := public.InterfaceArray_To_StringArray(params["ip_list"].([]interface{}))
	sitename := public.InterfaceToString(params["sitename"].(interface{}))
	is_https := public.InterfaceToBool(params["is_https"].(interface{}))
	fullchain := public.InterfaceToString(params["fullchain"].(interface{}))
	privkey := public.InterfaceToString(params["privkey"].(interface{}))
	cdn := public.InterfaceToBool(params["cdn"].(interface{}))
	polling_algorithm := public.InterfaceToString(params["polling_algorithm"].(interface{}))
	hostStr := public.InterfaceToString(params["host"].(interface{}))
	if hostStr == "" {
		hostStr = "$host"
	}
	err = public.AddSite(domain, ip_list, sitename, is_https, fullchain, privkey, cdn, polling_algorithm, hostStr)
	if err != nil {
		return core.Fail(err)
	}
	index := strings.Index(public.InterfaceToString(sitename), ":")
	if strings.Contains(sitename, ":") {
		portInt := sitename[index+1:]
		err := public.AllowPort(portInt)
		if err != nil {
			return core.Fail(err)
		}
	}
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("添加"+sitename+"网站成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("网站创建成功")

}

func (n *Nginx) ModifySite(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "sitename", "cdn", "polling_algorithm", "domain", "ip_list", "is_https", "privkey", "fullchain"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	domain := public.InterfaceArray_To_StringArray(params["domain"].([]interface{}))
	ip_list := public.InterfaceArray_To_StringArray(params["ip_list"].([]interface{}))
	sitename := public.InterfaceToString(params["sitename"].(interface{}))
	is_https := public.InterfaceToBool(params["is_https"].(interface{}))
	fullchain := public.InterfaceToString(params["fullchain"].(interface{}))
	privkey := public.InterfaceToString(params["privkey"].(interface{}))
	cdn := public.InterfaceToBool(params["cdn"].(interface{}))
	polling_algorithm := public.InterfaceToString(params["polling_algorithm"].(interface{}))
	site_id := public.InterfaceToString(params["site_id"].(interface{}))
	isRestore, err := public.ModifySiteJson(site_id, domain, ip_list, sitename, is_https, fullchain, privkey, cdn, polling_algorithm, "")
	if err != nil {
		if isRestore {
			public.RestoreSite(site_id)
			if err != nil {
				logging.Debug("回源配置失败，恢复站点配置失败")
			}
		}
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("编辑"+sitename+"网站成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("编辑网站成功")

}

func (n *Nginx) DeleteSite(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	err = public.DeleteSite(siteId)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("删除"+siteName+"网站成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("删除成功")

}

func (n *Nginx) ModifySiteInfo(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "site_name"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	newSiteName := public.InterfaceToString(params["site_name"].(interface{}))
	oldSiteName, _ := public.GetSiteNameBySiteId(siteId)

	err = public.ModifySiteName(siteId, newSiteName)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("修改网站名称"+oldSiteName+"为"+newSiteName+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("操作成功")

}

func (n *Nginx) GetSites(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"p", "p_size"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	p := public.InterfaceToInt(params["p"].(interface{}))
	pSize := public.InterfaceToInt(params["p_size"].(interface{}))
	searchStr := public.InterfaceToString(params["search"].(interface{}))
	siteinfos := public.GetSitesInfo(searchStr)
	return core.Success(public.PaginateData(siteinfos, p, pSize))

}

func (n *Nginx) DeployCert(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "ssl_name"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	sslName := public.InterfaceToString(params["ssl_name"].(interface{}))
	if sslName == "" || siteId == "" {
		return core.Fail("参数错误")
	}
	isRestore, err := public.DeployCert(siteId, sslName)
	if err != nil {
		if isRestore {
			public.RestoreSite(siteId)
			if err != nil {
				logging.Debug("回源配置失败，恢复站点配置失败")
			}
		}
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("证书夹部署"+sslName+"证书到"+siteName+"站点成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("部署成功")

}

func (n *Nginx) ModifyProxyinfo(request *http.Request) core.Response {

	params := struct {
		SiteId               string `json:"site_id"`
		ProxyConnectTimeout  string `json:"proxy_connect_timeout"`
		ProxySendTimeout     string `json:"proxy_send_timeout"`
		ProxyReadTimeout     string `json:"proxy_read_timeout"`
		ClientMaxBodySize    string `json:"client_max_body_size"`    //
		ClientBodyBufferSize string `json:"client_body_buffer_size"` //
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	siteId := params.SiteId
	count, err := public.M("site_info").Where("site_id=?", siteId).Count()
	if err != nil {
		return core.Fail(err)
	}
	if count == 0 {
		return core.Fail("网站不存在")
	}

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	err = public.BackupFile([]string{public.SiteJsonPath + siteId + ".json", public.VhostPath + siteId + ".conf"}, "", "")
	if err != nil {
		return core.Fail(err)
	}
	data, err := public.GetSiteJson(siteId)
	if err != nil {
		return core.Fail(err)
	}

	if err != nil {
		defer public.RestoreFile([]string{public.SiteJsonPath + siteId + ".json", public.VhostPath + siteId + ".conf"})
		return core.Fail(err)
	}
	data.ProxyInfo.ProxyConnectTimeout = params.ProxyConnectTimeout
	data.ProxyInfo.ProxySendTimeout = params.ProxySendTimeout
	data.ProxyInfo.ProxyReadTimeout = params.ProxyReadTimeout
	data.Client.MaxBodySize = params.ClientMaxBodySize

	jsonStr, err := json.Marshal(data)
	if err != nil {
		defer public.RestoreFile([]string{public.SiteJsonPath + siteId + ".json", public.VhostPath + siteId + ".conf"})
		return core.Fail(err)
	}
	boolV, err := public.WriteFile(public.SiteJsonPath+siteId+".json", string(jsonStr))
	if !boolV {
		return core.Fail("写入json配置文件失败")
	}
	upsteamConf, _ := public.AddNginxUpstreamConf(siteId)
	public.AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		defer public.RestoreFile([]string{public.SiteJsonPath + siteId + ".json", public.VhostPath + siteId + ".conf"})
		return core.Fail("重载nginx失败")
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("网站"+siteName+"修改常用参数配置成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("网站" + siteName + "修改常用参数配置成功")

}

func (n *Nginx) DeleteSsl(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"ssl_name"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	sslName := public.InterfaceToString(params["ssl_name"].(interface{}))
	if sslName == "" {
		return core.Fail("参数错误")
	}
	err = public.DelSslInfo(sslName)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("证书夹删除"+sslName+"证书成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("删除成功")

}

func (n *Nginx) InstallCert(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"privkey", "fullchain", "site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	fullchain := public.InterfaceToString(params["fullchain"].(interface{}))
	privkey := public.InterfaceToString(params["privkey"].(interface{}))
	siteIds := public.InterfaceArray_To_StringArray(params["site_id"].([]interface{}))
	AccessSite := make([]string, 0)
	ErrorSite := make([]string, 0)
	for _, siteId := range siteIds {
		siteName, _ := public.GetSiteNameBySiteId(siteId)
		if privkey == "" || fullchain == "" || siteId == "" {
			return core.Fail("参数错误")
		}
		isRestore, err := public.InstallCert(privkey, fullchain, siteId)

		if err != nil {
			ErrorSite = append(ErrorSite, siteName)
			if isRestore {
				public.RestoreSite(siteId)
				if err != nil {
					logging.Debug(siteName + "站点SSL证书安装失败！")
				}
			}
		} else {
			AccessSite = append(AccessSite, siteName)
		}

	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	errorInfo := ""
	if len(ErrorSite) > 0 {
		errorInfo = "安装ssl证书到" + strings.Join(ErrorSite, ",") + "站点失败"
	}
	successInfo := ""
	if len(AccessSite) > 0 {
		successInfo = "安装ssl证书到" + strings.Join(AccessSite, ",") + "站点成功"
	}
	fmtInfo := ""
	if successInfo != "" {
		fmtInfo = successInfo + "</br>" + errorInfo
	} else {
		fmtInfo = errorInfo
	}

	public.WriteOptLog(fmt.Sprintf("编辑网站-"+fmtInfo), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	if successInfo == "" {
		return core.Fail(fmtInfo)
	}
	return core.Success(fmtInfo)

}

func (n *Nginx) RemoveSiteSsl(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	if siteId == "" {
		return core.Fail("参数错误")
	}
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	err = public.RemoveSiteSslInfo(siteId)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf("关闭"+siteName+"站点证书成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("关闭成功")

}

func (n *Nginx) UserConfig(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "content"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	content := public.InterfaceToString(params["content"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	err = public.ModifyUserConfigInfo(siteId, content)
	if err != nil {
		public.RemoveFile([]string{public.UserPath + "/" + siteId + ".conf"})
		public.RestoreFile([]string{public.UserPath + "/" + siteId + ".conf"})
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.WriteOptLog(fmt.Sprintf(siteName+"站点-自定义配置文件修改成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func (n *Nginx) GetUserConfig(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	site_id := public.InterfaceToString(params["site_id"].(interface{}))
	result := public.GetUserConfigInfo(site_id)
	return core.Success(result)

}

func (n *Nginx) ReturnSource(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "polling_algorithm", "host"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	pollingAlgorithm := public.InterfaceToString(params["polling_algorithm"].(interface{}))
	HostStr := public.InterfaceToString(params["host"].(interface{}))
	if pollingAlgorithm == "" || siteId == "" {
		return core.Fail("参数错误")
	}

	siteName, _ := public.GetSiteNameBySiteId(siteId)
	isRestore, err := public.SetReturnSource(siteId, pollingAlgorithm, HostStr)
	if err != nil {
		if isRestore {
			public.RestoreSite(siteId)
			if err != nil {
				logging.Debug("回源配置失败，恢复u站点配置失败")
			}
		}
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

	public.WriteOptLog(fmt.Sprintf(siteName+"网站-回源配置成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func (n *Nginx) DownloadSsl(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))

	if siteId == "" {
		return core.Fail("参数错误")
	}
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	response, err := public.DownloadSsl(siteId)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(siteName+"网站-下载ssl证书成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return response

}

func (n *Nginx) AddDomain(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "domain"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	domain := public.InterfaceArray_To_StringArray(params["domain"].([]interface{}))
	if siteId == "default_wildcard_domain_server" {
		return core.Fail("通配所有域名站点不支持添加域名，如需添加域名请新建站点")
	}
	err = public.AddDomain(domain, siteId)
	if err != nil {
		return core.Fail(err)
	}
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteName+"网站-添加域名成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func (n *Nginx) DelDomain(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "domain"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	domain := public.InterfaceArray_To_StringArray(params["domain"].([]interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	if siteId == "default_wildcard_domain_server" {
		return core.Fail("通配所有域名站点不支持删除域名，如需删除域名请删除此站点")
	}
	err = public.DelDomain(domain, siteId)
	if err != nil {
		return core.Fail(err)
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
	public.WriteOptLog(fmt.Sprintf(siteName+"网站-删除域名成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func (n *Nginx) GetDomain(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	result := public.GetDomainInfo(siteId)
	return core.Success(result)

}

func (n *Nginx) ModifyResolver(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "status", "inspection_time"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))
	inspectionTime := public.InterfaceToInt(params["inspection_time"].(interface{}))
	if status == 1 {
		sourceSlice, err := public.GetSiteReturnDomain(siteId)
		if err != nil {
			return core.Fail(err)
		}
		newDomainParse, err := public.GetDomainParse(sourceSlice)
		if err != nil {
			return core.Fail(err)
		}
		newDomainParseJson, err := json.Marshal(newDomainParse)
		if err != nil {
			return core.Fail(err)
		}
		if len(newDomainParse) == 0 {
			return core.Fail("此站点无回源域名，无法开启自动巡检回源域名解析变化")
		}
		if !public.M("site_return_domain_check").Where("site_id=?", siteId).Exists() {
			_, err = public.M("site_return_domain_check").Insert(map[string]any{"status": status, "inspection_time": inspectionTime, "site_id": siteId, "parse_info": string(newDomainParseJson)})
			if err != nil {
				return core.Fail(err)
			}
		} else {
			_, err = public.M("site_return_domain_check").Where("site_id=?", siteId).Update(map[string]any{"status": status, "inspection_time": inspectionTime, "parse_info": string(newDomainParseJson)})
			if err != nil {
				return core.Fail(err)
			}
		}
	} else {
		if public.M("site_return_domain_check").Where("site_id=?", siteId).Exists() {
			_, err = public.M("site_return_domain_check").Where("site_id=?", siteId).Delete()
			if err != nil {
				return core.Fail(err)
			}
		}
	}
	data, err := public.GetSiteJson(siteId)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(data.SiteName+"网站-回源域名地址巡检成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func (n *Nginx) DeleteAllSite(request *http.Request) core.Response {

	jsonData, err := os.ReadFile("/www/cloud_waf/nginx/conf.d/other/siteid.json")
	if err != nil {
		return core.Fail(err)
	}
	var siteId map[string]string
	err = json.Unmarshal([]byte(jsonData), &siteId)
	if err != nil {
		return core.Fail(err)
	}
	for i, _ := range siteId {
		err = public.DeleteSite(i)
		if err != nil {
			continue
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	return core.Success("删除成功")

}

func (n *Nginx) GetAllSsl(request *http.Request) core.Response {

	sslInfo := public.GetAllSslInfo()
	return core.Success(sslInfo)

}

func (n *Nginx) GetAllDomain(request *http.Request) core.Response {

	domain, err := public.GetAllDomain()
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(domain)

}

func (n *Nginx) GetRealTimeData(request *http.Request) core.Response {
	siteId, err := public.GetSiteId()
	if err != nil {
		return core.Fail(err)
	}
	var RealTimeData []public.SiteRealTimeInfo
	wg := sync.WaitGroup{}
	for i, _ := range siteId {
		wg.Add(1)
		go func(id string) {
			defer func() {
				if err := recover(); err != nil {
					logging.Error(public.PanicTrace(err))
				}
			}()

			siteInfo := public.SiteRealTimeInfo{}
			siteInfo.SiteId = id
			defer wg.Done()
			result := struct {
				Request   int64 `json:"request"`
				Intercept int64 `json:"intercept"`
				Send      int64 `json:"send"`
				Recv      int64 `json:"recv"`
			}{}
			if err := public.MapToStruct(public.GetSingleSiteAccess(id), &result); err == nil {
				updateLock.Lock()
				siteInfo.AccessNum = result.Request
				siteInfo.InterceptionNum = result.Intercept
				siteInfo.RealTimeSend = result.Send
				siteInfo.RealTimeRecv = result.Recv
				updateLock.Unlock()
			} else {
				updateLock.Lock()
				siteInfo.AccessNum = 0
				siteInfo.InterceptionNum = 0
				siteInfo.RealTimeSend = 0
				siteInfo.RealTimeRecv = 0
				updateLock.Unlock()

			}

			updateLock.Lock()
			RealTimeData = append(RealTimeData, siteInfo)
			updateLock.Unlock()
		}(i)

	}
	wg.Wait()
	return core.Success(RealTimeData)

}

func (n *Nginx) SetForceHttps(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "force_https"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	forceHttps := public.InterfaceToBool(params["force_https"].(interface{}))
	siteName, _ := public.GetSiteNameBySiteId(siteId)
	err = public.SetForceHttps(siteId, forceHttps)
	if err != nil {
		return core.Fail(err)
	}
	statusStr := "关闭"
	if forceHttps {
		statusStr = "开启"
	}
	public.WriteOptLog(fmt.Sprintf(siteName+"网站-"+statusStr+"强制https成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("设置成功")

}

func (n *Nginx) GetSslInfo(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	sslInfo := public.GetSslInfoBySiteId(siteId)

	return core.Success(sslInfo)
}

func (n *Nginx) GetSslProtocolsAndCiphers(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	result := make(map[string]interface{}, 0)
	result["ssl_protocols"] = public.GetSslProtocols()
	result["ssl_ciphers"] = public.GetSslCiphers()
	result["current_ssl_protocols"] = public.GetCurrentSslProtocols(siteId)
	result["current_ssl_ciphers"] = public.GetCurrentSslCiphers(siteId)
	return core.Success(result)

}

func (n *Nginx) SetSslProtocolsOrCiphers(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "ssl_protocols", "ssl_ciphers"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	sslProtocols := public.InterfaceArray_To_StringArray(params["ssl_protocols"].([]interface{}))
	sslCiphers := public.InterfaceToString(params["ssl_ciphers"].(interface{}))
	err = public.SetSslSecureConfig(siteId, sslCiphers, sslProtocols)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("设置"+siteId+"网站ssl加密套件为"+sslCiphers+";安全协议为"+strings.Join(sslProtocols, ",")), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("设置成功")

}

func (n *Nginx) GetSiteSetting(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	result, err := public.GetSingleSiteSetting(siteId)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := result.WafInfo["rewrite_url"]; !ok {
		result.WafInfo["rewrite_url"] = map[string]interface{}{}
	}
	return core.Success(result)

}

func (n *Nginx) GetReplaceOpen(request *http.Request) core.Response {
	params := struct {
		SiteId string `json:"site_id"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.SiteId == "" {
		return core.Fail("参数错误")
	}

	data := make(map[string]bool)
	if n.is_exist(params.SiteId) {
		data["replace_open"] = true
	} else {
		data["replace_open"] = false
	}
	return core.Success(data)
}

func (n *Nginx) is_exist(server_id string) bool {

	file_data, err := n.getSpeedData()
	if err != nil {
		return false
	}
	if _, ok := file_data[server_id]; ok {
		if file_data[server_id].(map[string]interface{})["open"].(bool) == true {
			return true
		}
		return false
	}

	return false
}

func (n *Nginx) getSpeedData() (map[string]interface{}, error) {

	json_data, err := public.ReadFile("/www/cloud_waf/nginx/conf.d/waf/rule/replacement.json")
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

func (n *Nginx) GetReturnSource(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	result, err := public.GetReturnSourceInfo(siteId)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(result)

}

func (n *Nginx) AddReturnSourceIp(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "source_ip", "polling_algorithm", "host", "max_fails", "fail_timeout", "weight", "status", "ps"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	sourceIp := public.InterfaceToString(params["source_ip"].(interface{}))
	pollingAlgorithm := public.InterfaceToString(params["polling_algorithm"].(interface{}))
	hostStr := public.InterfaceToString(params["host"].(interface{}))
	maxFails := public.InterfaceToString(params["max_fails"].(interface{}))
	failTimeout := public.InterfaceToString(params["fail_timeout"].(interface{}))
	weight := public.InterfaceToString(params["weight"].(interface{}))
	ps := public.InterfaceToString(params["ps"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))

	_, err = public.AddReturnSourceIp(siteId, pollingAlgorithm, sourceIp, hostStr, maxFails, failTimeout, weight, status, ps)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("添加"+siteId+"网站回源节点"+sourceIp+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("添加成功")

}

func (n *Nginx) ModifyReturnSourceIp(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "source_id", "source_ip", "polling_algorithm", "host", "max_fails", "fail_timeout", "weight", "status", "old_status", "ps"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	sourceIp := public.InterfaceToString(params["source_ip"].(interface{}))
	id := public.InterfaceToString(params["source_id"].(interface{}))
	pollingAlgorithm := public.InterfaceToString(params["polling_algorithm"].(interface{}))
	hostStr := public.InterfaceToString(params["host"].(interface{}))
	maxFails := public.InterfaceToString(params["max_fails"].(interface{}))
	failTimeout := public.InterfaceToString(params["fail_timeout"].(interface{}))
	weight := public.InterfaceToString(params["weight"].(interface{}))
	ps := public.InterfaceToString(params["ps"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))
	oldStatus := public.InterfaceToInt(params["old_status"].(interface{}))

	err = public.ModifyReturnSourceIp(siteId, id, pollingAlgorithm, sourceIp, hostStr, maxFails, failTimeout, weight, status, oldStatus, ps)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("编辑"+siteId+"网站回源节点"+sourceIp+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("编辑成功")
}

func (n *Nginx) DelReturnSourceIp(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"site_id", "source_id", "source_ip"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	sourceIp := public.InterfaceToString(params["source_ip"].(interface{}))
	id := public.InterfaceToString(params["source_id"].(interface{}))
	err = public.DelReturnSourceIp(siteId, id)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("删除"+siteId+"网站回源节点"+sourceIp+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("删除成功")

}

func (n *Nginx) GetAddDomainInfo(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"domains"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	domains := public.InterfaceArray_To_StringArray(params["domains"].([]interface{}))
	newDomains := make([]string, 0)
	for _, domain := range domains {
		if domain != "" {
			ReplaceHttp := public.ReplaceHttp(domain)
			newDomains = append(newDomains, ReplaceHttp)
		}
	}
	result := public.DomainCheck(newDomains)

	type resItem struct {
		types.DomainCheck
		DefaultConfig struct {
			IP      string `json:"ip"`
			Port    string `json:"port"`
			IsHTTPS bool   `json:"is_https"`
		} `json:"default_config"`
	}

	res := make([]resItem, 0)
	for _, v := range result {
		item := resItem{}
		if err = public.MapToStruct(result, &item); err != nil {
			continue
		}
		if v.SourceIPList.ExtranetIPList != nil && len(v.SourceIPList.ExtranetIPList) > 0 {
			item.DefaultConfig.IP = v.SourceIPList.ExtranetIPList[0]
		}
		if item.DefaultConfig.IP == "" && v.SourceIPList.IntranetIPList != nil && len(v.SourceIPList.IntranetIPList) > 0 {
			item.DefaultConfig.IP = v.SourceIPList.IntranetIPList[0]
		}
		item.DefaultConfig.Port = "80"
		if v.IsHTTPS {
			item.DefaultConfig.Port = "443"
		}

		item.DefaultConfig.IsHTTPS = v.IsHTTPS

		res = append(res, item)
	}
	return core.Success(result)
}

func (n *Nginx) GetDomainResponseStatus(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"url", "extranet_ip_list", "intranet_ip_list", "is_force_https", "http_protocol", "is_ssl", "is_ssl_check"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	url := public.InterfaceToString(params["url"].(interface{}))
	intranetIpList := public.InterfaceArray_To_StringArray(params["intranet_ip_list"].([]interface{}))
	extranetIpList := public.InterfaceArray_To_StringArray(params["extranet_ip_list"].([]interface{}))
	isForceHttps := public.InterfaceToBool(params["is_force_https"].(interface{}))
	httpProtocol := public.InterfaceToString(params["http_protocol"].(interface{}))
	isSsl := public.InterfaceToBool(params["is_ssl"].(interface{}))
	isSslCheck := public.InterfaceToBool(params["is_ssl_check"].(interface{}))

	result := struct {
		Status     bool   `json:"status"`
		Error      string `json:"error"`
		Resolver   int    `json:"resolver"`
		StatusCode int    `json:"status_code"`
	}{}

	result.Status = true
	result.Error = ""
	result.Resolver = 200
	result.StatusCode = 200
	if isSslCheck && !isSsl && isForceHttps {
		result.Status = false
		result.Resolver = 404
		result.Error = "源站有开启强制https，WAF站建议开启SSL，否则会导致访问404"
		return core.Fail(result)
	}

	if len(intranetIpList) == 0 && len(extranetIpList) == 0 {
		result.Status = false
		result.Error = "该源站地址可能不是防护域名所在的IP地址，请检查源站地址是否填写正确"
	}

	if isForceHttps && httpProtocol == "http" {
		result.Status = false
		result.Resolver = 301
		result.Error = "源站有开启强制https，回源协议建议设置为https，否则会导致301重定向过多"
		return core.Fail(result)
	}

	statusCode, location, err := checkStatusCodeAndLocation(url)
	result.StatusCode = statusCode
	if err != nil {
		result.Status = false
		result.Error += "；该源站地址无法访问"
		return core.Fail(result)
	}

	if statusCode < 200 || statusCode > 399 {
		if statusCode == 404 {
			result.Status = false
			result.Error += "；源站首页访问404"
			return core.Fail(result)
		}
		result.Status = false
		result.Error += "；该源站地址无法访问"
		return core.Fail(result)
	}

	statusCodeDict := map[int]any{
		301: nil,
		302: nil,
		303: nil,
		307: nil,
		308: nil,
	}
	if _, ok := statusCodeDict[statusCode]; ok && location != "" {
		urlTwo := location
		statusCode, location, err = checkStatusCodeAndLocation(urlTwo)
		if err != nil {
			result.Status = false
			result.Error += "；" + urlTwo + " 重定向域名无法访问"
			result.Resolver = 301
			return core.Fail(result)
		}
		if statusCode == 301 {
			result.Status = false
			result.Error += "；301重定向次数过多"
			result.Resolver = 301
			return core.Fail(result)
		}
	}

	if !result.Status {
		return core.Fail(result)
	}

	return core.Success(result)

}

func checkStatusCodeAndLocation(url string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*9)

	defer cancel()

	resp, err := public.RequestRaw("GET", url, 15, map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
	}, nil, false, ctx)

	if err != nil {
		return 0, "", err
	}

	return resp.StatusCode, resp.Header.Get("Location"), nil
}

func (n *Nginx) SetListenIpvSixBySite(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"listen_ipv6", "site_id"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	ListenIpv6 := public.InterfaceToBool(params["listen_ipv6"].(interface{}))
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	jsonPath := public.SiteJsonPath + siteId + ".json"
	data, err := public.GetSiteJson(siteId)
	if err != nil {
		return core.Fail(err)
	}
	err = public.BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return core.Fail(err)
	}
	data.Server.ListenIpv6 = ListenIpv6
	writeJson, err := json.Marshal(data)
	if err != nil {
		return core.Fail(err)
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return core.Fail(err)
	}

	upsteamConf, _ := public.AddNginxUpstreamConf(siteId)
	public.AddNignxJsonToConf(siteId, upsteamConf)
	err = public.ReloadNginx()
	if err != nil {
		return core.Fail(err)
	}
	statusString := "关闭"
	if ListenIpv6 {
		statusString = "开启"
	}
	public.WriteOptLog(fmt.Sprintf("网站"+siteId+"设置监听IPv6监听状态为"+statusString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("设置监听IPv6成功")

}

func (n *Nginx) CheckReturnSourceAuth(request *http.Request) core.Response {
	isBool := public.GetIsSpecifyVersion(3)
	if isBool {
		return core.Success("授权检测成功")
	}
	return core.Fail("授权检测失败")
}

func (n *Nginx) AddTcpLoadBalance(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"protocol", "listen_address", "listen_port", "max_timeout", "not_timeout", "ps", "node_info"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	protocol := public.InterfaceToString(params["protocol"].(interface{}))
	listenAddress := public.InterfaceToString(params["listen_address"].(interface{}))
	listenPort := public.InterfaceToString(params["listen_port"].(interface{}))
	maxTimeout := public.InterfaceToString(params["max_timeout"].(interface{}))
	notTimeout := public.InterfaceToString(params["not_timeout"].(interface{}))
	ps := public.InterfaceToString(params["ps"].(interface{}))
	tmpNodeInfo := params["node_info"].([]interface{})
	nodeInfos := make([]types.LoadNodeInfo, len(tmpNodeInfo))
	for i, item := range tmpNodeInfo {
		if m, ok := item.(map[string]interface{}); ok {
			if !validate.IsPort(m["node_port"].(string)) {
				return core.Fail("目标端口不正确")
			}
			if !public.IsIpAddr(m["node_address"].(string)) {
				return core.Fail("目标主机地址不正确")
			}
			nodeInfo := types.LoadNodeInfo{
				NodeAddress:       m["node_address"].(string),
				NodePort:          m["node_port"].(string),
				Weight:            m["node_weight"].(string),
				MaxFails:          m["node_max_fails"].(string),
				FailTimeout:       m["node_fail_timeout"].(string),
				Status:            m["node_status"].(string),
				Ps:                m["ps"].(string),
				NodeAddressFollow: m["node_address_follow"].(bool),
				AddTime:           time.Now().Unix(),
				Count:             0,
				CountTime:         0,
			}
			nodeInfos[i] = nodeInfo
		}
	}
	if !validate.IsPort(listenPort) {
		return core.Fail("waf服务端口不正确")
	}

	if !public.CheckPort(public.StringToInt(listenPort)) {
		return core.Fail("waf服务端口已被占用")
	}
	_, err = public.AddTcpLoadBalance(protocol, listenAddress, listenPort, maxTimeout, notTimeout, ps, nodeInfos)
	if err != nil {
		return core.Fail(err)
	}

	public.WriteOptLog(fmt.Sprintf("添加【"+listenPort+"】端口的端口转发成功"), public.OPT_LOG_TYPE_PORT_FORWARD, public.GetUid(request))
	return core.Success("添加【" + listenPort + "】端口的端口转发成功")

}

func (n *Nginx) ModifyTcpLoadBalance(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"load_balance_name", "load_info"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}

	loadBalanceName := public.InterfaceToString(params["load_balance_name"].(interface{}))
	if _, ok := params["load_info"].(map[string]interface{}); !ok {
		return core.Fail("参数错误")
	}
	jsonData, err := json.Marshal(params["load_info"].(map[string]interface{}))
	if err != nil {
		return core.Fail(err)
	}

	loadInfoString := string(jsonData)
	var LoadInfoMap types.SingleTcpLoadBalance
	err = json.Unmarshal([]byte(loadInfoString), &LoadInfoMap)
	if err != nil {
		return core.Fail(err)
	}
	sourceLoadStr, err := public.ReadTcpLoadJsonFile(public.NginxJsonPath + "/nginx.json")
	if err != nil {
		return core.Fail(err)
	}
	cmd := ""
	if _, ok := sourceLoadStr.TcpLoadBalance[loadBalanceName]; ok {
		m := sourceLoadStr.TcpLoadBalance[loadBalanceName]
		m.ListenAddress = LoadInfoMap.ListenAddress

		m.Protocol = LoadInfoMap.Protocol

		m.MaxTimeout = LoadInfoMap.MaxTimeout
		m.NotTimeout = LoadInfoMap.NotTimeout
		m.Ps = LoadInfoMap.Ps
		sourcePort := sourceLoadStr.TcpLoadBalance[loadBalanceName].ListenPort
		SourceProtocol := sourceLoadStr.TcpLoadBalance[loadBalanceName].Protocol
		sourceAddress := sourceLoadStr.TcpLoadBalance[loadBalanceName].ListenAddress
		if !validate.IsPort(sourcePort) {
			sourcePort = "0"
		}
		cmd = "lsof -i:" + sourcePort + " | awk 'NR>1 {print $2}' | xargs kill"
		if LoadInfoMap.ListenAddress != sourceLoadStr.TcpLoadBalance[loadBalanceName].ListenAddress {
			public.Command(cmd)
			if SourceProtocol != "udp" {
				err = public.DeletePortByProtocol(sourcePort, SourceProtocol, true)
				if err != nil {
					return core.Fail("【" + sourcePort + "】端口删除防火墙端口失败")
				}
			}
			if LoadInfoMap.ListenAddress == "0.0.0.0" {
				public.AllowPortByProtocol(sourcePort, LoadInfoMap.Protocol, true)

			}
		} else {
			if LoadInfoMap.Protocol != sourceLoadStr.TcpLoadBalance[loadBalanceName].Protocol && sourceAddress == "0.0.0.0" {
				err = public.DeletePortByProtocol(sourcePort, SourceProtocol, true)
				if err != nil {
					return core.Fail("【" + sourcePort + "】端口删除防火墙端口失败")
				}
				err = public.AllowPortByProtocol(sourcePort, LoadInfoMap.Protocol, true)
				if err != nil {
					return core.Fail("【" + sourcePort + "】端口放行防火墙端口失败")
				}
			}

		}
		for k, v := range LoadInfoMap.NodeAddressMap {
			if _, ok := m.NodeAddressMap[k]; ok {
				if !validate.IsPort(v.NodePort) {
					return core.Fail("目标端口不正确")
				}
				if !public.IsIpAddr(v.NodeAddress) {
					return core.Fail("目标主机地址不正确")
				}
				if _, ok := LoadInfoMap.NodeAddressMap[k]; ok {
					m.NodeAddressMap[k] = v
				}
			}

		}
		sourceLoadStr.TcpLoadBalance[loadBalanceName] = m
	}

	writeData, err := json.Marshal(sourceLoadStr)
	if err != nil {
		return core.Fail(err)
	}
	boolV, err := public.WriteFile(public.NginxJsonPath+"/nginx.json", string(writeData))
	if !boolV {
		return core.Fail("写入nginx.json配置文件失败")
	}

	loadStr, err := public.ReadTcpLoadJsonFile(public.NginxJsonPath + "/nginx.json")

	tcpUpstreamContent := public.AddTcpJsonToTcpUpstream(loadStr.TcpLoadBalance)
	tcpServerContent := public.AddTcpJsonToTcpServer(loadStr.TcpLoadBalance)
	tcpContent := tcpUpstreamContent + tcpServerContent
	boolV, err = public.WriteFile(public.NginxStreamPath+"/tcp.conf", tcpContent)
	if !boolV {
		return core.Fail("写入tcp.conf配置文件失败")
	}

	public.Command(cmd)
	err = public.ReloadNginx()
	if err != nil {
		return core.Fail(err)
	}
	public.Command(cmd)

	public.WriteOptLog(fmt.Sprintf("编辑【"+sourceLoadStr.TcpLoadBalance[loadBalanceName].ListenPort+"】端口的端口转发成功"), public.OPT_LOG_TYPE_PORT_FORWARD, public.GetUid(request))
	return core.Success("编辑【" + sourceLoadStr.TcpLoadBalance[loadBalanceName].ListenPort + "】端口的端口转发成功")

}

func (n *Nginx) DelTcpLoadBalance(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"load_balance_name", "is_del_port", "port"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	loadBalanceId := public.InterfaceToString(params["load_balance_name"].(interface{}))
	isDelPort := public.InterfaceToBool(params["is_del_port"].(interface{}))
	port := public.InterfaceToString(params["port"].(interface{}))
	loadBalanceContent, err := public.ReadMapStringInterfaceFile(public.NginxJsonPath + "/nginx.json")
	if !validate.IsPort(port) {
		return core.Fail("waf服务端口不正确")
	}

	if err != nil {
		return core.Fail(err)
	}
	loadBalance := make(map[string]interface{}, 0)
	if _, ok := loadBalanceContent["tcp_load_balance"]; ok {
		loadBalance = loadBalanceContent["tcp_load_balance"].(map[string]interface{})
	}

	if _, ok := loadBalance[loadBalanceId]; ok {
		isDelPort = true
		if isDelPort {
			err = public.DeletePortByProtocol(port, loadBalance[loadBalanceId].(map[string]interface{})["protocol"].(string), true)
			if err != nil {
				return core.Fail("【" + port + "】端口删除防火墙端口失败")
			}
		}
		delete(loadBalance, loadBalanceId)
		loadBalanceContent["tcp_load_balance"] = loadBalance
	}
	err = public.WriteMapStringInterfaceFile(public.NginxJsonPath+"/nginx.json", loadBalanceContent)
	if err != nil {
		return core.Fail(err)
	}
	loadStr, err := public.ReadTcpLoadJsonFile(public.NginxJsonPath + "/nginx.json")
	tcpUpstreamContent := public.AddTcpJsonToTcpUpstream(loadStr.TcpLoadBalance)
	tcpServerContent := public.AddTcpJsonToTcpServer(loadStr.TcpLoadBalance)
	tcpContent := tcpUpstreamContent + tcpServerContent
	boolV, err := public.WriteFile(public.NginxStreamPath+"/tcp.conf", tcpContent)
	if !boolV {
		return core.Fail("写入tcp.conf配置文件失败")
	}
	err = public.ReloadNginx()
	if err != nil {
		return core.Fail(err)
	}
	os.Remove(public.LogRootPath + "tcp_udp_" + loadBalanceId + ".log")
	os.Remove(public.LogRootPath + "tcp_udp_" + loadBalanceId + "error.log")
	public.WriteOptLog(fmt.Sprintf("删除【"+port+"】端口的端口转发成功"), public.OPT_LOG_TYPE_PORT_FORWARD, public.GetUid(request))
	return core.Success("删除【" + port + "】端口的端口转发成功")

}

func (n *Nginx) GetTcpLoadBalance(request *http.Request) core.Response {
	if !public.FileExists(public.NginxJsonPath + "/nginx.json") {
		return core.Success(nil)
	}
	loadBalanceContent, err := public.ReadMapStringInterfaceFile((public.NginxJsonPath + "/nginx.json"))
	if err != nil {
		return core.Fail(err)
	}
	public.PortForwardingCount()
	return core.Success(loadBalanceContent)

}

func (n *Nginx) ClearTcpLoadBalanceCount(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"load_balance_name"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	loadBalanceName := public.InterfaceToString(params["load_balance_name"].(interface{}))
	testStr, err := public.ReadTcpLoadJsonFile(public.NginxJsonPath + "/nginx.json")
	if _, ok := testStr.TcpLoadBalance[loadBalanceName]; ok {
		m := testStr.TcpLoadBalance[loadBalanceName]
		m.Count = 0
		m.CountTime = float64(time.Now().Unix())
		testStr.TcpLoadBalance[loadBalanceName] = m
	}
	writeData, err := json.Marshal(testStr)
	if err != nil {
		return core.Fail(err)
	}
	boolV, err := public.WriteFile(public.NginxJsonPath+"/nginx.json", string(writeData))
	if !boolV {
		return core.Fail("写入nginx.json配置文件失败")
	}
	public.WriteOptLog(fmt.Sprintf("端口转发清空"+loadBalanceName+"统计成功"), public.OPT_LOG_TYPE_PORT_FORWARD, public.GetUid(request))

	return core.Success("清空成功")
}

func (n *Nginx) GetSiteLog(request *http.Request) core.Response {

	params := struct {
		SiteId string  `json:"site_id"`
		Types  string  `json:"types"`
		Clear  float64 `json:"clear"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询site_id失败")
	}
	if count == 0 {
		return core.Fail("查询site_id失败")
	}

	if params.Clear == 1 {
		_, err := public.ClearSiteLog(params.SiteId, params.Types)
		if err != nil {
			return core.Fail(err)
		}
		return core.Success("清空成功")
	}

	result := public.GetSiteLogInfo(params.SiteId, params.Types)

	return core.Success(result)

}

func (n *Nginx) GetLogList(request *http.Request) core.Response {
	params := struct {
		SiteId string `json:"site_id"`
		Types  string `json:"types"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询site_id失败")
	}
	if count == 0 {
		return core.Fail("查询site_id失败")
	}
	if params.Types != "access" && params.Types != "error" {
		return core.Fail("日志类型错误")
	}
	dir_path := "/www/cloud_waf/vhost/history_backups/logs/" + params.SiteId + "/" + params.Types + "_log"
	result, _ := n.getFilesInDirectory(dir_path)
	return core.Success(result)
}

func (n *Nginx) getFilesInDirectory(dirPath string) ([]map[string]interface{}, error) {
	dir, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var fileInfos []map[string]interface{}
	for _, entry := range dir {
		if !entry.IsDir() {

			filePath := filepath.Join(dirPath, entry.Name())
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				return nil, err
			}
			info := map[string]interface{}{
				"name":      entry.Name(),
				"timestamp": fileInfo.ModTime().Unix(),
				"size":      fileInfo.Size(),
			}
			fileInfos = append(fileInfos, info)
		}
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i]["timestamp"].(int64) > fileInfos[j]["timestamp"].(int64)
	})

	return fileInfos, nil

}

func (n *Nginx) DownloadLog(request *http.Request) core.Response {
	params := struct {
		SiteId   string  `json:"site_id"`
		Types    string  `json:"types"`
		FileName string  `json:"filename"`
		Delete   float64 `json:"delete"`
		Download float64 `json:"download"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询site_id失败")
	}
	if count == 0 {
		return core.Fail("查询site_id失败")
	}
	if params.Types != "access" && params.Types != "error" {
		return core.Fail("日志类型错误")
	}

	dir_path := core.AbsPath("/www/cloud_waf/vhost/history_backups/logs/") + params.SiteId + "/" + params.Types + "_log/"
	file_name := dir_path + params.FileName
	if params.Download == 1 {
		response, err := core.DownloadFile(file_name, params.FileName)
		if err != nil {
			return core.Fail(err)
		}
		return response
	}

	if params.Delete == 1 {
		err := os.Remove(file_name)
		if err != nil {
			return core.Success("删除成功")
		}
	}

	return core.Success("操作成功")
}
