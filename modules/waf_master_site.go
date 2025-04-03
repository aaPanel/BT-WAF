package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/common"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/compress"
	"CloudWaf/public/db"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alibabacloud-go/alidns-20150109/v4/client"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

var (
	SliceSiteLogPath      = core.AbsPath("./logs/slice_site_log.log")
	WafSiteConfigJsonPath = core.AbsPath("./config/waf_site.json")
	StatusMap             = map[int64]string{0: "关闭", 1: "开启"}
)

type Wafmastersite struct{}

func init() {
	core.RegisterModule(&Wafmastersite{})
	MkdirPaths := []string{types.GlobalVhostPath, types.SslPath, types.SiteJsonPath, types.CertPath, types.BackupPath, types.ZipPath, types.HistoryBackupPath, types.HistoryBackupConfig, types.SliceSiteLogJson, types.NginxJsonPath, types.NginxStreamPath}
	for _, v := range MkdirPaths {
		if !public.FileExists(v) {
			os.MkdirAll(v, 0600)
		}
	}

}

func AllowPortBySite() {
	siteInfo, err := public.M("site_check").Field([]string{"distinct port"}).Select()
	if err != nil {
		return
	}
	if len(siteInfo) > 0 {
		ports := make([]string, 0)
		for _, v := range siteInfo {
			ports = append(ports, v["port"].(string))
		}
		public.AllowPortsByProtocol(ports, "", true)
	}
}

func (s *Wafmastersite) CreateSite(request *http.Request) core.Response {
	siteJson := types.SiteJson{}
	siteJson.Server.Location = &types.LocationList{}
	if err := core.GetParamsFromRequestToStruct(request, &siteJson); err != nil {
		return core.Fail(err)
	}
	err := error(nil)
	if len(siteJson.DomainList) != 1 || (len(siteJson.DomainList) == 1 && siteJson.DomainList[0] != "*") {
		err = ReturnDomainPortCheck(siteJson.DomainList, false, false)
		if err != nil {
			return core.Fail(err)
		}
		sourceDomains := make([]string, 0)
		for _, v := range siteJson.Server.Upstream.Server {
			sourceDomains = append(sourceDomains, v.Address)
		}
		err = ReturnDomainPortCheck(sourceDomains, true, true)
		if err != nil {
			return core.Fail(err)
		}
	}
	if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
		if siteJson.LoadGroupId != 0 {
			loadBalance, err := public.M("load_balance").Where("id=?", siteJson.LoadGroupId).Find()
			if err != nil {
				return core.Fail(fmt.Errorf("负载均衡分组不存在"))
			}
			nodes, err := TransformBack(loadBalance["nodes"].(string))
			if err != nil {
				return core.Fail(fmt.Errorf("负载均衡分组节点格式错误"))
			}
			if len(nodes) == 0 {
				return core.Fail(fmt.Errorf("负载均衡分组【" + loadBalance["load_name"].(string) + "】下没有节点"))
			}
		}
	} else {
		siteJson.LoadGroupId = 0
	}
	timestamp := time.Now().Unix()
	siteJson, err = CreateSiteJson(&siteJson)
	if err != nil {
		return core.Fail(err)
	}
	entrySiteJson, err := siteJsonToEntry(&siteJson)
	domainPortMap := make(map[string]string, 0)
	for _, server := range siteJson.Server.ServerName {
		allPorts := make(map[string]string, 0)
		for _, port := range siteJson.Server.ListenPort {
			allPorts[port] = "1"
		}
		if siteJson.Server.Ssl.IsSsl == 1 && siteJson.Server.ListenSslPort != nil {
			for _, port := range siteJson.Server.ListenSslPort {
				allPorts[port] = "1"
			}

		}
		for k, _ := range allPorts {
			domainPortMap[server+":"+k] = "1"
		}
	}

	if len(siteJson.DomainList) == 1 && siteJson.DomainList[0] == "*" {
		if public.M("site_info").Where("site_id = ?", []any{"default_wildcard_domain_server"}).Exists() {
			return core.Fail(fmt.Errorf("通配所有域名网站已经添加过"))
		}
	}
	for key, _ := range domainPortMap {
		domain, port := strings.Split(key, ":")[0], strings.Split(key, ":")[1]
		if public.M("site_check").Where("domain_string = ?", []any{domain}).Where("port = ?", []any{port}).Exists() {
			return core.Fail(fmt.Errorf("域名端口【%s】:【%s】已经添加过", domain, port))
		}
	}
	if siteJson.Server.Ssl.IsSsl == 1 {
		SslName, boolV := CheckSslInfo(siteJson.Server.Ssl.FullChain, siteJson.Server.Ssl.PrivateKey)
		if !boolV {
			return core.Fail("开启ssl证书失败，检测到错误的证书或密钥格式，请检查！")
		}
		intersection := Intersect(siteJson.Server.ListenPort, siteJson.Server.ListenSslPort)
		if len(intersection) > 0 {
			return core.Fail(fmt.Errorf("http和https不能监听重复端口【%s】", strings.Join(intersection, ",")))
		}
		err := installCert(siteJson.Server.Ssl.PrivateKey, siteJson.Server.Ssl.FullChain, siteJson.SiteID, SslName)
		if err != nil {
			return core.Fail(err)
		}
		siteJson.Server.Ssl.SslName = SslName
		certFile := types.CertPath + "/" + siteJson.SiteID + "/fullchain.pem"
		keyFile := types.CertPath + "/" + siteJson.SiteID + "/privkey.pem"
		SslInfo := GetSslInfo(certFile, keyFile)
		siteJson.Server.Ssl.SslName = SslInfo.SslName
		siteJson.Server.Ssl.Brand = SslInfo.Brand
		siteJson.Server.Ssl.NotAfter = SslInfo.NotAfter
		siteJson.Server.Ssl.Domains = SslInfo.Domains
	}

	if len(siteJson.Server.ServerName) > 1 {
		for _, server := range siteJson.Server.ServerName {
			if public.M("site_check").Where("domain_string = ?", []any{server}).Exists() {
				return core.Fail(fmt.Errorf("域名【%s】已经添加过", server))
			}
		}
		if len(siteJson.Server.ListenPort)+len(siteJson.Server.ListenSslPort) > 1 {
			if siteJson.Server.Ssl.IsSsl == 1 {
				if len(siteJson.Server.ListenPort) == 1 && (siteJson.Server.ListenPort[0] != "80" || siteJson.Server.ListenSslPort[0] != "443") {
					return core.Fail(fmt.Errorf(types.ReturnInfo, ""))
				}
			} else {
				return core.Fail(fmt.Errorf(types.ReturnInfo, ""))
			}

		}
	}

	siteInfoData := public.StructToMap(entrySiteJson)
	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		confPath := types.VhostPath + siteJson.SiteID + ".conf"
		userFile := types.UserPath + siteJson.SiteID + ".conf"
		defer func() {
			if err != nil {
				conn.Rollback()
				os.Remove(confPath)
				os.Remove(userFile)
				ReloadNginx()
				return
			}
			conn.Commit()
		}()
		err = public.WriteDomain(siteJson.DomainList, siteJson.SiteID)
		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().Table("site_info").Insert(siteInfoData)
		if err != nil {
			return nil, err
		}
		for key, _ := range domainPortMap {
			domain, port := strings.Split(key, ":")[0], strings.Split(key, ":")[1]
			entryCheckData := types.EntrySiteCheck{
				SiteId:       siteJson.SiteID,
				DomainString: domain,
				Port:         port,
				CreateTime:   timestamp,
			}
			_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))
			if err != nil {
				return nil, err
			}
		}
		cdn := false
		if siteJson.IsCDN == 1 {
			cdn = true
		}
		err = CreateWafConfigJson(siteJson.SiteID, cdn)
		if err != nil {
			return nil, err
		}
		err = ParseSiteJson(siteJson)
		if err != nil {
			return nil, err
		}
		if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
			conn, err = AddSiteSyncData(conn, siteJson.LoadGroupId, "", timestamp)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf("新建网站【"+siteJson.SiteName+"】失败： %w", err))
	}
	_ = public.AddTaskOnce(AllowPortBySite, time.Second*1)
	logString := "新建网站【" + siteJson.SiteName + "】成功"
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success(logString)

}

func StringToLower(stringSlice []string) []string {
	strLower := make([]string, 0)
	for _, v := range stringSlice {
		v = strings.ToLower(v)
		strLower = append(strLower, v)
	}
	return strLower
}

func AddSiteSyncData(conn *db.MySql, loadGroupId int64, siteId string, timestamp int64) (*db.MySql, error) {
	clusterNodes, err := public.M("cluster_nodes").Field([]string{"sid"}).Where("group_id=?", loadGroupId).Select()
	if err != nil {
		return conn, err
	}
	for _, node := range clusterNodes {
		if !public.M("wait_sync_nodes").Where("node_id=?", node["sid"].(string)).Exists() {
			_, err = conn.NewQuery().Table("wait_sync_nodes").Insert(map[string]any{"node_id": node["sid"], "site_id": siteId, "create_time": timestamp})
			if err != nil {
				return conn, err
			}
		} else {
			_, err = conn.NewQuery().Table("wait_sync_nodes").Where("node_id=?", node["sid"].(string)).Update(map[string]any{"node_id": node["sid"], "site_id": siteId, "create_time": timestamp})
			if err != nil {
				return conn, err
			}
		}
	}
	return conn, nil
}

func CreateWafConfigJson(siteId string, isCDN bool) error {

	siteConfig, err := public.Rconfigfile(WafSiteConfigJsonPath)
	if err != nil {
		return err
	}
	siteConfig["cdn"] = isCDN
	siteConfig["cc"].(map[string]interface{})["is_cc_url"] = true
	wafFiles := []string{types.WafSiteConfigPath, types.SiteWafConfigJson}
	wafConfig := make(map[string]interface{})
	if public.FileExists(types.WafSiteConfigPath) {
		wafConfig, err := public.Rconfigfile(types.WafSiteConfigPath)
		if err != nil {
			return err
		}
		GlobalRules, err := public.GetGlobalConfigRules()
		if err == nil {
			if GlobalRules.(map[string]interface{})["cc"] != nil {
				wafConfig["cc"] = GlobalRules.(map[string]interface{})["cc"]
			}
			if GlobalRules.(map[string]interface{})["number_attacks"] != nil {
				wafConfig["number_attacks"] = GlobalRules.(map[string]interface{})["number_attacks"]
			}
			if GlobalRules.(map[string]interface{})["sql"] != nil {
				wafConfig["sql"] = GlobalRules.(map[string]interface{})["sql"]
			}
			if GlobalRules.(map[string]interface{})["xss"] != nil {
				wafConfig["xss"] = GlobalRules.(map[string]interface{})["xss"]
			}
			if GlobalRules.(map[string]interface{})["ssrf"] != nil {
				wafConfig["ssrf"] = GlobalRules.(map[string]interface{})["ssrf"]
			}
			if GlobalRules.(map[string]interface{})["cookie"] != nil {
				wafConfig["cookie"] = GlobalRules.(map[string]interface{})["cookie"]
			}
			if GlobalRules.(map[string]interface{})["rce"] != nil {
				wafConfig["rce"] = GlobalRules.(map[string]interface{})["rce"]
			}
			if GlobalRules.(map[string]interface{})["file_upload"] != nil {
				wafConfig["file_upload"] = GlobalRules.(map[string]interface{})["file_upload"]
			}
			if GlobalRules.(map[string]interface{})["from_data"] != nil {
				wafConfig["from_data"] = GlobalRules.(map[string]interface{})["from_data"]
			}
			if GlobalRules.(map[string]interface{})["download"] != nil {
				wafConfig["download"] = GlobalRules.(map[string]interface{})["download"]
			}
			if GlobalRules.(map[string]interface{})["file_import"] != nil {
				wafConfig["file_import"] = GlobalRules.(map[string]interface{})["file_import"]
			}
			if GlobalRules.(map[string]interface{})["php_eval"] != nil {
				wafConfig["php_eval"] = GlobalRules.(map[string]interface{})["php_eval"]
			}
			if GlobalRules.(map[string]interface{})["scan"] != nil {
				wafConfig["scan"] = GlobalRules.(map[string]interface{})["scan"]
			}
			if GlobalRules.(map[string]interface{})["user_agent"] != nil {
				wafConfig["user_agent"] = GlobalRules.(map[string]interface{})["user_agent"]
			}

		}
		wafConfig[siteId] = siteConfig
		for _, v := range wafFiles {
			err = public.Wconfigfile(v, wafConfig)
			if err != nil {
				return err
			}
		}

	} else {
		wafConfig[siteId] = siteConfig
		for _, v := range wafFiles {
			err = public.Wconfigfile(v, wafConfig)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func escapeSpecialCharacters(str string) string {
	str = replaceString(str, "\n", "\\n")
	str = replaceString(str, "\r", "\\r")
	logging.Debug("str:\n", str)
	return str
}

func replaceString(str, old, new string) string {
	return strings.ReplaceAll(str, old, new)
}

func GetSiteJson(siteId string) (types.SiteJson, error) {
	siteJson := types.SiteJson{}
	if !public.M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
		return siteJson, fmt.Errorf("网站【%d】不存在", siteId)
	}
	query := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
		Where("site_id = ?", []any{siteId})
	result, err := query.Find()
	if err != nil {
		return siteJson, err
	}
	sourceSiteJson, err := SiteJsonToBack(result)
	if err != nil {
		return siteJson, err
	}
	return sourceSiteJson, nil
}

func (s *Wafmastersite) ModifySite(request *http.Request) core.Response {
	modifySiteJson := types.SiteJson{}
	if err := core.GetParamsFromRequestToStruct(request, &modifySiteJson); err != nil {
		return core.Fail(err)
	}
	modifyType := modifySiteJson.Types
	if !public.M("site_info").Where("site_id = ?", []any{modifySiteJson.SiteID}).Exists() {
		return core.Fail(fmt.Errorf("网站【%d】不存在", modifySiteJson.SiteID))
	}
	query := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
		Where("site_id = ?", []any{modifySiteJson.SiteID})
	result, err := query.Find()
	if err != nil {
		return core.Fail(err)
	}
	sourceSiteJson, err := SiteJsonToBack(result)
	if err != nil {
		return core.Fail(err)
	}
	timestamp := time.Now().Unix()
	sourceSiteJson.UpdateTime = timestamp
	backupSiteJson := sourceSiteJson
	if modifyType == "startStopSite" {
		sourceSiteJson.Status = modifySiteJson.Status
	}
	delPort := make([]string, 0)
	if modifyType == "closeCert" && sourceSiteJson.Server.Ssl.IsSsl == 1 && modifySiteJson.Server.Ssl.IsSsl == 0 && modifySiteJson.Server.Ssl.SSLProtocols == nil {
		sourceSiteJson, delPort, err = CloseCert(sourceSiteJson, modifySiteJson)
		if err != nil {
			return core.Fail(err)
		}
	}

	addPortBool := false
	if modifyType == "openCert" {
		sourceSiteJson, addPortBool, err = OpenCert(sourceSiteJson, modifySiteJson)
		if err != nil {
			return core.Fail(err)
		}

	}

	if modifyType == "modifyCommon" {
		sourceSiteJson.Server.ProxyInfo.ProxyConnectTimeout = modifySiteJson.Server.ProxyInfo.ProxyConnectTimeout
		sourceSiteJson.Server.ProxyInfo.ProxySendTimeout = modifySiteJson.Server.ProxyInfo.ProxySendTimeout
		sourceSiteJson.Server.ProxyInfo.ProxyReadTimeout = modifySiteJson.Server.ProxyInfo.ProxyReadTimeout
		sourceSiteJson.Server.Client.MaxBodySize = modifySiteJson.Server.Client.MaxBodySize
	}

	if modifyType == "modifySsl" && sourceSiteJson.Server.Ssl.IsSsl == 1 && modifySiteJson.Server.Ssl.SSLProtocols != nil && modifySiteJson.Server.Ssl.SSLCiphers != nil {
		sort.Strings(modifySiteJson.Server.Ssl.SSLProtocols)
		sourceSiteJson.Server.Ssl.SSLProtocols = modifySiteJson.Server.Ssl.SSLProtocols
		sourceSiteJson.Server.Ssl.SSLCiphers = modifySiteJson.Server.Ssl.SSLCiphers
	}

	if modifyType == "openForceHttps" && sourceSiteJson.Server.Ssl.ForceHttps == 0 && modifySiteJson.Server.Ssl.ForceHttps == 1 {
		if sourceSiteJson.Server.Ssl.IsSsl == 0 {
			return core.Fail(fmt.Errorf("请先开启证书"))
		}
		sourceSiteJson.Server.Ssl.ForceHttps = 1
	}
	if modifyType == "closeForceHttps" && sourceSiteJson.Server.Ssl.ForceHttps == 1 && modifySiteJson.Server.Ssl.ForceHttps == 0 {
		sourceSiteJson.Server.Ssl.ForceHttps = 0
	}
	modifyUpstreamNodeLog := ""
	if modifyType == "modifyUpstream" || modifyType == "addUpstreamNode" || modifyType == "delUpstreamNode" || modifyType == "modifyUpstreamNode" {
		sourceSiteJson, modifyUpstreamNodeLog, err = ModifyUpstream(sourceSiteJson, modifySiteJson)
		if err != nil {
			return core.Fail(err)
		}
	}
	if modifyType == "modifyUserIncludeText" && modifySiteJson.Server.UserIncludeText != "" {
		logging.Debug("modifySiteJson.Server.UserIncludeText:", modifySiteJson.Server.UserIncludeText)
		sourceSiteJson.Server.UserIncludeText = modifySiteJson.Server.UserIncludeText
	}

	if modifyType == "updateDomain" && modifySiteJson.DomainList != nil {
		sourceSiteJson, err = UpdateDomain(sourceSiteJson, modifySiteJson)
		if err != nil {
			return core.Fail(err)
		}
		sourceSiteJson.SiteName = modifySiteJson.SiteName

	}
	if modifyType == "ipv6" {
		sourceSiteJson.Server.ListenIpv6 = modifySiteJson.Server.ListenIpv6
	}
	if modifyType == "modifyLoadBalance" {
		err := error(nil)
		sourceSiteJson, err = ModifyLoadBalance(sourceSiteJson, modifySiteJson)
		if err != nil {
			return core.Fail(err)
		}

	}

	entrySiteJson, err := siteJsonToEntry(&sourceSiteJson)
	siteInfoData := public.StructToMap(entrySiteJson)
	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				err = ParseSiteJson(backupSiteJson)
				if err != nil {
					return
				}
				return
			}
			conn.Commit()
		}()
		if err != nil {
			return nil, err
		}
		if modifyType == "openCert" && addPortBool {
			timestamp := time.Now().Unix()
			for _, server := range sourceSiteJson.Server.ServerName {
				entryCheckData := types.EntrySiteCheck{
					SiteId:       sourceSiteJson.SiteID,
					DomainString: server,
					Port:         sourceSiteJson.Server.ListenSslPort[0],
					CreateTime:   timestamp,
				}
				for _, port := range sourceSiteJson.Server.ListenSslPort {
					if !public.M("site_check").Where("domain_string = ? and port = ?", []any{server, port}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
		if modifyType == "closeCert" && len(delPort) != 0 {
			for _, server := range sourceSiteJson.Server.ServerName {
				for _, port := range delPort {
					if public.M("site_check").Where("site_id = ? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Where("site_id =? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Delete()
						if err != nil {
							return nil, err
						}
					}
				}

			}

		}
		if modifyType == "updateDomain" {
			timestamp := time.Now().Unix()
			_, err = conn.NewQuery().Table("site_check").Where("site_id = ?", []any{sourceSiteJson.SiteID}).Delete()
			if err != nil {
				return nil, err
			}
			for _, server := range sourceSiteJson.Server.ServerName {
				for _, port := range sourceSiteJson.Server.ListenPort {
					entryCheckData := types.EntrySiteCheck{
						SiteId:       sourceSiteJson.SiteID,
						DomainString: server,
						Port:         port,
						CreateTime:   timestamp,
					}
					if !public.M("site_check").Where("site_id = ? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))
						if err != nil {
							return nil, err
						}
					}
				}
				for _, port := range sourceSiteJson.Server.ListenSslPort {
					entryCheckData := types.EntrySiteCheck{
						SiteId:       sourceSiteJson.SiteID,
						DomainString: server,
						Port:         port,
						CreateTime:   timestamp,
					}
					if !public.M("site_check").Where("site_id = ? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))
						if err != nil {
							return nil, err
						}
					}
				}

			}

		}
		if modifyType == "delDomain" && modifySiteJson.DomainList != nil {
			sourceSiteJson, conn, err = DelDomain(conn, sourceSiteJson, modifySiteJson)
			if err != nil {
				return nil, err
			}
			entrySiteJson, _ := siteJsonToEntry(&sourceSiteJson)
			siteInfoData = public.StructToMap(entrySiteJson)
		}
		err = ParseSiteJson(sourceSiteJson)
		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().Table("site_info").Where("site_id = ?", []any{sourceSiteJson.SiteID}).Update(siteInfoData)

		if err != nil {
			return nil, err
		}
		if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
			conn, err = AddSiteSyncData(conn, sourceSiteJson.LoadGroupId, "", timestamp)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf("编辑网站【"+sourceSiteJson.SiteName+"】失败： %w", err))
	}
	_ = public.AddTaskOnce(AllowPortBySite, time.Second*1)
	logString := ""
	switch modifyType {
	case "startStopSite":
		logString = "网站【" + sourceSiteJson.SiteName + "】" + StatusMap[modifySiteJson.Status]
	case "closeCert":
		logString = "网站【" + sourceSiteJson.SiteName + "】关闭证书"
	case "openCert":
		logString = "网站【" + sourceSiteJson.SiteName + "】开启证书"
	case "modifySsl":
		logString = "网站【" + sourceSiteJson.SiteName + "】修改ssl安全配置加密套件为【" + strings.Join(sourceSiteJson.Server.Ssl.SSLCiphers, ",") + "】安全协议为【" + strings.Join(sourceSiteJson.Server.Ssl.SSLProtocols, ",") + "】"
	case "openForceHttps":
		logString = "网站【" + sourceSiteJson.SiteName + "】开启强制https"
	case "closeForceHttps":
		logString = "网站【" + sourceSiteJson.SiteName + "】关闭强制https"
	case "modifyUpstream":
		logString = "网站【" + sourceSiteJson.SiteName + "】回源配置负载方式为【" + sourceSiteJson.Server.Upstream.PollingAlgorithm + "】 发送域名为【" + sourceSiteJson.Server.Upstream.Host + "源站协议为【" + sourceSiteJson.Server.Upstream.SourceProtocol + "】"
	case "addUpstreamNode":
		logString = "网站【" + sourceSiteJson.SiteName + "】添加回源节点【" + modifySiteJson.Server.Upstream.Server[0].Address + "】"
	case "delUpstreamNode":
		logString = "网站【" + sourceSiteJson.SiteName + "】回源配置" + modifyUpstreamNodeLog
	case "modifyUpstreamNode":
		logString = "网站【" + sourceSiteJson.SiteName + "】回源配置" + modifyUpstreamNodeLog
	case "ipv6":
		if sourceSiteJson.Server.ListenIpv6 == 1 {
			logString = "网站【" + sourceSiteJson.SiteName + "】开启监听ipv6"
		} else {
			logString = "网站【" + sourceSiteJson.SiteName + "】关闭监听ipv6"
		}
	case "updateDomain":
		logString = "网站【" + sourceSiteJson.SiteName + "】更新域名管理信息【防护域名：" + strings.Join(modifySiteJson.DomainList, ",") + ";HTTP端口:" + strings.Join(modifySiteJson.Server.ListenPort, ",") + ";HTTPS端口:" + strings.Join(modifySiteJson.Server.ListenSslPort, ",") + ";网站域名：" + modifySiteJson.SiteName + "】"
	case "delDomain":
		logString = "网站【" + sourceSiteJson.SiteName + "】删除域名【" + strings.Join(modifySiteJson.DomainList, ",") + "】"
	case "modifyUserIncludeText":
		logString = "网站【" + sourceSiteJson.SiteName + "】修改自定义配置"
	case "modifyLoadBalance":
		loadName := ""
		loadGroupInfo, err := public.M("load_balance").Field([]string{"load_name"}).Where("id=?", sourceSiteJson.LoadGroupId).Find()
		if err == nil {
			loadName = loadGroupInfo["load_name"].(string)
		}
		logString = "网站【" + sourceSiteJson.SiteName + "】修改负载均衡分组为【" + public.InterfaceToString(sourceSiteJson.LoadGroupId) + "--" + loadName + "】"
	case "modifyCommon":
		logString = "网站【" + sourceSiteJson.SiteName + "】修改常用参数配置"
	}
	if err != nil {
		return core.Fail(fmt.Errorf(logString+"失败： %w", err))
	}
	public.WriteOptLog(fmt.Sprintf(logString+"成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("设置成功！")
}

func ModifyLoadBalance(sourceSiteJson, modifySiteJson types.SiteJson) (types.SiteJson, error) {
	loadBalance, err := public.M("load_balance").Where("id=?", modifySiteJson.LoadGroupId).Find()
	if err != nil {
		return sourceSiteJson, fmt.Errorf("负载均衡分组不存在")
	}
	nodes, err := TransformBack(loadBalance["nodes"].(string))
	if err != nil {
		return sourceSiteJson, fmt.Errorf("负载均衡分组节点格式错误")
	}
	if len(nodes) == 0 {
		return sourceSiteJson, fmt.Errorf("负载均衡分组【" + loadBalance["load_name"].(string) + "】下没有节点")
	}
	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		timestamp := time.Now().Unix()
		conn, err = AddSiteSyncData(conn, sourceSiteJson.LoadGroupId, sourceSiteJson.SiteID, timestamp)
		if err != nil {
			return nil, err
		}
		conn, err = AddSiteSyncData(conn, modifySiteJson.LoadGroupId, "", timestamp)
		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return sourceSiteJson, err
	}
	sourceSiteJson.LoadGroupId = modifySiteJson.LoadGroupId
	return sourceSiteJson, nil
}

func getDomain(domains []string) map[string]string {
	domainMap := make(map[string]string, 0)
	for _, v := range domains {
		v = strings.TrimSpace(v)
		v = ReplaceHttp(v)
		v = strings.ToLower(v)
		domainMap[v] = "1"
	}
	return domainMap

}

func (s *Wafmastersite) DeploySsl(request *http.Request) core.Response {
	sslJson := struct {
		SiteIDs    []string `json:"site_ids"`
		SslName    string   `json:"ssl_name"`
		Fullchain  string   `json:"full_chain"`
		PrivateKey string   `json:"private_key"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &sslJson); err != nil {
		return core.Fail(err)
	}
	if sslJson.Fullchain == "" || sslJson.PrivateKey == "" {
		return core.Fail("证书内容不能为空")
	}
	if sslJson.SiteIDs == nil {
		return core.Fail("参数错误")
	}
	_, boolV := CheckSslInfo(sslJson.Fullchain, sslJson.PrivateKey)
	if !boolV {
		return core.Fail("开启ssl证书失败，检测到错误的证书或密钥格式，请检查！")
	}
	successList := make([]string, 0)
	failList := make([]string, 0)
	for _, siteId := range sslJson.SiteIDs {
		public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
			conn.Begin()
			siteName := ""
			defer func() {
				if err != nil {
					conn.Rollback()
					failList = append(failList, siteName)
					return
				}
				conn.Commit()
			}()
			if !public.M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
				return nil, fmt.Errorf("网站【%d】不存在", siteId)
			}
			query := public.M("site_info").
				Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
				Where("site_id = ?", []any{siteId})
			result, err := query.Find()
			if err != nil {
				return nil, err
			}
			siteName = result["site_name"].(string)
			sourceSiteJson, err := SiteJsonToBack(result)
			if err != nil {
				return nil, err
			}
			if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
				sourceSiteJson.Server.ListenSslPort = make([]string, 0)
			}
			listenPortTotal := len(sourceSiteJson.Server.ListenPort)
			isCheckPort := false
			if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
				for i, v := range sourceSiteJson.Server.ListenPort {
					if listenPortTotal == 1 {
						if v == "80" {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, "443")
							isCheckPort = true
							break
						} else {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, v)
							sourceSiteJson.Server.ListenPort = []string{}
							break
						}
					}
					if listenPortTotal > 1 {
						if v == "80" {
							continue
						}

						if v == "443" {
							if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
								sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort[:i], sourceSiteJson.Server.ListenPort[i+1:]...)
							} else {
								for _, v1 := range sourceSiteJson.Server.ListenSslPort {
									sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort, v1)
								}
							}
							sort.Strings(sourceSiteJson.Server.ListenPort)
							break
						}

						if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, v)
							sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort[:i], sourceSiteJson.Server.ListenPort[i+1:]...)
						}
					}
				}
			}

			if isCheckPort {
				for _, domain := range sourceSiteJson.Server.ServerName {
					if public.M("site_check").Where("domain_string = ? and port = ?", []any{domain, sourceSiteJson.Server.ListenSslPort}).Exists() {
						return nil, fmt.Errorf("网站【%s】已经使用了端口【%s】，请先关闭该网站的证书", domain, sourceSiteJson.Server.ListenSslPort)
					}
				}
			}
			err = installCert(sslJson.PrivateKey, sslJson.Fullchain, sourceSiteJson.SiteID, sslJson.SslName)
			if err != nil {
				return nil, err
			}
			sourceSiteJson.Server.Ssl.PrivateKey = sslJson.PrivateKey
			sourceSiteJson.Server.Ssl.FullChain = sslJson.Fullchain
			sourceSiteJson.Server.Ssl.IsSsl = 1
			sourceSiteJson.Server.Ssl.SslName = sslJson.SslName
			timestamp := time.Now().Unix()
			sourceSiteJson.UpdateTime = timestamp
			for _, server := range sourceSiteJson.Server.ServerName {
				for _, port := range sourceSiteJson.Server.ListenSslPort {
					entryCheckData := types.EntrySiteCheck{
						SiteId:       sourceSiteJson.SiteID,
						DomainString: server,
						Port:         port,
						CreateTime:   timestamp,
					}
					if !public.M("site_check").Where("site_id = ? and domain_string = ? and port = ?", []any{siteId, server, sourceSiteJson.Server.ListenSslPort}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))
						if err != nil {
							return nil, err
						}
					}
				}

			}
			entrySiteJson, err := siteJsonToEntry(&sourceSiteJson)
			if err != nil {
				return nil, err
			}
			siteInfoData := public.StructToMap(entrySiteJson)
			_, err = conn.NewQuery().Table("site_info").Where("site_id = ?", []any{sourceSiteJson.SiteID}).Update(siteInfoData)

			if err != nil {
				return nil, err
			}
			err = ParseSiteJson(sourceSiteJson)
			if err != nil {
				return nil, err
			}
			if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
				conn, err = AddSiteSyncData(conn, sourceSiteJson.LoadGroupId, "", timestamp)
				if err != nil {
					return nil, err
				}
			}
			successList = append(successList, siteName)
			return nil, nil
		})
	}
	logString := ""
	if len(successList) > 0 {
		logString = "网站【" + strings.Join(successList, ",") + "】安装证书成功"
	}
	if len(failList) > 0 {
		if logString != "" {
			logString = logString + "," +
				"</br>" + "网站【" + strings.Join(failList, ",") + "】安装证书失败"
		} else {
			logString = "网站【" + strings.Join(failList, ",") + "】安装证书失败"
		}
	}
	public.WriteOptLog(logString, public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	if len(successList) == 0 && len(failList) > 0 {
		return core.Fail(logString)
	}
	return core.Success(logString)

}

func DeploySsl(sslJson types.SslJson, isApply bool) error {
	if sslJson.Fullchain == "" || sslJson.PrivateKey == "" {
		return errors.New("证书内容不能为空")
	}
	if sslJson.SiteIDs == nil {
		return errors.New("参数错误")
	}
	_, boolV := CheckSslInfo(sslJson.Fullchain, sslJson.PrivateKey)
	if !boolV {
		return errors.New("开启ssl证书失败，检测到错误的证书或密钥格式，请检查！")
	}
	successList := make([]string, 0)
	failList := make([]string, 0)
	for _, siteId := range sslJson.SiteIDs {
		public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
			conn.Begin()
			siteName := ""
			defer func() {
				if err != nil {
					conn.Rollback()
					failList = append(failList, siteName)
					return
				}
				conn.Commit()
			}()
			if !public.M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
				return nil, fmt.Errorf("网站【%d】不存在", siteId)
			}
			query := public.M("site_info").
				Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
				Where("site_id = ?", []any{siteId})
			result, err := query.Find()
			if err != nil {
				return nil, err
			}
			siteName = result["site_name"].(string)
			sourceSiteJson, err := SiteJsonToBack(result)
			if err != nil {
				return nil, err
			}
			if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
				sourceSiteJson.Server.ListenSslPort = make([]string, 0)
			}

			listenPortTotal := len(sourceSiteJson.Server.ListenPort)
			isCheckPort := false
			if len(sourceSiteJson.Server.ListenSslPort) == 0 {
				for i, v := range sourceSiteJson.Server.ListenPort {
					if listenPortTotal == 1 {
						if v == "80" {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, "443")
							isCheckPort = true
							break
						} else {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, v)
							sourceSiteJson.Server.ListenPort = []string{}
							break
						}
					}
					if listenPortTotal > 1 {
						if v == "80" {
							continue
						}

						if v == "443" {
							if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
								sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort[:i], sourceSiteJson.Server.ListenPort[i+1:]...)
							} else {
								for _, v1 := range sourceSiteJson.Server.ListenSslPort {
									sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort, v1)
								}
							}
							sort.Strings(sourceSiteJson.Server.ListenPort)
							break
						}
						if sourceSiteJson.Server.ListenSslPort == nil || len(sourceSiteJson.Server.ListenSslPort) == 0 {
							sourceSiteJson.Server.ListenSslPort = append(sourceSiteJson.Server.ListenSslPort, v)
							sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort[:i], sourceSiteJson.Server.ListenPort[i+1:]...)
						}
					}
				}
			}
			if isCheckPort {
				for _, domain := range sourceSiteJson.Server.ServerName {
					if public.M("site_check").Where("domain_string = ? and port = ?", []any{domain, sourceSiteJson.Server.ListenSslPort}).Exists() {
						return nil, fmt.Errorf("网站【%s】已经使用了端口【%s】，请先关闭该网站的证书", domain, sourceSiteJson.Server.ListenSslPort)
					}
				}
			}
			err = installCert(sslJson.PrivateKey, sslJson.Fullchain, sourceSiteJson.SiteID, sslJson.SslName)
			if err != nil {
				return nil, err
			}
			sourceSiteJson.Server.Ssl.PrivateKey = sslJson.PrivateKey
			sourceSiteJson.Server.Ssl.FullChain = sslJson.Fullchain
			sourceSiteJson.Server.Ssl.IsSsl = 1
			sourceSiteJson.Server.Ssl.SslName = sslJson.SslName
			timestamp := time.Now().Unix()
			sourceSiteJson.UpdateTime = timestamp
			for _, server := range sourceSiteJson.Server.ServerName {
				for _, port := range sourceSiteJson.Server.ListenSslPort {
					entryCheckData := types.EntrySiteCheck{
						SiteId:       sourceSiteJson.SiteID,
						DomainString: server,
						Port:         port,
						CreateTime:   timestamp,
					}
					if !public.M("site_check").Where("site_id = ? and domain_string = ? and port = ?", []any{siteId, server, sourceSiteJson.Server.ListenSslPort}).Exists() {
						_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))

						if err != nil {
							return nil, err
						}
					}
				}
			}

			entrySiteJson, err := siteJsonToEntry(&sourceSiteJson)
			if err != nil {
				return nil, err
			}
			siteInfoData := public.StructToMap(entrySiteJson)
			_, err = conn.NewQuery().Table("site_info").Where("site_id = ?", []any{sourceSiteJson.SiteID}).Update(siteInfoData)

			if err != nil {
				return nil, err
			}
			if isApply {
				domainMap := make(map[string]string, 0)
				for _, domain := range sslJson.Domains {
					domainMap[domain] = "1"
				}
				domains, err := json.Marshal(domainMap)
				if err != nil {
					return nil, err
				}
				applySslInfo := types.SslEntryJson{
					SiteID:     siteId,
					SslName:    sslJson.SslName,
					SslType:    sslJson.SslType,
					SslPath:    sslJson.SslPath,
					Domains:    string(domains),
					ApplyType:  sslJson.ApplyType,
					CreateTime: timestamp,
				}
				if !public.M("ssl_info").Where("site_id = ? and ssl_name = ? and ssl_type = ? and ssl_path = ?", []any{siteId, sslJson.SslName, sslJson.SslType, sslJson.SslPath}).Exists() {
					_, err = conn.NewQuery().Table("ssl_info").Insert(public.StructToMap(applySslInfo))
					if err != nil {
						return nil, err
					}
				}
				err = ParseSiteJson(sourceSiteJson)
				if err != nil {
					return nil, err
				}
			}
			if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
				conn, err = AddSiteSyncData(conn, sourceSiteJson.LoadGroupId, "", timestamp)
				if err != nil {
					return nil, err
				}
			}
			successList = append(successList, siteName)
			return nil, nil
		})
	}

	logString := ""
	if len(successList) > 0 {
		logString = "网站【" + strings.Join(successList, ",") + "】安装证书成功"
	}
	if len(failList) > 0 {
		if logString != "" {
			logString = logString + "," +
				"</br>" + "网站【" + strings.Join(failList, ",") + "】安装证书失败"
		} else {
			logString = "网站【" + strings.Join(failList, ",") + "】安装证书失败"
		}
	}
	if len(successList) == 0 && len(failList) > 0 {
		return errors.New(logString)
	}
	return nil

}

func (s *Wafmastersite) DownloadSsl(request *http.Request) core.Response {
	siteJson := types.SiteJson{}
	if err := core.GetParamsFromRequestToStruct(request, &siteJson); err != nil {
		return core.Fail(err)
	}
	if siteJson.SiteID == "" {
		return core.Fail("参数错误")
	}
	count, err := public.M("site_info").Where("site_id=?", siteJson.SiteID).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	response, err := public.DownloadSsl(siteJson.SiteID)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf(siteJson.SiteID+"网站-下载ssl证书成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return response

}

func DownloadSsl(siteId string) (core.Response, error) {
	err := compress.Zip(types.ZipPath+siteId+".zip", types.CertPath+siteId)
	if err != nil {
		return nil, err
	}
	response, err := core.DownloadFile(types.ZipPath+siteId+".zip", siteId+".zip")

	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Wafmastersite) GetSiteLog(request *http.Request) core.Response {
	siteJson := struct {
		SiteID      string `json:"site_id"`
		Types       string `json:"types"`
		LoadGroupId int64  `json:"load_group_id"`
		NodeId      string `json:"node_id"`
		Itself      int    `json:"itself"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &siteJson); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=?", siteJson.SiteID).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	result := GetSiteLogInfo(siteJson.SiteID, siteJson.Types, siteJson.LoadGroupId, siteJson.NodeId, siteJson.Itself)
	return core.Success(result)

}

func (s *Wafmastersite) ClearSiteLog(request *http.Request) core.Response {
	siteJson := struct {
		SiteID      string `json:"site_id"`
		Types       string `json:"types"`
		LoadGroupId int64  `json:"load_group_id"`
		NodeId      string `json:"node_id"`
		Itself      int    `json:"itself"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &siteJson); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=?", siteJson.SiteID).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}

	if siteJson.Itself == 0 && siteJson.LoadGroupId > 0 && siteJson.NodeId != "" {
		pushMap := map[string]any{"site_id": siteJson.SiteID, "types": siteJson.Types}
		receiveMap := types.SyncSite{}
		err := public.MapToStruct(pushMap, &receiveMap)
		if err != nil {
			return core.Fail("清空日志失败")
		}
	} else {
		_, err := public.ClearSiteLog(siteJson.SiteID, siteJson.Types)
		if err != nil {
			return core.Fail("清空日志失败")
		}
	}

	types := "访问"
	if siteJson.Types == "error" {
		types = "错误"
	}
	public.WriteOptLog(fmt.Sprintf(siteJson.SiteID+"网站-清空"+types+"日志成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("清空日志成功")
}

func GetSiteLogInfo(siteId string, logType string, groudId int64, nodeId string, itself int) string {
	logPath := types.LogRootPath + siteId + ".log"
	if logType == "error" {
		logPath = types.LogRootPath + siteId + ".error.log"
	}
	logStr, err := public.Tail(logPath, 1000)
	if err != nil {
		return ""
	}
	return logStr
}

func (s *Wafmastersite) GetAllSsl(request *http.Request) core.Response {

	sslInfo := GetAllSslInfo()
	return core.Success(sslInfo)

}

func GetAllSslInfo() []types.SslInfo {
	var sslInfos []types.SslInfo
	files, _ := os.ReadDir(types.SslPath)
	for _, f := range files {
		var sslInfo types.SslInfo
		sslInfo.SslName = f.Name()
		fullFile := types.SslPath + "/" + f.Name() + "/fullchain.pem"
		privateFile := types.SslPath + "/" + f.Name() + "/privkey.pem"
		fullStr, err := public.ReadFile(fullFile)
		if err != nil {
			continue
		}
		privateStr, err := public.ReadFile(privateFile)
		if err != nil {
			continue
		}
		cert, err := tls.LoadX509KeyPair(types.SslPath+"/"+f.Name()+"/fullchain.pem", types.SslPath+"/"+f.Name()+"/privkey.pem")
		if err != nil {
			continue
		}

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		sslInfo.Fullchain = fullStr
		sslInfo.Privkey = privateStr
		sslInfo.Brand = x509Cert.Issuer.CommonName
		sslInfo.NotAfter = x509Cert.NotAfter
		sslInfo.Domains = x509Cert.DNSNames
		sslInfos = append(sslInfos, sslInfo)
	}
	return sslInfos
}

func DelDomain(conn *db.MySql, sourceSiteJson types.SiteJson, modifySiteJson types.SiteJson) (types.SiteJson, *db.MySql, error) {
	listenTagMap := make(map[string]string, 0)
	listenDomainMap := make(map[string]string, 0)
	listenPortMap := make(map[string]string, 0)
	for _, v := range sourceSiteJson.Server.ListenTag {
		listenTagMap[v] = "1"
		domain := splitDomainSplitIndex(v, ":", 0)
		port := splitDomainSplitIndex(v, ":", 1)
		listenPortMap[port] = "1"
		listenDomainMap[domain] = "1"
	}
	for _, v := range modifySiteJson.DomainList {
		v = strings.TrimSpace(v)
		if _, ok := listenTagMap[v]; ok {
			delete(listenTagMap, v)
		}
	}
	newListenDomainMap := make(map[string]string, 0)
	newListenPortMap := make(map[string]string, 0)
	for domainPort, _ := range listenTagMap {
		domain := splitDomainSplitIndex(domainPort, ":", 0)
		port := splitDomainSplitIndex(domainPort, ":", 1)
		newListenDomainMap[domain] = "1"
		newListenPortMap[port] = "1"
	}
	for k, _ := range listenPortMap {
		if _, ok := newListenPortMap[k]; ok {
			delete(listenPortMap, k)
		}
	}
	for port, _ := range listenPortMap {
		if public.M("site_check").Where("site_id = ? and port = ?", []any{sourceSiteJson.SiteID, port}).Exists() {
			_, err := conn.NewQuery().Table("site_check").Where("site_id =? and port = ?", []any{sourceSiteJson.SiteID, port}).Delete()
			if err != nil {
				return sourceSiteJson, conn, err
			}
		}
	}
	for k, _ := range listenDomainMap {
		if _, ok := newListenDomainMap[k]; ok {
			delete(listenDomainMap, k)
		}
	}
	for domain, _ := range listenDomainMap {
		if public.M("site_check").Where("site_id = ? and domain_string = ?", []any{sourceSiteJson.SiteID, domain}).Exists() {
			_, err := conn.NewQuery().Table("site_check").Where("site_id =? and domain_string = ?", []any{sourceSiteJson.SiteID, domain}).Delete()
			if err != nil {
				return sourceSiteJson, conn, err
			}
		}
	}
	domainSlice := make([]string, 0)
	for k, _ := range newListenDomainMap {
		domainSlice = append(domainSlice, k)
	}
	sort.Strings(domainSlice)
	sourceSiteJson.Server.ServerName = domainSlice
	portSlice := make([]string, 0)
	for k, _ := range newListenPortMap {
		portSlice = append(portSlice, k)
	}
	sort.Strings(portSlice)
	sourceSiteJson.Server.ListenPort = portSlice
	tagSlice := make([]string, 0)
	for k, _ := range listenTagMap {
		tagSlice = append(tagSlice, k)
	}
	sort.Strings(tagSlice)
	sourceSiteJson.Server.ListenTag = tagSlice
	return sourceSiteJson, conn, nil
}

func Intersect(a []string, b []string) []string {
	m := make(map[string]bool, 0)
	for _, v := range a {
		m[v] = true
	}
	result := make([]string, 0)
	for _, v := range b {
		if m[v] == true {
			result = append(result, v)
		}
	}
	return result
}

func UpdateDomain(sourceSiteJson types.SiteJson, modifySiteJson types.SiteJson) (types.SiteJson, error) {
	if modifySiteJson.Server.ListenSslPort != nil {
		tmpPorts := make(map[string]string, 0)
		addPorts := make([]string, 0)
		for _, v := range modifySiteJson.Server.ListenSslPort {
			if _, ok := tmpPorts[v]; !ok {
				tmpPorts[v] = "1"
				addPorts = append(addPorts, v)
			}
		}
		modifySiteJson.Server.ListenSslPort = addPorts
	}
	if modifySiteJson.Server.ListenPort != nil {
		tmpPorts := make(map[string]string, 0)
		addPorts := make([]string, 0)
		for _, v := range modifySiteJson.Server.ListenPort {
			if v == "" {
				continue
			}
			if _, ok := tmpPorts[v]; !ok {
				tmpPorts[v] = "1"
				addPorts = append(addPorts, v)
			}
		}
		modifySiteJson.Server.ListenPort = addPorts
	}
	modifySiteJson.DomainList = StringToLower(modifySiteJson.DomainList)
	if sourceSiteJson.SiteID != "default_wildcard_domain_server" {
		err := ReturnDomainPortCheck(modifySiteJson.DomainList, false, false)
		if err != nil {
			return sourceSiteJson, err
		}
	}

	allPort := make(map[string]string, 0)
	if sourceSiteJson.Server.Ssl.IsSsl == 0 && (modifySiteJson.Server.ListenPort == nil || len(modifySiteJson.Server.ListenPort) == 0) {
		return sourceSiteJson, fmt.Errorf("HTTP端口不能为空，请输入正确端口，端口范围为1-65535")
	}
	for _, v := range modifySiteJson.Server.ListenPort {
		if v == "" && sourceSiteJson.Server.Ssl.IsSsl == 1 {
			continue
		}
		if !validate.IsPort(v) {
			return sourceSiteJson, fmt.Errorf("端口【%s】不正确，端口范围为1-65535", v)
		}
		allPort[v] = "1"
	}
	if sourceSiteJson.Server.Ssl.IsSsl == 1 {
		if modifySiteJson.Server.ListenSslPort == nil || len(modifySiteJson.Server.ListenSslPort) == 0 {
			return sourceSiteJson, fmt.Errorf("HTTPS端口不能为空,如需要关闭SSL证书，请在SSL证书管理中关闭！")
		}
		for _, v := range modifySiteJson.Server.ListenSslPort {
			if v == "" && len(modifySiteJson.Server.ListenSslPort) == 1 {
				return sourceSiteJson, fmt.Errorf("HTTPS端口不能为空,如需要关闭SSL证书，请在SSL证书管理中关闭！")
			}
			if !validate.IsPort(v) {
				return sourceSiteJson, fmt.Errorf("端口【%s】不正确，端口范围为1-65535", v)
			}
			allPort[v] = "1"
		}
		intersection := Intersect(modifySiteJson.Server.ListenPort, modifySiteJson.Server.ListenSslPort)
		if len(intersection) > 0 {
			return sourceSiteJson, fmt.Errorf("http和https不能监听重复端口【%s】", strings.Join(intersection, ","))
		}
	}

	if sourceSiteJson.SiteID != "default_wildcard_domain_server" {
		domainMap := getDomain(modifySiteJson.DomainList)
		for server, _ := range domainMap {
			for port, _ := range allPort {
				if public.M("site_check").Where("site_id != ? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Exists() {
					return sourceSiteJson, fmt.Errorf("域名端口【%s】:【%s】已经添加过", server, port)
				}
			}
		}
		if len(domainMap) > 1 {
			for server, _ := range domainMap {
				if public.M("site_check").Where("site_id != ? and domain_string = ?", []any{sourceSiteJson.SiteID, server}).Exists() {
					return sourceSiteJson, fmt.Errorf(types.ReturnInfo, server)

				}
				if sourceSiteJson.Server.Ssl.IsSsl == 1 && len(modifySiteJson.Server.ListenPort) > 0 {
					if len(modifySiteJson.Server.ListenPort) > 1 || len(sourceSiteJson.Server.ListenSslPort) > 1 || sourceSiteJson.Server.ListenSslPort[0] != "443" {
						return sourceSiteJson, fmt.Errorf("暂不支持此添加方式！你可以用此域名【%s】创建一个新的网站！", server)
					}
					if modifySiteJson.Server.ListenPort[0] != "80" {
						return sourceSiteJson, fmt.Errorf("暂不支持此添加方式！你可以用此域名【%s】创建一个新的网站！", server)
					}
					if sourceSiteJson.Server.Ssl.IsSsl == 0 && len(sourceSiteJson.Server.ListenPort) > 1 {
						return sourceSiteJson, fmt.Errorf("暂不支持此添加方式！你可以用此域名【%s】创建一个新的网站！", server)
					}
				}
			}
		}
		domainSlice := make([]string, 0)
		for k, _ := range domainMap {
			domainSlice = append(domainSlice, k)
		}
		sort.Strings(domainSlice)
		sourceSiteJson.Server.ServerName = domainSlice
	}
	portSlice := modifySiteJson.Server.ListenPort
	sort.Strings(portSlice)
	sourceSiteJson.Server.ListenPort = portSlice
	sort.Strings(modifySiteJson.Server.ListenSslPort)
	sourceSiteJson.Server.ListenSslPort = modifySiteJson.Server.ListenSslPort
	return sourceSiteJson, nil
}

func ModifyUpstream(sourceSiteJson types.SiteJson, modifySiteJson types.SiteJson) (types.SiteJson, string, error) {
	modifyUpstreamNodeLog := ""
	if modifySiteJson.Types == "addUpstreamNode" {
		addNodeAddress := ReplaceHttp(modifySiteJson.Server.Upstream.Server[0].Address)
		addNodeAddress = StringToLower([]string{addNodeAddress})[0]
		for _, v := range sourceSiteJson.Server.Upstream.Server {
			if v.Address == addNodeAddress {
				return sourceSiteJson, modifyUpstreamNodeLog, errors.New("节点【" + addNodeAddress + "】重复")
			}
		}
		err := ReturnDomainPortCheck([]string{addNodeAddress}, true, true)
		if err != nil {
			return sourceSiteJson, modifyUpstreamNodeLog, err
		}
		addNode := types.SiteUpstream{}
		addNode.AddTime = time.Now().Unix()
		addNode.Id = public.RandomStr(10)
		addNode.Status = "1"
		addNode.Address = addNodeAddress
		if sourceSiteJson.Server.Upstream.PollingAlgorithm == "round_robin" {
			addNode.Weight = modifySiteJson.Server.Upstream.Server[0].Weight
		} else {
			addNode.Weight = "1"
		}
		addNode.MaxFails = modifySiteJson.Server.Upstream.Server[0].MaxFails
		addNode.FailTimeout = modifySiteJson.Server.Upstream.Server[0].FailTimeout
		addNode.Ps = modifySiteJson.Server.Upstream.Server[0].Ps
		for _, v := range sourceSiteJson.Server.Upstream.Server {
			logging.Debug("v:", v)
		}
		sourceSiteJson.Server.Upstream.Server = append(sourceSiteJson.Server.Upstream.Server, &addNode)
		for _, v := range sourceSiteJson.Server.Upstream.Server {
			logging.Debug("v1:", v)
		}
	}
	delIndex := -1
	if modifySiteJson.Types == "delUpstreamNode" {
		if len(sourceSiteJson.Server.Upstream.Server) == 1 {
			return sourceSiteJson, modifyUpstreamNodeLog, errors.New("删除节点失败，至少保留一个节点")
		}
		for i, v := range sourceSiteJson.Server.Upstream.Server {
			if v.Id == modifySiteJson.Server.Upstream.Server[0].Id {
				delIndex = i
				modifyUpstreamNodeLog = "删除节点【" + v.Address + "】"
				break
			}
		}
		for i, _ := range sourceSiteJson.Server.Upstream.Server {
			if i == delIndex {
				if i == len(sourceSiteJson.Server.Upstream.Server)-1 {
					sourceSiteJson.Server.Upstream.Server = sourceSiteJson.Server.Upstream.Server[:i]
					break
				} else {
					sourceSiteJson.Server.Upstream.Server = append(sourceSiteJson.Server.Upstream.Server[:i], sourceSiteJson.Server.Upstream.Server[i+1:]...)
					break
				}

			}
		}

	}
	if modifySiteJson.Types == "modifyUpstream" {
		if modifySiteJson.Server.Upstream.PollingAlgorithm != "" {
			sourceSiteJson.Server.Upstream.PollingAlgorithm = modifySiteJson.Server.Upstream.PollingAlgorithm
		}
		if modifySiteJson.Server.Upstream.Host != "" {
			sourceSiteJson.Server.Upstream.Host = modifySiteJson.Server.Upstream.Host
		}
		if modifySiteJson.Server.Upstream.SourceProtocol != "" {
			sourceSiteJson.Server.Upstream.SourceProtocol = modifySiteJson.Server.Upstream.SourceProtocol
		}
	}

	if modifySiteJson.Types == "modifyUpstreamNode" {
		statusMap := map[string]string{"0": "关闭", "1": "开启"}
		for i, v := range sourceSiteJson.Server.Upstream.Server {
			if v.Id == modifySiteJson.Server.Upstream.Server[0].Id {
				modifyServer := modifySiteJson.Server.Upstream.Server[0]
				if sourceSiteJson.Server.Upstream.PollingAlgorithm == "round_robin" {
					sourceSiteJson.Server.Upstream.Server[i].Weight = modifyServer.Weight
				}
				if modifyServer.Address != "" {
					err := ReturnDomainPortCheck([]string{modifyServer.Address}, true, true)
					if err != nil {
						return sourceSiteJson, modifyUpstreamNodeLog, err
					}
					modifyUpstreamNodeLog = "节点【" + v.Address + "】修改节点地址为【" + modifyServer.Address + "】负载状态为【" + statusMap[modifyServer.Status] + "】连接失败次数为【" + modifyServer.MaxFails + "】重连时间为【" + modifyServer.FailTimeout + "s】备注为【" + modifyServer.Ps + "】"
					nowProtocols := ""
					if len(modifySiteJson.Server.Upstream.Server) == 1 {
						if strings.Contains(modifyServer.Address, "//") {
							nowProtocols = strings.Split(modifyServer.Address, "://")[0]
						}
						if nowProtocols != "" {
							sourceSiteJson.Server.Upstream.SourceProtocol = nowProtocols
						}
					}
					sourceSiteJson.Server.Upstream.Server[i].Ps = modifyServer.Ps
					modifyNodeAddress := ReplaceHttp(modifyServer.Address)
					for _, v := range sourceSiteJson.Server.Upstream.Server {
						if v.Address == modifyNodeAddress && v.Id != modifyServer.Id {
							return sourceSiteJson, modifyUpstreamNodeLog, errors.New("节点【" + modifyNodeAddress + "】重复")
						}
					}
					sourceSiteJson.Server.Upstream.Server[i].Address = modifyServer.Address
					if modifyServer.Status != "" {
						sourceSiteJson.Server.Upstream.Server[i].Status = modifyServer.Status
						if modifyServer.Status == "0" {
							nodesOn := 0
							for _, v := range sourceSiteJson.Server.Upstream.Server {
								if v.Status == "1" {
									nodesOn++
								}
							}
							if nodesOn == 0 {
								return sourceSiteJson, modifyUpstreamNodeLog, errors.New("关闭节点失败，至少需要一个节点处于开启状态")
							}
						}
					}
					if modifyServer.Weight != "" {
						sourceSiteJson.Server.Upstream.Server[i].Weight = modifyServer.Weight
					}
					if modifyServer.MaxFails != "" {
						sourceSiteJson.Server.Upstream.Server[i].MaxFails = modifyServer.MaxFails
					}
					if modifyServer.FailTimeout != "" {
						sourceSiteJson.Server.Upstream.Server[i].FailTimeout = modifyServer.FailTimeout
					}
					break
				} else {
					if modifyServer.Status != "" {
						modifyUpstreamNodeLog = "节点【" + modifyServer.Address + "】修改节点状态为【" + statusMap[modifyServer.Status] + "】"
						sourceSiteJson.Server.Upstream.Server[i].Status = modifyServer.Status
						if modifyServer.Status == "0" {
							nodesOn := 0
							for _, v := range sourceSiteJson.Server.Upstream.Server {
								if v.Status == "1" {
									nodesOn++
								}
							}
							if nodesOn == 0 {
								return sourceSiteJson, modifyUpstreamNodeLog, errors.New("关闭节点失败，至少需要一个节点处于开启状态")
							}
						}
					}

				}
			}
		}

	}
	return sourceSiteJson, modifyUpstreamNodeLog, nil

}

func OpenCert(sourceSiteJson types.SiteJson, modifySiteJson types.SiteJson) (types.SiteJson, bool, error) {
	isCheckPort := false
	if modifySiteJson.Server.Ssl.FullChain == "" || modifySiteJson.Server.Ssl.PrivateKey == "" {
		return sourceSiteJson, isCheckPort, fmt.Errorf("证书内容不能为空")
	}
	SslName, boolV := CheckSslInfo(modifySiteJson.Server.Ssl.FullChain, modifySiteJson.Server.Ssl.PrivateKey)
	if !boolV {
		return sourceSiteJson, isCheckPort, fmt.Errorf("开启ssl证书失败，检测到错误的证书或密钥格式，请检查！")
	}
	for _, v := range modifySiteJson.Server.ListenSslPort {
		if !validate.IsPort(v) {
			return sourceSiteJson, isCheckPort, fmt.Errorf("端口【" + v + "】不正确，端口范围为1-65535")
		}
		if v == "80" {
			return sourceSiteJson, isCheckPort, fmt.Errorf("端口【" + v + "】不正确，不支持使用80端口开启ssl证书")
		}

	}

	allPort := make(map[string]string, 0)
	allPortSlice := make([]string, 0)
	for _, v := range modifySiteJson.Server.ListenPort {
		if v == "" {
			continue
		}
		if !validate.IsPort(v) {
			return sourceSiteJson, isCheckPort, fmt.Errorf("端口【%s】不正确，端口范围为1-65535", v)
		}
		if _, ok := allPort[v]; !ok {
			allPort[v] = "1"
			allPortSlice = append(allPortSlice, v)
		}
	}
	if len(modifySiteJson.Server.ListenSslPort) == 0 {
		return sourceSiteJson, isCheckPort, fmt.Errorf("ssl端口不能为空,如需要关闭ssl，请在ssl证书管理中关闭！")
	}
	for _, v := range modifySiteJson.Server.ListenSslPort {
		if !validate.IsPort(v) {
			return sourceSiteJson, isCheckPort, fmt.Errorf("端口【%s】不正确，端口范围为1-65535", v)
		}
		if _, ok := allPort[v]; !ok {
			allPort[v] = "1"
			allPortSlice = append(allPortSlice, v)
		}
	}
	intersection := Intersect(sourceSiteJson.Server.ListenPort, modifySiteJson.Server.ListenSslPort)
	if len(intersection) > 0 {
		return sourceSiteJson, isCheckPort, fmt.Errorf("http和https不能监听重复端口【%s】", strings.Join(intersection, ","))
	}
	if sourceSiteJson.SiteID != "default_wildcard_domain_server" {
		for _, server := range sourceSiteJson.Server.ServerName {
			for port, _ := range allPort {
				if public.M("site_check").Where("site_id != ? and domain_string = ? and port = ?", []any{sourceSiteJson.SiteID, server, port}).Exists() {
					return sourceSiteJson, isCheckPort, fmt.Errorf("域名端口【%s】:【%s】已经添加过", server, port)
				}
			}
		}
	}

	intersection = Intersect(sourceSiteJson.Server.ListenPort, modifySiteJson.Server.ListenSslPort)
	if len(intersection) > 0 {
		for _, v := range intersection {
			for i, v1 := range sourceSiteJson.Server.ListenPort {
				if v == v1 {
					if len(sourceSiteJson.Server.ListenPort) == 1 {
						sourceSiteJson.Server.ListenPort = []string{}
					} else {
						if i == len(sourceSiteJson.Server.ListenPort)-1 {
							sourceSiteJson.Server.ListenPort = sourceSiteJson.Server.ListenPort[:i]
							break
						} else {
							sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort[:i], sourceSiteJson.Server.ListenPort[i+1:]...)
							break
						}
					}
				}
			}
		}
	}
	sourceSiteJson.Server.ListenSslPort = modifySiteJson.Server.ListenSslPort
	if isCheckPort {
		for _, domain := range sourceSiteJson.Server.ServerName {
			for _, port := range sourceSiteJson.Server.ListenSslPort {
				if public.M("site_check").Where("domain_string = ? and port = ?", []any{domain, port}).Exists() {
					return sourceSiteJson, isCheckPort, fmt.Errorf("域名【" + domain + ":" + port + "】已经被使用!开启ssl证书失败！")
				}
			}
		}
	}
	err := installCert(modifySiteJson.Server.Ssl.PrivateKey, modifySiteJson.Server.Ssl.FullChain, sourceSiteJson.SiteID, SslName)
	if err != nil {
		return sourceSiteJson, isCheckPort, err
	}
	sourceSiteJson.Server.Ssl.PrivateKey = modifySiteJson.Server.Ssl.PrivateKey
	sourceSiteJson.Server.Ssl.FullChain = modifySiteJson.Server.Ssl.FullChain
	sourceSiteJson.Server.Ssl.IsSsl = 1
	sourceSiteJson.Server.Ssl.SslName = SslName
	isCheckPort = true
	public.M("site_check").
		Where("site_id = ?", []any{sourceSiteJson.SiteID}).
		WhereNotIn("port", allPortSlice).
		Delete()
	return sourceSiteJson, isCheckPort, nil
}

func CloseCert(sourceSiteJson types.SiteJson, modifySiteJson types.SiteJson) (types.SiteJson, []string, error) {
	delPort := make([]string, 0)
	fullchain := types.CertPath + sourceSiteJson.SiteID + "/fullchain.pem"
	privkey := types.CertPath + sourceSiteJson.SiteID + "/privkey.pem"
	if sourceSiteJson.Server.Ssl.IsSsl == 1 && modifySiteJson.Server.Ssl.IsSsl == 0 {
		if public.FileExists(fullchain) {
			os.Remove(types.CertPath + sourceSiteJson.SiteID + "/fullchain.pem")
		}
		if public.FileExists(privkey) {
			os.Remove(types.CertPath + sourceSiteJson.SiteID + "/privkey.pem")
		}
		if sourceSiteJson.Server.ListenSslPort != nil {
			if sourceSiteJson.Server.ListenPort == nil {
				sourceSiteJson.Server.ListenPort = sourceSiteJson.Server.ListenSslPort
			} else {
				if sourceSiteJson.Server.ListenSslPort[0] != "443" {
					for _, v1 := range sourceSiteJson.Server.ListenSslPort {
						if v1 != "443" {
							sourceSiteJson.Server.ListenPort = append(sourceSiteJson.Server.ListenPort, v1)
						}
					}
				} else {
					delPort = append(delPort, "443")
				}
			}
			sort.Strings(sourceSiteJson.Server.ListenPort)
			sourceSiteJson.Server.ListenSslPort = []string{}
		}
		sourceSiteJson.Server.Ssl.IsSsl = 0
		sourceSiteJson.Server.Ssl.ForceHttps = 0
	}
	return sourceSiteJson, delPort, nil
}

func DelSslInfo(sslName string) error {
	if _, err := os.Stat(types.SslPath); os.IsNotExist(err) {
		return err
	}
	files, err := os.ReadDir(types.SslPath)
	if err != nil {
		return err
	}
	flag := false
	for _, f := range files {
		if f.Name() == sslName {
			flag = true
		}
	}
	if !flag {
		return fmt.Errorf("证书【%s】不存在", sslName)
	}
	err = os.RemoveAll(types.SslPath + sslName)
	if err != nil {
		return err
	}
	if public.M("ssl_info").Where("ssl_name = ?", []any{sslName}).Exists() {
		_, err = public.M("ssl_info").Where("ssl_name = ?", []any{sslName}).Delete()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Wafmastersite) DeleteSsl(request *http.Request) core.Response {

	params, err := public.ParamsCheck(request, []string{"ssl_name"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	sslName := public.InterfaceToString(params["ssl_name"].(interface{}))
	if sslName == "" {
		return core.Fail("参数错误")
	}
	err = DelSslInfo(sslName)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("证书夹删除【"+sslName+"】证书成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("删除成功")

}

func (s *Wafmastersite) GetSiteIdAndName(request *http.Request) core.Response {
	params := struct {
		P     int `json:"p"`
		PSize int `json:"p_size"`
	}{}
	params.PSize = 10000
	params.P = 1

	query := public.M("site_info").
		Field([]string{"site_id", "site_name", "create_time"}).
		Order("site_name", "desc")
	res, err := public.SimplePage(query, params)

	if err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	mm := struct {
		Total int                    `json:"total"`
		List  []*types.SiteIdAndName `json:"list"`
	}{}

	if err = public.MapToStruct(res, &mm); err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	mm.Total = len(mm.List)
	return core.Success(mm)
}

func (s *Wafmastersite) GetSiteidAndDomains(request *http.Request) core.Response {
	params := struct {
		P      int    `json:"p"`
		PSize  int    `json:"p_size"`
		SiteId string `json:"site_id"`
		Types  string `json:"types"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	params.PSize = 10000
	params.P = 1

	query := public.M("site_check").
		Field([]string{"distinct domain_string"}).
		Where("site_id = ?", []any{params.SiteId}).
		Order("domain_string", "desc")
	res, err := public.SimplePage(query, params)
	if err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	mm := struct {
		Total int             `json:"total"`
		List  []types.Domains `json:"list"`
	}{}

	if err = public.MapToStruct(res, &mm); err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	newList := make([]types.Domains, 0)
	for _, v := range mm.List {
		if params.Types == "http" && strings.HasPrefix(v.DomainString, "*.") {
			continue
		}
		if public.IsIpv4(v.DomainString) {
			continue
		}
		newList = append(newList, v)

	}
	mm.List = newList
	mm.Total = len(newList)
	return core.Success(mm)
}

func (s *Wafmastersite) GetSiteDomainParse(request *http.Request) core.Response {
	params := struct {
		P     int `json:"p"`
		PSize int `json:"p_size"`
	}{}
	params.PSize = 10000
	params.P = 1

	query := public.M("site_info").
		Field([]string{"site_id", "load_group_id"}).
		Order("site_name", "desc")
	result, err := query.Select()
	if err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	returnResult := make(map[string]any, 0)
	for _, v := range result {
		parseStatus := 0
		parseTrueStatus := 0
		if _, ok := v["site_id"].(string); !ok {
			continue
		}
		if public.InterfaceToString(v["site_id"]) == "default_wildcard_domain_server" {
			continue
		}
		loadBalance, err := public.M("load_balance").Where("id =? ", []any{v["load_group_id"].(int)}).Find()
		if err != nil {
			continue
		}
		nodes := []*types.LoadNodes{}
		if loadBalance["nodes"] == nil {
			continue
		}
		if err := json.Unmarshal([]byte(loadBalance["nodes"].(string)), &nodes); err != nil {
			return core.Fail(fmt.Errorf("获取列表失败：%w", err))
		}
		if nodes == nil {
			continue
		}
		for _, v := range nodes {
			query := public.M("cluster_nodes cn").
				Join("left", "load_balance lb", "cn.group_id=lb.id").
				Field([]string{"cn.*", "ifnull(lb.load_name, '') group_name"}).
				Where("cn.type = ?", []any{1}).Where("cn.sid = ?", []any{v.Id})
			res, err := query.Find()
			if err != nil {
				continue
			}
			if len(res) < 1 {
				continue
			}

		}
		domainMap := make(map[string]string, 0)
		query := public.M("site_check").
			Field([]string{"distinct domain_string"}).
			Where("site_id = ?", []any{v["site_id"].(string)}).
			Order("domain_string", "desc")
		subResult, err := query.Select()
		tmpdomainMap := make(map[string]any, 0)
		returndomainMap := make(map[string]any, 0)
		parseDomainMap := make(map[string]any, 0)
		rootDomain := make(map[string]string, 0)
		allRootDomain := make(map[string]string, 0)
		successParse := make(map[string]string, 0)
		errorParse := make(map[string]string, 0)
		if err == nil {
			for _, v := range subResult {
				if public.IsIpv4(v["domain_string"].(string)) {
					continue
				}
				if _, ok := v["domain_string"].(string); ok {
					domainMap[v["domain_string"].(string)] = "1"
					tmpdomainMap[v["domain_string"].(string)] = common.Copy(nodes)
					parts := strings.Split(v["domain_string"].(string), ".")
					rootDomain[v["domain_string"].(string)] = strings.Join(parts[len(parts)-2:], ".")
					if _, ok := allRootDomain[v["domain_string"].(string)]; !ok {
						allRootDomain[rootDomain[v["domain_string"].(string)]] = "1"
					}

				}
			}
		}
		if loadBalance["dns_name"] == "aliyun" {
			for k, _ := range allRootDomain {
				api, err := GetApiKey("aliyun")
				if err != nil {
					continue
				}
				aliyunClient, err := CreateClient(&api.SecretId, &api.SecretKey)
				if err != nil {
					return core.Fail(err)
				}
				dnsServerStatus := GetAliyunDomainDns(aliyunClient, k)
				if dnsServerStatus {
					parseTrueStatus++
				}
				tmpParse, err := GetAliyunDnsRecord(k)
				if err != nil {
					continue
				}

				if tmpParse != nil && tmpParse.Body != nil && tmpParse.Body.DomainRecords != nil && tmpParse.Body.DomainRecords.Record != nil {
					parseDomainMap[k] = tmpParse.Body.DomainRecords.Record
				}

			}
		}
		for k, _ := range rootDomain {
			AddSubdomainMap := make(map[string]string, 0)
			parts := strings.Split(k, ".")
			domainPrefix := strings.Join(parts[:len(parts)-2], ".")
			delSameIP := make(map[int]string, 0)
			for idx, v1 := range tmpdomainMap[k].([]*types.LoadNodes) {
				if _, ok := AddSubdomainMap[k+v1.Ip]; ok {
					delSameIP[idx] = "1"
					continue
				}
				v1.IsParse = false
				v1.IsParse = CheckDomainParseByAddress(k, v1.Ip)
				AddSubdomainMap[k+v1.Ip] = "1"
				if v1.IsParse {
					successParse[k] = "0"
					continue
				}
				if loadBalance["dns_name"] == "aliyun" {
					if parseDomainMap[rootDomain[k]] == nil {
						continue
					}
					for _, v2 := range parseDomainMap[rootDomain[k]].([]*client.DescribeDomainRecordsResponseBodyDomainRecordsRecord) {
						if *v2.RR == domainPrefix && *v2.Status == "ENABLE" && *v2.Type == "A" && v1.Ip == *v2.Value {
							successParse[k] = "0"
							v1.IsParse = true
							break
						}
					}
					errorParse[k] = "0"

				}
				if loadBalance["dns_name"] == "tencent" {
					tenentResponse, _ := _getTencentDnsList()
					for key, _ := range allRootDomain {
						tmpParse, err := GetTencentDnsRecord(key)
						if err != nil {
							continue
						}
						parseDomainMap[key] = tmpParse.Response.RecordList
						if _, ok := tenentResponse[key]; ok {
							if tenentResponse[key] {
								parseTrueStatus++
							}
						}
					}
					if parseDomainMap[rootDomain[k]] == nil {
						continue
					}
					for _, v2 := range parseDomainMap[rootDomain[k]].([]*dnspod.RecordListItem) {
						if *v2.Name == domainPrefix && *v2.Status == "ENABLE" && *v2.Type == "A" && v1.Ip == *v2.Value {
							successParse[k] = "0"
							v1.IsParse = true
							break
						}
					}
					errorParse[k] = "0"
				}
			}
			if _, ok := returndomainMap[k]; !ok {
				returndomainMap[k] = make([]*types.LoadNodes, 0)
			}
			for idx, value := range tmpdomainMap[k].([]*types.LoadNodes) {
				if _, ok := delSameIP[idx]; !ok {
					returndomainMap[k] = append(returndomainMap[k].([]*types.LoadNodes), value)
				}
			}
		}
		if parseTrueStatus == 0 && len(allRootDomain) > 0 {
			parseStatus = 0
		}
		if len(allRootDomain) > 0 && parseTrueStatus > 0 {
			if len(successParse) > 0 && len(errorParse) == 0 {
				if len(allRootDomain) == parseTrueStatus {
					parseStatus = 1
				} else {
					parseStatus = 2
				}
			}
			if len(successParse) > 0 && len(errorParse) > 0 {
				parseStatus = 2
			}
			if len(successParse) == 0 && len(errorParse) > 0 {
				parseStatus = 0
			}
		}
		singleSiteInfo := map[string]any{"domain_info": returndomainMap, "parse_status": parseStatus}
		returnResult[v["site_id"].(string)] = singleSiteInfo

	}
	return core.Success(returnResult)
}

func GetSiteListCluster(params types.SiteListParams) ([]types.SiteJson, int, error) {
	siteList := make([]types.SiteJson, 0)
	tatal := 0
	query := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time"}).
		Order("create_time", "desc")
	if params.SiteId != "" {
		query.Where("site_id = ?", []any{params.SiteId})
	}
	if params.SiteName != "" {
		query.Where("site_name like ?", []any{"%" + params.SiteName + "%"})
		querySiteId, err := public.M("site_check").
			Field([]string{"distinct site_id"}).
			Where("domain_string like ?", []any{"%" + params.SiteName + "%"}).Select()
		if err == nil && len(querySiteId) > 0 {
			for _, v := range querySiteId {
				if _, ok := v["site_id"].(string); ok {
					query.WhereOr("site_id = ?", []any{v["site_id"].(string)})
				}
			}
		}
	}
	count, err := query.Count()
	if err != nil {
		return siteList, tatal, fmt.Errorf("获取列表失败：%w", err)
	}
	tatal = int(count)
	res, err := public.SimplePage(query, params)

	if err != nil {
		return siteList, tatal, fmt.Errorf("获取列表失败：%w", err)
	}
	mm := struct {
		Total int                    `json:"total"`
		List  []*types.EntrySiteJson `json:"list"`
	}{}

	if err = public.MapToStruct(res, &mm); err != nil {
		return siteList, tatal, fmt.Errorf("获取列表失败：%w", err)
	}
	for _, v := range mm.List {
		siteJson, err := entryToSiteJson(*v)
		if err == nil {
			if siteJson.Server.Ssl.IsSsl == 1 {
				certFile := types.CertPath + siteJson.SiteID + "/fullchain.pem"
				keyFile := types.CertPath + siteJson.SiteID + "/privkey.pem"
				SslInfo := GetSslInfo(certFile, keyFile)
				siteJson.Server.Ssl.Brand = SslInfo.Brand
				siteJson.Server.Ssl.NotAfter = SslInfo.NotAfter
				siteJson.Server.Ssl.Domains = SslInfo.Domains
				if public.M("ssl_info").Where("ssl_name = ? and ssl_path = ?", []any{siteJson.Server.Ssl.SslName, types.SslPath}).Exists() {
					res, err := public.M("ssl_info").Where("ssl_name = ? and ssl_path = ?", []any{siteJson.Server.Ssl.SslName, types.SslPath}).Find()
					if err == nil {
						tmp := types.SslEntryJson{}
						if err := core.MapToStruct(res, &tmp); err == nil {
							siteJson.Server.Ssl.SslType = tmp.SslType
							if siteJson.Server.Ssl.SslType == "letsencrypt" {
								siteJson.Server.Ssl.SslType = "Let's Encrypt"
							}
							siteJson.Server.Ssl.ApplyType = tmp.ApplyType
						}
					}
				}
				siteJson.Server.Ssl.FullChain, _ = public.ReadFile(certFile)
				siteJson.Server.Ssl.PrivateKey, _ = public.ReadFile(keyFile)
			}
			siteJson.WafInfo, _ = GetRulesBySiteId(siteJson.SiteID)
			siteJson.RegionalRestrictions = GetSpecifySiteRegionRules(siteJson.SiteID)
			siteJson.Overseas.Status, siteJson.Overseas.RegionId = public.GetSpecifySiteRegionOverseasRules(siteJson.SiteID)
			if siteJson.Server.Ssl.IsSsl == 0 && siteJson.Server.ListenSslPort != nil {
				siteJson.Server.ListenSslPort = nil
			}
			ress, err := public.M("site_return_domain_check").Field([]string{"status"}).Where("site_id = ?", []any{siteJson.SiteID}).Find()
			if err == nil && ress["status"] != nil {
				siteJson.Server.Upstream.CheckDns.Status = ress["status"].(int64)
			}
			nodeNumber := 0
			for _, v1 := range siteJson.Server.Upstream.Server {
				if v1.Status == "1" {
					nodeNumber++
				}
			}
			siteJson.Server.Upstream.EnableNote = nodeNumber
			siteList = append(siteList, siteJson)

		}
	}
	return siteList, tatal, nil
}

func SiteListSingleToCluster() error {
	siteIds, err := public.GetSiteId()
	if err != nil {
		return fmt.Errorf("获取列表失败：%w", err)
	}
	if len(siteIds) == 0 {
		return fmt.Errorf("获取列表失败：%w", err)
	}
	for siteId, _ := range siteIds {
		if siteId == "" {
			continue
		}
		if public.M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
			continue
		}
		siteInfo := types.SiteJson{}
		data, err := public.GetSiteJson(siteId)
		if err != nil {
			continue
		}
		siteInfo.CreateTime = int64(data.AddTime)
		siteInfo.SiteID = siteId
		siteInfo.SiteName = data.SiteName
		siteInfo.Status = 1
		siteInfo.LoadGroupId = 0
		siteInfo.IsCDN = 0
		if data.IsCDN {
			siteInfo.IsCDN = 1
		}

		for _, v := range data.Server.Listen {
			for _, vv := range v {
				if strings.Contains(vv, "ssl") {
					splitValue := strings.Split(vv, " ")
					siteInfo.Server.ListenSslPort = append(siteInfo.Server.ListenSslPort, splitValue[0])
				} else {
					siteInfo.Server.ListenPort = append(siteInfo.Server.ListenPort, vv)
				}
			}
		}
		siteInfo.Server.Index = data.Server.Index
		siteInfo.Server.ListenIpv6 = 0
		if data.Server.ListenIpv6 {
			siteInfo.Server.ListenIpv6 = 1
		}
		siteInfo.Server.ServerName = data.Server.ServerName
		siteInfo.Server.Root = data.Server.Root
		siteInfo.Server.If.Uri.Name = "$uri"
		siteInfo.Server.If.Uri.Value = "\"^/\\.well-known/.*\\.(php|jsp|py|js|css|lua|ts|go|zip|tar\\.gz|rar|7z|sql|bak)$\""
		siteInfo.Server.If.Uri.Return = "403"
		siteInfo.Server.If.Uri.Match = "~"
		siteInfo.Server.Ssl = &types.SiteSsl{}
		siteInfo.Server.Ssl.IsSsl = 0
		if data.IsSSL {
			siteInfo.Server.Ssl.IsSsl = 1
		}
		siteInfo.Server.Ssl.ForceHttps = 0
		if data.ForceHttps {
			siteInfo.Server.Ssl.ForceHttps = 1
		}

		siteInfo.Server.Ssl.SSLCertificate = types.DockerCertPath + siteInfo.SiteID + "/fullchain.pem"
		siteInfo.Server.Ssl.SSLCertificateKey = types.DockerCertPath + siteInfo.SiteID + "/privkey.pem"
		siteInfo.Server.Ssl.SSLCiphers = []string{"\"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\""}
		siteInfo.Server.Ssl.SSLPreferServerCiphers = "on"
		siteInfo.Server.Ssl.SSLSessionCache = []string{"shared:SSL:10m"}
		siteInfo.Server.Ssl.SSLSessionTimeout = "10m"
		siteInfo.Server.Ssl.AddHeader = []string{"Strict-Transport-Security", "\"max-age=31536000\""}
		siteInfo.Server.Ssl.ErrorPage = []string{"497", "https://$host$request_uri"}
		siteInfo.Server.Ssl.SSLProtocols = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
		siteInfo.Server.Ssl.Brand = ""
		siteInfo.Server.Ssl.Domains = []string{}
		siteInfo.Server.Ssl.SslName = ""
		siteInfo.Server.Ssl.FullChain = ""
		siteInfo.Server.Ssl.PrivateKey = ""
		if siteInfo.Server.Ssl.IsSsl == 1 {
			certFile := types.CertPath + siteInfo.SiteID + "/fullchain.pem"
			keyFile := types.CertPath + siteInfo.SiteID + "/privkey.pem"
			oldSslInfo := GetSslInfo(certFile, keyFile)
			siteInfo.Server.Ssl.Brand = oldSslInfo.Brand
			siteInfo.Server.Ssl.Domains = oldSslInfo.Domains
			siteInfo.Server.Ssl.SslName = oldSslInfo.SslName
			siteInfo.Server.Ssl.SSLCiphers = data.Server.SSL.SSLCiphers
			siteInfo.Server.Ssl.SSLProtocols = data.Server.SSL.SSLProtocols
			siteInfo.Server.Ssl.FullChain, _ = public.ReadFile(siteInfo.Server.Ssl.SSLCertificate)
			siteInfo.Server.Ssl.PrivateKey, _ = public.ReadFile(siteInfo.Server.Ssl.SSLCertificateKey)
		}
		siteInfo.Server.UserInclude = types.UserPath + siteInfo.SiteID + ".conf"
		siteInfo.Server.UserIncludeText, _ = public.ReadFile(siteInfo.Server.UserInclude)
		siteInfo.Server.Upstream = &types.UpstreamJson{}
		siteInfo.Server.Upstream.Name = siteInfo.SiteID
		siteInfo.Server.Upstream.PollingAlgorithm = data.Server.Upstream.PollingAlgorithm
		siteInfo.Server.Upstream.Host = data.Server.Location.HostName
		siteInfo.Server.Upstream.EnableNote = data.Server.Upstream.EnableNote
		siteInfo.Server.Upstream.SourceProtocol = strings.Replace(data.SourceProtocol, "://", "", -1)
		if len(data.Server.Upstream.Server) > 0 {
			for _, v := range data.Server.Upstream.Server {
				serverInfo := types.SiteUpstream{}
				serverInfo.Address = ReplaceHttp(v)
				serverInfo.FailTimeout = "600"
				serverInfo.MaxFails = "2"
				serverInfo.Weight = "1"
				serverInfo.Status = "1"
				serverInfo.Ps = ""
				serverInfo.AddTime = int64(data.AddTime)
				serverInfo.Id = public.RandomStr(20)
				siteInfo.Server.Upstream.Server = append(siteInfo.Server.Upstream.Server, &serverInfo)
			}
		}
		if len(data.Server.Upstream.ServerNew) > 0 {
			for _, v := range data.Server.Upstream.ServerNew {
				serverInfo := types.SiteUpstream{}
				serverInfo.Address = ReplaceHttp(v.Server)
				serverInfo.FailTimeout = v.FailTimeout
				serverInfo.MaxFails = v.MaxFails
				serverInfo.Weight = v.Weight
				serverInfo.Status = public.InterfaceToString(v.Status)
				serverInfo.Ps = v.Ps
				serverInfo.AddTime = int64(v.AddTime)
				serverInfo.Id = v.Id
				siteInfo.Server.Upstream.Server = append(siteInfo.Server.Upstream.Server, &serverInfo)
			}
		}
		siteInfo.Server.Gzip = SetGzip()
		siteInfo.Server.Log.LogSetting.Local.AccessLog = []string{types.WwwLogs + siteInfo.SiteID + ".log"}
		siteInfo.Server.Log.LogSetting.Local.ErrorLog = []string{types.WwwLogs + siteInfo.SiteID + ".error.log"}
		siteInfo.Server.Log.LogSetting.Mode = "local"

		siteInfo.Server.Location = &types.LocationList{}
		locationNot := AddLocationJson("", "/", siteId, "1.1", []string{"Host", "Upgrade $http_upgrade", "Connection \"upgrade\"", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, []string{"error timeout invalid_header http_500 http_502 http_503 http_504"}, "off", "", "", nil, "", "", "", "")
		siteInfo.Server.Location.LocationNot = make([]types.LocationJson, 0)
		siteInfo.Server.Location.LocationNot = append(siteInfo.Server.Location.LocationNot, locationNot)
		locationAt := AddLocationJson("@", "static", siteId, "", []string{"Host", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, nil, "off", "", "", nil, "", "", "", "")
		siteInfo.Server.Location.LocationAt = make([]types.LocationJson, 0)
		siteInfo.Server.Location.LocationAt = append(siteInfo.Server.Location.LocationAt, locationAt)

		LocationRegex := AddLocationJson("~", "\\.*\\.(gif|jpg|jpeg|png|bmp|swf|js|css|woff|woff2)$", "", "", nil, nil, "", "", "", []string{"$uri", "@static"}, "1h", "", "", "")
		siteInfo.Server.Location.LocationRegex = make([]types.LocationJson, 0)

		siteInfo.Server.Location.LocationRegex = append(siteInfo.Server.Location.LocationRegex, LocationRegex)

		LocationCert := AddLocationJson("~", "^/\\.well-known/", "", "", nil, nil, "", "all", "", nil, "", "", "", "")
		siteInfo.Server.Location.LocationRegex = append(siteInfo.Server.Location.LocationRegex, LocationCert)

		LocationDeny := AddLocationJson("~", "^/(\\.user\\.ini|\\.htaccess|\\.git|\\.env|\\.svn|\\.project)", "", "", nil, nil, "", "", "", nil, "", "", "", "404")
		siteInfo.Server.Location.LocationRegex = append(siteInfo.Server.Location.LocationRegex, LocationDeny)

		siteInfo.Server.ProxyInfo = types.ProxyInfo{}
		siteInfo.Server.ProxyInfo.ProxySendTimeout = data.ProxyInfo.ProxySendTimeout
		siteInfo.Server.ProxyInfo.ProxyReadTimeout = data.ProxyInfo.ProxyReadTimeout
		siteInfo.Server.ProxyInfo.ProxyConnectTimeout = data.ProxyInfo.ProxyConnectTimeout
		siteInfo.Server.Client.MaxBodySize = data.Client.MaxBodySize
		siteInfo.Server.Client.BodyBufferSize = data.Client.BodyBufferSize
		entrySiteJson, err := siteJsonToEntry(&siteInfo)

		domainPortMap := make(map[string]string, 0)
		for _, server := range siteInfo.Server.ServerName {
			allPorts := make(map[string]string, 0)
			for _, port := range siteInfo.Server.ListenPort {
				allPorts[port] = "1"
			}
			if siteInfo.Server.Ssl.IsSsl == 1 && siteInfo.Server.ListenSslPort != nil {
				for _, port := range siteInfo.Server.ListenSslPort {
					allPorts[port] = "1"
				}

			}
			for k, _ := range allPorts {
				domainPortMap[server+":"+k] = "1"
			}
		}
		siteInfoData := public.StructToMap(entrySiteJson)
		_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
			conn.Begin()

			defer func() {
				if err != nil {
					conn.Rollback()
					return
				}
				conn.Commit()
			}()
			_, err = conn.NewQuery().Table("site_info").Insert(siteInfoData)

			if err != nil {
				return nil, err
			}
			for key, _ := range domainPortMap {
				domain, port := strings.Split(key, ":")[0], strings.Split(key, ":")[1]
				entryCheckData := types.EntrySiteCheck{
					SiteId:       siteInfo.SiteID,
					DomainString: domain,
					Port:         port,
					CreateTime:   siteInfo.CreateTime,
				}
				_, err = conn.NewQuery().Table("site_check").Insert(public.StructToMap(entryCheckData))

				if err != nil {
					return nil, err
				}
			}
			if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
				conn, err = AddSiteSyncData(conn, siteInfo.LoadGroupId, "", siteInfo.CreateTime)
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
		if err != nil {
			return fmt.Errorf("新建网站【"+siteInfo.SiteName+"】失败： %w", err)
		}
		jsonPath := types.SiteJsonPath + siteId + ".json"
		if public.FileExists(jsonPath) {
			os.Remove(jsonPath)
		}
	}
	return nil

}

func (s *Wafmastersite) GetSiteList(request *http.Request) core.Response {
	params := types.SiteListParams{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	SiteListSingleToCluster()
	clusterSiteList, total, _ := GetSiteListCluster(params)
	return core.Success(map[string]any{
		"total": total,
		"list":  clusterSiteList,
	})
}

func GetSpecifySiteRegionRules(siteId string) []any {
	var result []any
	jsonData, err := ReadListInterfaceFileBytesOne(ProvinceConfig)
	if err != nil {
		return result
	}
	for _, v := range jsonData {
		if !v.Status {
			continue
		}
		if _, ok := v.SiteId[siteId]; ok {
			result = append(result, v)
		} else {
			if _, ok := v.SiteId["allsite"]; ok {
				result = append(result, v)
			}
		}
	}
	jsonDataA, err := ReadListInterfaceFileBytesOne(CityConfig)
	if err != nil {
		return result
	}
	for _, v := range jsonDataA {
		if !v.Status {
			continue
		}
		if _, ok := v.SiteId[siteId]; ok {
			result = append(result, v)
		} else {
			if _, ok := v.SiteId["allsite"]; ok {
				result = append(result, v)
			}
		}
	}
	return result
}

func GetRulesBySiteId(siteId string) (map[string]interface{}, error) {
	resultSlice := make(map[string]interface{})
	jsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return resultSlice, err
	}
	for k, v := range jsonData.(map[string]interface{}) {
		if k == siteId {
			resultSlice = v.(map[string]interface{})
		}
	}
	if _, ok := resultSlice["crawler"]; !ok {
		resultSlice["crawler"] = map[string]interface{}{
			"encryption": map[string]interface{}{
				"open": false,
				"type": "default",
				"text": "",
			},
			"watermark": map[string]interface{}{
				"open": false,
				"type": "default",
				"text": "",
			},
		}
	}
	if _, ok := resultSlice["wait"]; !ok {
		resultSlice["wait"] = map[string]interface{}{
			"open": false,
			"time": 10,
			"user": 50,
			"qps":  1,
			"type": "default",
			"text": "",
		}
	}

	return resultSlice, nil
}

func GetSslInfo(certFile string, keyFile string) types.SslInfo {
	var sslInfo types.SslInfo
	fullChain, err := public.ReadFile(certFile)
	if err != nil {
		return sslInfo
	}
	privateKey, err := public.ReadFile(keyFile)
	if err != nil {
		return sslInfo
	}
	sslInfo.Fullchain = fullChain
	sslInfo.Privkey = privateKey
	return ReadSslInfo(certFile, keyFile, sslInfo)
}

func GetRealTimeDataResult(_result chan<- []public.SiteRealTimeInfo) {
	RealTimeData := make([]public.SiteRealTimeInfo, 0)
	query := public.M("site_info").
		Field([]string{"site_id", "load_group_id"})
	result, err := query.Select()
	if err != nil {
		_result <- RealTimeData
	}
	wg := sync.WaitGroup{}
	for _, mapInfo := range result {
		wg.Add(1)
		go func(id string, loadId int) {
			siteInfo := public.SiteRealTimeInfo{}
			siteInfo.SiteId = id
			defer func() {
				wg.Done()
				updateLock.Lock()
				RealTimeData = append(RealTimeData, siteInfo)
				updateLock.Unlock()
				if err := recover(); err != nil {
					logging.Error(public.PanicTrace(err))
				}
			}()
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
		}(mapInfo["site_id"].(string), mapInfo["load_group_id"].(int))
	}
	wg.Wait()
	_result <- RealTimeData
}

func (s *Wafmastersite) GetRealTimeData(request *http.Request) core.Response {

	RealTimeDataResult := make(chan []public.SiteRealTimeInfo)
	go GetRealTimeDataResult(RealTimeDataResult)
	select {
	case RealTimeData := <-RealTimeDataResult:
		return core.Success(RealTimeData)
	case <-time.After(3 * time.Second):
		RealTimeData := make([]public.SiteRealTimeInfo, 0)
		return core.Success(RealTimeData)
	}

}

func (s *Wafmastersite) GetSslProtocols(request *http.Request) core.Response {
	return core.Success([]string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"})
}

func (s *Wafmastersite) DeleteSite(request *http.Request) core.Response {
	params := struct {
		SiteId string `json:"site_id"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if !public.M("site_info").Where("site_id = ?", []any{params.SiteId}).Exists() {
		return core.Fail(fmt.Errorf("网站【%d】不存在", params.SiteId))
	}
	query := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
		Where("site_id = ?", []any{params.SiteId})
	result, err := query.Find()
	if err != nil {
		logging.Debug("query.Find() err", err)
	}
	siteJson, err := SiteJsonToBack(result)
	if err != nil {
		logging.Debug("siteJsonToBack err", err)
	}
	confPath := types.VhostPath + siteJson.SiteID + ".conf"
	os.Remove(confPath)

	userFile := types.UserPath + siteJson.SiteID + ".conf"
	os.Remove(userFile)
	logPath := types.WwwLogs + siteJson.SiteID + ".log"
	os.Remove(logPath)
	errorLogPath := types.WwwLogs + siteJson.SiteID + ".error.log"
	os.Remove(errorLogPath)
	rootPath := types.SiteRootPath + siteJson.SiteID
	os.RemoveAll(rootPath)
	certPath := types.CertPath + siteJson.SiteID
	os.RemoveAll(certPath)
	jsonStr, err := ReadFileBytes(types.WafSiteConfigPath)
	if err != nil {
		logging.Error("读取site.json文件失败：", err)
	}
	var jsonData interface{}
	if err = json.Unmarshal(jsonStr, &jsonData); err != nil {
		logging.Error("解析site.json文件失败：", err)
	}
	if _, ok := jsonData.(map[string]interface{})[params.SiteId]; ok {
		delete(jsonData.(map[string]interface{}), params.SiteId)
	}
	jsonStr, err = json.Marshal(jsonData)
	if err != nil {
		logging.Error("转换site.json文件失败：", err)
	}
	boolV, err := public.WriteFile(types.WafSiteConfigPath, string(jsonStr))
	if !boolV {
		logging.Error("写入site.json文件失败：", err)
	}
	delSiteId := []string{params.SiteId}
	for _, v := range delSiteId {
		err = DelSiteRegion(v, ProvinceConfig)
		if err != nil {
			continue
		}
		err = DelSiteRegion(v, CityConfig)
		if err != nil {
			continue
		}
		err := DelSiteAuth(v)
		if err != nil {
			continue
		}
	}
	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().Table("site_info").Where("site_id = ?", []any{params.SiteId}).Delete()
		if err != nil {
			return nil, err
		}
		_, err = conn.NewQuery().Table("site_check").Where("site_id = ?", []any{params.SiteId}).Delete()
		if err != nil {
			return nil, err
		}

		if clusterCommon.ClusterState() == clusterCommon.CLUSTER_UPPER {
			timestamp := time.Now().Unix()
			conn, err = AddSiteSyncData(conn, siteJson.LoadGroupId, params.SiteId, timestamp)
			if err != nil {
				return nil, err
			}
		}
		err = ReloadNginx()
		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf("删除网站【"+params.SiteId+"】失败： %w", err))
	}
	logString := "删除网站【" + siteJson.SiteName + "】成功"
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success(logString)

}

func DelSiteAuth(siteId string) error {
	_, err := public.MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		err := public.DelSpecificSiteAllAuthInfo(db, siteId)
		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func installCert(privateKey string, fullChain string, siteId string, sslName string) error {
	siteSslPath := types.SslPath + "/" + sslName
	SiteSslPrivateKey := siteSslPath + "/privkey.pem"
	SiteSslFullChain := siteSslPath + "/fullchain.pem"
	siteCertPath := types.CertPath + "/" + siteId
	sitePrivateKey := siteCertPath + "/privkey.pem"
	siteFullChain := siteCertPath + "/fullchain.pem"
	MkdirPathS := []string{siteSslPath, siteCertPath}
	for _, v := range MkdirPathS {
		if !public.FileExists(v) {
			err := os.MkdirAll(v, 0600)
			if err != nil {
				return err
			}
		}
	}
	WritePrivateKeyFile := []string{SiteSslPrivateKey, SiteSslFullChain, sitePrivateKey, siteFullChain}
	for _, v := range WritePrivateKeyFile {
		writeString := privateKey
		if strings.Contains(v, "full") {
			writeString = fullChain
		}
		err := os.WriteFile(v, []byte(writeString), 0644)
		if err != nil {
			return err
		}
	}
	for _, v := range WritePrivateKeyFile {
		if !public.FileExists(v) {
			return errors.New(v + "文件不存在")
		}
	}
	return nil
}

func DelSiteRegion(siteId string, filePath string) error {
	jsonData, err := ReadListInterfaceFileBytes(filePath)
	if err != nil {
		return err
	}
	for i := len(jsonData) - 1; i > -1; i-- {
		v := jsonData[i]
		if v1, ok := v.(map[string]interface{}); ok {
			if v2, ok := v1["site"].(map[string]interface{}); ok {
				if _, ok := v2[siteId]; ok {
					jsonData = append(jsonData[:i], jsonData[i+1:]...)
				}
			}
		}
	}
	err = public.WriteListInterfaceFile(filePath, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func ReadListInterfaceFileBytesOne(filePath string) ([]types.WafRegion, error) {
	var result []types.WafRegion
	jsonStr, err := ReadFileBytes(filePath)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(jsonStr, &result); err != nil {
		return result, err
	}
	return result, nil
}

func ReadListInterfaceFileBytes(filePath string) ([]interface{}, error) {
	var result []interface{}
	jsonStr, err := ReadFileBytes(filePath)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(jsonStr, &result); err != nil {
		return result, err
	}
	return result, nil
}

func ReadFileBytes(filename string) ([]byte, error) {
	if !public.FileExists(filename) {
		return nil, os.ErrNotExist
	}
	fd, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	context, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	return context, nil
}

func ReloadNginx() error {
	_, stdErr, err := ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-t")
	if err != nil {
		return err
	}
	if stdErr != "" && !strings.Contains(stdErr, "test is successful") {
		return errors.New(stdErr)
	}
	public.AddTaskOnce(public.OnlyReloadNginx, time.Second*1)
	return nil
}

func CheckSslInfo(fullChain string, privateKey string) (string, bool) {
	certFile := types.CertPath + "test.fullchain.pem"
	keyFile := types.CertPath + "test.privkey.pem"
	boolV, _ := public.WriteFile(certFile, fullChain)
	if !boolV {
		return "", false
	}
	boolV, _ = public.WriteFile(keyFile, privateKey)
	if !boolV {
		return "", false
	}
	var sslInfo types.SslInfo
	sslInfo = ReadSslInfo(certFile, keyFile, sslInfo)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)
	if sslInfo.Brand == "" && sslInfo.Domains == nil {
		return "", false
	}
	sslName := strings.ReplaceAll(sslInfo.Domains[0], "*.", "")
	return sslName, true
}

func ReadSslInfo(certFile string, keyFile string, sslInfo types.SslInfo) types.SslInfo {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return sslInfo
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return sslInfo
	}
	sslInfo.Brand = x509Cert.Issuer.CommonName
	sslInfo.NotAfter = x509Cert.NotAfter
	sslInfo.Domains = x509Cert.DNSNames
	return sslInfo
}

func ExecNginxCommand(command string, args ...string) (stdout, stderr string, err error) {
	cmd := exec.Command(command, args...)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	err = cmd.Run()
	if err != nil && !strings.Contains(err.Error(), "exit status") {
		return stdout, stderr, err
	}

	if runtime.GOOS == "linux" {
		return stdoutBuf.String(), stderrBuf.String(), nil
	}
	return public.ConvertByte2String(stdoutBuf.Bytes(), "GB18030"), public.ConvertByte2String(stderrBuf.Bytes(), "GB18030"), nil
}

func siteJsonToEntry(siteJson *types.SiteJson) (types.EntrySiteJson, error) {
	serverByte, err := json.Marshal(siteJson.Server)

	if err != nil {
		return types.EntrySiteJson{}, err
	}
	return types.EntrySiteJson{
		SiteName:    siteJson.SiteName,
		SiteID:      siteJson.SiteID,
		Server:      string(serverByte),
		IsCDN:       siteJson.IsCDN,
		CreateTime:  siteJson.CreateTime,
		UpdateTime:  siteJson.UpdateTime,
		LoadGroupId: siteJson.LoadGroupId,
		Status:      siteJson.Status,
	}, nil
}

func SiteJsonToBack(siteJson map[string]interface{}) (types.SiteJson, error) {
	server := types.ServerJson{}
	err := json.Unmarshal([]byte(siteJson["server"].(string)), &server)
	if err != nil {
		return types.SiteJson{}, err
	}
	newPorts := make([]string, 0)
	for _, v := range server.ListenPort {
		tmp := strings.TrimSpace(v)
		if tmp != "" {
			newPorts = append(newPorts, tmp)
		}
	}
	server.ListenPort = newPorts
	newSslPorts := make([]string, 0)
	for _, v := range server.ListenSslPort {
		tmp := strings.TrimSpace(v)
		if tmp != "" {
			newSslPorts = append(newSslPorts, tmp)
		}
	}
	server.ListenSslPort = newSslPorts
	return types.SiteJson{
		SiteName:    siteJson["site_name"].(string),
		SiteID:      siteJson["site_id"].(string),
		Server:      server,
		IsCDN:       siteJson["is_cdn"].(int64),
		CreateTime:  siteJson["create_time"].(int64),
		UpdateTime:  siteJson["update_time"].(int64),
		LoadGroupId: siteJson["load_group_id"].(int64),
		Status:      siteJson["status"].(int64),
	}, nil
}

func entryToSiteJson(entrySiteJson types.EntrySiteJson) (types.SiteJson, error) {
	server := types.ServerJson{}
	err := json.Unmarshal([]byte(entrySiteJson.Server), &server)
	if err != nil {
		return types.SiteJson{}, err
	}
	return types.SiteJson{
		SiteName:    entrySiteJson.SiteName,
		SiteID:      entrySiteJson.SiteID,
		Server:      server,
		IsCDN:       entrySiteJson.IsCDN,
		CreateTime:  entrySiteJson.CreateTime,
		LoadGroupId: entrySiteJson.LoadGroupId,
		Status:      entrySiteJson.Status,
	}, nil
}

func SetGzip() types.GzipJson {
	gzip := types.GzipJson{}
	gzip.Status = true
	gzip.GzipMinLength = "1k"
	gzip.GzipBuffers = []string{"4", "16k"}
	gzip.GzipHttpVersion = "1.1"
	gzip.GzipCompLevel = "3"
	gzip.GzipTypes = []string{"text/plain", "text/css", "text/xml", "application/json", "application/javascript", "application/xml+rss", "application/atom+xml", "image/svg+xml"}
	gzip.GzipVary = true
	gzip.GzipProxied = []string{"expired", "no-cache", "no-store", "private", "auth"}
	gzip.GzipDisable = []string{"\"MSIE [1-6]\\.\""}
	return gzip
}

func CreateSiteJson(siteJson *types.SiteJson) (types.SiteJson, error) {
	if siteJson.Server.Ssl.IsSsl == 1 {
		for _, v := range siteJson.Server.ListenSslPort {
			if !validate.IsPort(v) {
				return *siteJson, fmt.Errorf("端口【" + v + "】不正确，端口范围为1-65535")
			}
		}
	} else {
		siteJson.Server.ListenSslPort = nil
	}
	for _, v := range siteJson.Server.ListenPort {
		if !validate.IsPort(v) {
			return *siteJson, fmt.Errorf("端口【" + v + "】不正确，端口范围为1-65535")
		}
	}
	for _, v := range siteJson.DomainList {
		v = ReplaceHttp(v)
		if strings.Contains(v, ":") {
			return *siteJson, fmt.Errorf("域名【" + v + "】不正确，正确填写示例:</br>192.168.10.11")
		}
	}
	timestamp := time.Now().Unix()
	siteId := "default_wildcard_domain_server"
	if len(siteJson.DomainList) > 1 || (len(siteJson.DomainList) == 1 && siteJson.DomainList[0] != "*") {
		siteId = strings.ReplaceAll(siteJson.DomainList[0], `*.`, "__")
		siteId = strings.ReplaceAll(siteId, ".", "_")
		siteId = strings.ReplaceAll(siteId, "https://", "")
		siteId = strings.ReplaceAll(siteId, "http://", "")
		siteId = strings.ReplaceAll(siteId, "：", "_")
		siteId = strings.ReplaceAll(siteId, ":", "_")
		sourceSiteId := siteId
		for i := 0; i < 10000; i++ {
			siteId = sourceSiteId + "_" + strconv.Itoa(i)
			if public.M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
				continue
			} else {
				break
			}
		}
	}
	siteJson.SiteID = siteId
	appendPort := "80"
	if siteJson.Server.Ssl.IsSsl == 1 {
		appendPort = "443"
	}
	if len(siteJson.DomainList) == 1 && siteJson.DomainList[0] == "*" {
		siteJson.SiteName = "通配所有域名"
	}

	siteJson.CreateTime = timestamp
	siteJson.UpdateTime = timestamp
	siteJson.Server.Root = "/www/wwwroot/" + siteJson.SiteID

	siteJson.Server.Index = []string{"index.html"}
	siteJson.Server.ServerName = make([]string, 0)
	siteJson.Server.ServerName = getdomainSlice(siteJson.DomainList, siteJson.Server.ServerName, appendPort)

	siteJson.Server.Ssl.SSLCertificate = types.DockerNginx + siteJson.SiteID + "/fullchain.pem"
	siteJson.Server.Ssl.SSLCertificateKey = types.DockerNginx + siteJson.SiteID + "/privkey.pem"
	siteJson.Server.Ssl.SSLProtocols = []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}
	siteJson.Server.Ssl.SSLCiphers = []string{"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5"}
	siteJson.Server.Ssl.SSLPreferServerCiphers = "on"
	siteJson.Server.Ssl.SSLSessionCache = []string{"shared:SSL:10m"}
	siteJson.Server.Ssl.SSLSessionTimeout = "10m"
	siteJson.Server.Ssl.AddHeader = []string{"Strict-Transport-Security", "\"max-age=31536000\""}
	siteJson.Server.Ssl.ErrorPage = []string{"497", "https://$host$request_uri"}

	siteJson.Server.UserInclude = types.UserPath + "user.conf"

	siteJson.Server.Upstream.Name = siteJson.SiteID
	for _, v := range siteJson.Server.Upstream.Server {
		v.MaxFails = "2"
		v.FailTimeout = "600s"
		v.Weight = "1"
		v.Status = "1"
		v.AddTime = timestamp
		v.Id = public.RandomStr(10)
		v.Ps = ""
		siteJson.Server.Upstream.EnableNote++

	}
	siteJson.Server.Log.LogSetting.Local.AccessLog = []string{types.WwwLogs + siteJson.SiteID + ".log"}
	siteJson.Server.Log.LogSetting.Local.ErrorLog = []string{types.WwwLogs + siteJson.SiteID + ".error.log"}
	siteJson.Server.Log.LogSetting.Mode = "local"

	ifUri := types.If{
		Name:   "$uri",
		Match:  "~",
		Value:  "\"^/\\.well-known/.*\\.(php|jsp|py|js|css|lua|ts|go|zip|tar\\.gz|rar|7z|sql|bak)$\"",
		Return: "403",
	}
	siteJson.Server.If.Uri = ifUri
	siteJson.Server.Gzip = SetGzip()
	siteJson.DomainList = nil

	locationNot := AddLocationJson("", "/", siteId, "1.1", []string{"Host", "Upgrade $http_upgrade", "Connection \"upgrade\"", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, []string{"error timeout invalid_header http_500 http_502 http_503 http_504"}, "off", "", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationNot = make([]types.LocationJson, 0)
	siteJson.Server.Location.LocationNot = append(siteJson.Server.Location.LocationNot, locationNot)
	locationAt := AddLocationJson("@", "static", siteId, "", []string{"Host", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, nil, "off", "", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationAt = make([]types.LocationJson, 0)
	siteJson.Server.Location.LocationAt = append(siteJson.Server.Location.LocationAt, locationAt)
	LocationRegex := AddLocationJson("~", "\\.*\\.(gif|jpg|jpeg|png|bmp|swf|js|css|woff|woff2)$", "", "", nil, nil, "", "", "", []string{"$uri", "@static"}, "1h", "", "", "")
	siteJson.Server.Location.LocationRegex = make([]types.LocationJson, 0)
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationRegex)

	LocationCert := AddLocationJson("~", "^/\\.well-known/", "", "", nil, nil, "", "all", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationCert)
	LocationDeny := AddLocationJson("~", "^/(\\.user\\.ini|\\.htaccess|\\.git|\\.env|\\.svn|\\.project)", "", "", nil, nil, "", "", "", nil, "", "", "", "404")
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationDeny)
	return *siteJson, nil
}

func AddLocationJson(matchPriority string, matchArguments string, proxyPass string, proxyHttpVersion string, proxySetHeader []string, proxyNextUpstream []string, proxyCache string, allow string, deny string, tryFiles []string, expires string, accessLog string, errorLog string, Return string) types.LocationJson {
	location := types.LocationJson{}
	location.MatchPriority = matchPriority
	location.MatchArguments = matchArguments
	location.ProxyPass = proxyPass
	location.ProxySetHeader = proxySetHeader
	location.ProxyNextUpstream = proxyNextUpstream
	location.ProxyCache = proxyCache
	location.Allow = allow
	location.Deny = deny
	location.TryFiles = tryFiles
	location.Expires = expires
	location.AccessLog = accessLog
	location.ErrorLog = errorLog
	location.Return = Return
	return location
}

func WriteDomain(domain []string, siteId string) error {
	domains := make([]interface{}, 0)
	domainMap := map[string]interface{}{"name": siteId, "domains": domain}
	if !public.FileExists(types.SiteDomainConfigJson) && public.FileExists(types.DomainsJsonPath) {
		oldData, err := ReadListInterfaceFileBytes(types.DomainsJsonPath)
		if err == nil {
			domains = oldData
		}

	}
	if public.FileExists(types.SiteDomainConfigJson) {
		oldData, err := ReadListInterfaceFileBytes(types.SiteDomainConfigJson)
		if err == nil {
			domains = oldData
		}
	}
	isAdd := true
	for i, v := range domains {
		if v.(map[string]interface{})["name"] == siteId {
			domains[i] = domainMap
			if len(domain) == 0 {
				domains = append(domains[:i], domains[i+1:]...)
			}
			isAdd = false
		}
	}
	if isAdd {
		domains = append(domains, domainMap)
	}
	writeData, err := json.Marshal(domains)
	if err != nil {
		return err
	}
	domaiFiles := []string{types.SiteDomainConfigJson, types.DomainsJsonPath}
	for _, v := range domaiFiles {
		err = os.WriteFile(v, writeData, 0644)
	}
	return nil

}

func ParseSiteJson(siteJson types.SiteJson) error {
	if siteJson.Status == 0 {
		os.Remove(types.VhostPath + siteJson.SiteID + ".conf")
	} else {
		conf, err := ParseUpstreamConf(siteJson)
		if err != nil {
			return err
		}
		conf = conf + ParseRootJson(siteJson)
		conf = conf + ParseSSLJson(siteJson)
		conf = conf + ParseError502()
		conf = conf + ParseGzip(siteJson)
		conf = conf + ParseHttpHost()
		conf = conf + "\tinclude /etc/nginx/user/" + siteJson.SiteID + ".conf;\n\n"

		if public.FileExists(types.SsLHttpDebug) {
			conf += "\tlocation ~ ^/\\.well-known/acme-challenge {\n\t\troot /www/wwwroot/" + siteJson.SiteID + ";\n\t}\n"
		}
		hostString := siteJson.Server.Upstream.Host
		httpProtocol := siteJson.Server.Upstream.SourceProtocol
		for _, item := range siteJson.Server.Location.LocationNot {
			conf = conf + ParseLocationJson(item, hostString, httpProtocol, siteJson)
		}
		for _, item := range siteJson.Server.Location.LocationAt {
			conf = conf + ParseLocationJson(item, hostString, httpProtocol, siteJson)
		}
		for _, item := range siteJson.Server.Location.LocationRegex {
			conf = conf + ParseLocationJson(item, hostString, httpProtocol, siteJson)
		}
		for _, item := range siteJson.Server.Location.LocationTilde {
			conf = conf + ParseLocationJson(item, hostString, httpProtocol, siteJson)
		}

		for _, item := range siteJson.Server.Location.LocationStar {
			conf = conf + ParseLocationJson(item, hostString, httpProtocol, siteJson)
		}

		logFormatAccess := ""
		if public.GetCdnRule(siteJson.SiteID) {
			logFormatAccess = " access_log"
		}
		conf = conf + "\n\taccess_log " + strings.Join(siteJson.Server.Log.LogSetting.Local.AccessLog, " ") + logFormatAccess + ";\n"
		conf = conf + "\terror_log " + strings.Join(siteJson.Server.Log.LogSetting.Local.ErrorLog, " ") + ";\n"
		conf = conf + "}\n"

		confPath := types.VhostPath + siteJson.SiteID + ".conf"
		userFile := types.UserPath + siteJson.SiteID + ".conf"
		err = os.WriteFile(confPath, []byte(conf), 0644)
		if err != nil {
			return err
		}
		err = os.WriteFile(userFile, []byte(siteJson.Server.UserIncludeText), 0644)
		if err != nil {
			return err
		}

	}
	err := ReloadNginx()
	if err != nil {
		logging.Debug("重载nginx失败", err)
		return err
	}
	return nil

}

func ParseIfJson(ifConfig types.If) string {
	conf := ""
	if ifConfig.Name != "" {
		conf = "\n\tif ( " + ifConfig.Name
	}
	if ifConfig.Match != "" {
		conf = conf + " " + ifConfig.Match
	}
	if ifConfig.Value != "" {
		conf = conf + " " + ifConfig.Value + " ) {\n"
	}
	if ifConfig.Return != "" {
		conf = conf + "\t\treturn " + ifConfig.Return + ";\n\t}\n\n"
	}
	return conf
}

func ParseHttpHost() string {
	return "\tset $host_optimize $http_host;\n\tif ($http_host = \"\") {\n\t\tset $host_optimize \"default\";\n\t}\n\n"
}

func ParseLocationJson(locationJson types.LocationJson, hostString string, httpProtocol string, siteJson types.SiteJson) string {
	conf := ""
	emptyString := true
	isEmpty := false
	addSNI := false
	isRoot := false
	if locationJson.MatchPriority == "@" {
		emptyString = false
		addSNI = true
	}
	if locationJson.MatchPriority == "" {
		isRoot = true
	}

	if locationJson.MatchPriority != "" {
		conf = conf + "\tlocation " + locationJson.MatchPriority
	} else {
		conf = conf + "\tlocation "
		addSNI = true
	}

	if locationJson.MatchArguments != "" {
		if locationJson.MatchArguments == "^/\\.well-known/" || locationJson.MatchArguments == "\\.*\\.(gif|jpg|jpeg|png|bmp|swf|js|css|woff|woff2)$" || locationJson.MatchArguments == "static" {
			isEmpty = true
		}
		if emptyString {
			conf = conf + " " + locationJson.MatchArguments + " {\n"
		} else {
			conf = conf + locationJson.MatchArguments + " {\n"
		}
	}
	if locationJson.ProxyPass != "" {
		conf = conf + "\t\tproxy_pass " + httpProtocol + "://" + locationJson.ProxyPass + ";\n"
		conf = strings.ReplaceAll(conf, "://://", "://")
	}
	if locationJson.ProxySetHeader != nil && len(locationJson.ProxySetHeader) > 0 {
		for _, item := range locationJson.ProxySetHeader {
			if item == "Host" {
				item = item + " " + hostString
			}
			conf = conf + "\t\tproxy_set_header " + item + ";\n"

		}
	}
	if addSNI {
		conf = conf + "\t\tproxy_ssl_server_name on;\n"
		conf = conf + "\t\tproxy_ssl_name $host_optimize;\n"
	}
	if locationJson.ProxyCache != "" {
		conf = conf + "\t\tproxy_cache " + locationJson.ProxyCache + ";\n"
	}

	if isRoot {
		proxyInfo := siteJson.Server.ProxyInfo
		clientInfo := siteJson.Server.Client
		if proxyInfo.ProxySendTimeout != "" && proxyInfo.ProxyReadTimeout != "" && proxyInfo.ProxyConnectTimeout != "" {
			conf = conf + "\t\tproxy_connect_timeout " + proxyInfo.ProxyConnectTimeout + ";\n"
			conf = conf + "\t\tproxy_send_timeout " + proxyInfo.ProxySendTimeout + ";\n"
			conf = conf + "\t\tproxy_read_timeout " + proxyInfo.ProxyReadTimeout + ";\n"
			conf = conf + "\t\tclient_max_body_size " + clientInfo.MaxBodySize + ";\n"
		}
	}

	if locationJson.Allow != "" {
		conf = conf + "\t\tallow " + locationJson.Allow + ";\n"
	}

	if locationJson.Deny != "" {
		conf = conf + "\t\tdeny " + locationJson.Deny + ";\n"
	}

	if locationJson.TryFiles != nil && len(locationJson.TryFiles) > 0 {
		conf = conf + "\t\ttry_files " + strings.Join(locationJson.TryFiles, " ") + ";\n"
	}

	if locationJson.Expires != "" {
		conf = conf + "\t\texpires " + locationJson.Expires + ";\n"
	}

	if locationJson.AccessLog != "" {
		conf = conf + "\t\taccess_log " + locationJson.AccessLog + ";\n"
	}

	if locationJson.ErrorLog != "" {
		conf = conf + "\t\terror_log " + locationJson.ErrorLog + ";\n"
	}

	if locationJson.Return != "" {
		conf = conf + "\t\treturn " + locationJson.Return + ";\n\t}\n\n"
	} else {
		conf = conf + "\n\t}\n\n"
	}
	if isEmpty {
		conf = ""
	}
	return conf
}

func ParseUpstreamConf(jsonData types.SiteJson) (string, error) {
	upstream := jsonData.Server.Upstream
	var UpstreamConf string
	UpstreamConf = "upstream " + upstream.Name + " {\n"
	if upstream.PollingAlgorithm != "round_robin" && upstream.PollingAlgorithm != "sticky" {
		UpstreamConf = UpstreamConf + "\t" + upstream.PollingAlgorithm + ";\n"
	}
	if upstream.PollingAlgorithm == "sticky" {
		UpstreamConf = UpstreamConf + "\tsticky name=bt_waf_route expires=12h httponly secure;\n"
	}

	if len(upstream.Server) > 0 {
		for _, item := range upstream.Server {
			if item.Status != "1" {
				continue
			}
			addData := " max_fails=" + item.MaxFails + " fail_timeout=" + strings.ReplaceAll(item.FailTimeout, "s", "") + "s"
			if upstream.PollingAlgorithm == "round_robin" {
				addData = addData + " weight=" + item.Weight
			}
			if item.Status == "2" {
				addData = addData + " backup"
			}
			sourceItem := item.Address
			domainName := strings.TrimSpace(item.Address)
			domainName = strings.ReplaceAll(domainName, "https://", "")
			domainName = strings.ReplaceAll(domainName, "http://", "")
			if !strings.Contains(domainName, ":") && (strings.Contains(sourceItem, "https://") || strings.Contains(jsonData.Server.Upstream.SourceProtocol, "https")) {
				domainName = domainName + ":443"
			}
			UpstreamConf = UpstreamConf + "\tserver " + domainName + addData + ";\n"
		}
	}
	UpstreamConf = UpstreamConf + "}\n\n"
	return UpstreamConf, nil
}

func IsStringValid(input string) bool {
	pattern := `^\d+(\.\d+){3}$`
	matched, err := regexp.MatchString(pattern, input)
	if err != nil {
		return false
	}
	return matched
}

func CheckIp(ip string) bool {
	ip = ReplaceHttp(ip)
	if net.ParseIP(ip) == nil {
		return false
	}
	return true
}

func CheckDomainIp(domain []string, isHttps bool) ([]string, []string, []map[string]string, error) {
	var err error
	addDomain := []string{}
	addDomainMap := make(map[string]string)
	addPort := []string{}
	addPortMap := make(map[string]string, 0)
	addMapList := make([]map[string]string, 0)
	ErrorList := []string{}
	for _, ip := range domain {
		ip = ReplaceHttp(ip)
		isWildcard := false
		if strings.HasPrefix(ip, "*.") {
			ip = strings.Replace(ip, "*.", "", 1)
			isWildcard = true
		}
		if !validate.IsHost(ip) {
			return addDomain, addPort, addMapList, errors.New("2")
		}
		addMap := make(map[string]string, 0)
		if strings.Contains(ip, ":") {
			ipSplit := strings.Split(ip, ":")
			ip = ipSplit[0]
			port := ipSplit[1]
			if IsStringValid(ip) && !CheckIp(ip) {
				return addDomain, addPort, addMapList, errors.New("1")
			}
			if !validate.IsHost(ip) {
				return addDomain, addPort, addMapList, errors.New("2")
			}
			if !validate.IsPort(port) {
				return addDomain, addPort, addMapList, errors.New("0")
			}
			addPortMap[port] = "1"
			if isWildcard {
				addMap["*."+ip] = port
			} else {
				addMap[ip] = port
			}
			addMapList = append(addMapList, addMap)
		} else {
			httpPort := "80"
			if isHttps {
				httpPort = "443"
			}
			addPortMap[httpPort] = "1"
			addMap[ip] = httpPort
			addMapList = append(addMapList, addMap)
		}

		if isWildcard {
			addDomainMap["*."+ip] = "1"
		} else {
			addDomainMap[ip] = "1"
		}
		if IsStringValid(ip) {
			if !CheckIp(ip) {
				err = errors.New("1")
				break
			}
		} else {
			err = errors.New("3")
			ErrorList = append(ErrorList, "3")
		}
	}
	if ErrorList != nil && len(ErrorList) > 0 {
		err = errors.New(ErrorList[0])
	}
	for key, _ := range addDomainMap {
		addDomain = append(addDomain, key)
	}
	for key, _ := range addPortMap {
		addPort = append(addPort, key)
	}
	return addDomain, addPort, addMapList, err
}

func CheckDomainPort(domains []string, isReturnSource, checkParse bool) (string, int) {
	domainMap := make(map[string]string, 0)
	portMap := make(map[string]string, 0)
	for _, domain := range domains {
		sourceDomain := domain
		domain = strings.TrimSpace(domain)
		domain = ReplaceHttp(domain)
		if isReturnSource {
			if strings.Contains(domain, ":") {
				ipSplit := strings.Split(domain, ":")
				domain = ipSplit[0]
				port := ipSplit[1]
				portMap[port] = "1"
			} else {
				domainMap[domain] = "1"
			}
		} else {
			if strings.Contains(domain, ":") {
				return sourceDomain, 4
			}
			domainMap[domain] = "1"
		}

	}

	for domain, _ := range domainMap {
		sourceDomain := domain
		if strings.HasPrefix(domain, "*.") {
			domain = strings.Replace(domain, "*.", "", 1)
		}
		if !validate.IsHost(domain) {
			return sourceDomain, 4
		}
		if IsStringValid(domain) {
			if !CheckIp(domain) {
				return sourceDomain, 3
			}
		} else {
			if checkParse {
				if !CheckDomainParseByDomain(domain) {
					return sourceDomain, 6
				}
			}
		}
	}
	for port, _ := range portMap {
		if !validate.IsPort(port) {
			return port, 1
		}
	}
	return "", 0

}

func ReturnDomainPortCheck(domainList []string, isReturnSource bool, checkParse bool) error {
	errorString, errorNumber := CheckDomainPort(domainList, isReturnSource, checkParse)
	switch errorNumber {
	case 1:
		return fmt.Errorf("域名端口【%s】不正确,端口范围为1-65535", errorString)
	case 2:
		return fmt.Errorf("域名地址【%s】不正确", errorString)
	case 3:
		return fmt.Errorf("ip地址【%s】不正确", errorString)
	case 4:
		return fmt.Errorf("域名地址【%s】不正确,正确填写示例：</br>192.168.10.11", errorString)
	case 6:
		return fmt.Errorf("域名【%s】未解析，请先解析域名！", errorString)
	}
	return nil
}

func ParseGzip(siteJson types.SiteJson) string {
	conf := ""
	if siteJson.Server.Gzip.Status {
		gzipJson := siteJson.Server.Gzip
		conf := "\tgzip on;\n"
		conf = conf + "\tgzip_min_length " + gzipJson.GzipMinLength + ";\n"
		conf = conf + "\tgzip_buffers " + strings.Join(gzipJson.GzipBuffers, " ") + ";\n"
		conf = conf + "\tgzip_http_version " + gzipJson.GzipHttpVersion + ";\n"
		conf = conf + "\tgzip_comp_level " + gzipJson.GzipCompLevel + ";\n"
		conf = conf + "\tgzip_types " + strings.Join(gzipJson.GzipTypes, " ") + ";\n"
		if siteJson.Server.Gzip.GzipVary {
			conf = conf + "\tgzip_vary on;\n"
		}
		conf = conf + "\tgzip_proxied " + strings.Join(gzipJson.GzipProxied, " ") + ";\n"
		conf = conf + "\tgzip_disable \"MSIE [1-6]\\.\";\n\n"
		return conf

	}
	return conf
}

func ParseError502() string {
	return "\terror_page 502 /502.html;\n\tlocation = /502.html {\n\t\troot /etc/nginx/waf/html;\n\t}\n\n"
}

func ParseSSLJson(siteJson types.SiteJson) string {
	conf := ""
	if siteJson.Server.Ssl.IsSsl == 1 {
		sslInfo := siteJson.Server.Ssl
		conf = conf + "\tssl_certificate " + sslInfo.SSLCertificate + ";\n"
		conf = conf + "\tssl_certificate_key " + sslInfo.SSLCertificateKey + ";\n"
		conf = conf + "\tssl_protocols " + strings.Join(sslInfo.SSLProtocols, " ") + ";\n"
		conf = conf + "\tssl_ciphers " + strings.Join(sslInfo.SSLCiphers, " ") + ";\n"
		conf = conf + "\tssl_prefer_server_ciphers " + sslInfo.SSLPreferServerCiphers + ";\n"
		conf = conf + "\tssl_session_cache " + strings.Join(sslInfo.SSLSessionCache, " ") + ";\n"
		conf = conf + "\tssl_session_timeout " + sslInfo.SSLSessionTimeout + ";\n"
		conf = conf + "\tadd_header " + strings.Join(sslInfo.AddHeader, " ") + ";\n"
		conf = conf + "\terror_page " + strings.Join(sslInfo.ErrorPage, " ") + ";\n\n"
	}
	if siteJson.Server.Ssl.ForceHttps == 1 {
		conf = conf + "\tif ($server_port !~ 443) {\n\t\trewrite \"^(/.*)$\" https://$host$1 permanent;\n\t}\n\n "
	}
	return conf
}

func ParseRootJson(siteJson types.SiteJson) string {
	defaultServer := " default_server"
	if siteJson.SiteID != "default_wildcard_domain_server" {
		defaultServer = ""
	}
	addedPorts := make(map[string]string, 0)
	conf := "server {\n"
	for _, v := range siteJson.Server.ListenPort {
		if _, ok := addedPorts[v]; ok {
			continue
		}
		conf = conf + "\tlisten " + v + defaultServer + ";\n"

		if siteJson.Server.ListenIpv6 == 1 {
			conf = conf + "\tlisten [::]:" + v + defaultServer + ";\n"

		}
		addedPorts[v] = "1"
	}

	addedSslPorts := make(map[string]string, 0)
	addedSslTwoPorts := make(map[string]string, 0)
	if siteJson.Server.Ssl.IsSsl == 1 {
		count := 0
		for _, v := range siteJson.Server.ListenSslPort {
			if _, ok := addedSslPorts[v]; ok {
				continue
			}

			count += 1
			if count == 1 {
				conf = conf + "\tlisten " + v + defaultServer + " ssl;\n\thttp2 on;\n"
			} else {
				conf = conf + "\tlisten " + v + defaultServer + " ssl;\n"
			}
			addedSslPorts[v] = "1"
		}
		if siteJson.Server.ListenIpv6 == 1 {
			for _, v := range siteJson.Server.ListenSslPort {
				if _, ok := addedSslTwoPorts[v]; ok {
					continue
				}
				conf = conf + "\tlisten [::]:" + v + defaultServer + " ssl;\n"
				addedSslTwoPorts[v] = "1"
			}
		}

	}
	serverName := siteJson.Server.ServerName
	if siteJson.SiteID == "default_wildcard_domain_server" {
		serverName = []string{"_"}
	}
	conf = conf + "\tserver_name " + siteJson.SiteID + " " + strings.Join(serverName, " ") + ";\n"
	conf = conf + "\tindex " + strings.Join(siteJson.Server.Index, ",") + ";\n"
	conf = conf + "\troot " + siteJson.Server.Root + ";\n\n"
	return conf
}

func ReplaceHttp(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if strings.Contains(domain, "https://") {
		domain = strings.ReplaceAll(domain, "https://", "")
	}
	if strings.Contains(domain, "http://") {
		domain = strings.ReplaceAll(domain, "http://", "")
	}
	return domain
}

func splitDomainSplitIndex(domain string, splitString string, index int) string {
	return strings.Split(domain, ":")[index]
}

func getdomainSlice(domain []string, serverName []string, appendPort string) []string {
	domainMap := make(map[string]string, 0)
	for _, v := range domain {
		v = ReplaceHttp(v)
		if !strings.Contains(v, ":") {
			v = v + ":" + appendPort
		}
		v = splitDomainSplitIndex(v, ":", 0)
		domainMap[v] = "1"
	}
	for k, _ := range domainMap {
		serverName = append(serverName, k)
	}
	sort.Strings(serverName[1:])
	return serverName

}

func getDomainPortSlice(domain []string, ListenTag []string, appendPort string) []string {
	domainMap := make(map[string]string, 0)
	for _, v := range domain {
		v = ReplaceHttp(v)
		if !strings.Contains(v, ":") {
			v = v + ":" + appendPort
		}
		domainMap[v] = "1"
	}
	if ListenTag != nil && len(ListenTag) > 0 {
		for _, v := range ListenTag {
			domainMap[v] = "1"
		}
	}
	ListenTag = make([]string, 0)
	for k, _ := range domainMap {
		strings.Split(k, ":")
		ListenTag = append(ListenTag, k)
	}
	sort.Strings(ListenTag)
	return ListenTag
}

func getdomainPort(domain []string, port []string, appendPort string, isSsl int) ([]string, []string) {
	domainMap := make(map[string]string, 0)
	portMap := make(map[string]string, 0)
	sslPortDelete := false
	for _, v := range domain {
		v = ReplaceHttp(v)
		if !strings.Contains(v, ":") {
			v = v + ":" + appendPort
		}
		v = splitDomainSplitIndex(v, ":", 1)
		domainMap[v] = "1"
	}

	for k, _ := range domainMap {
		port = append(port, k)
	}
	for _, v := range port {
		portMap[v] = "1"
	}
	port = make([]string, 0)
	for k, _ := range portMap {
		port = append(port, k)
	}
	sort.Strings(port)
	if _, ok := domainMap["443"]; !ok {
		sslPortDelete = true
	}
	sslPort := "443"
	for i, v := range port {
		if v == "80" {
			continue
		}
		if sslPortDelete && v == "443" && sslPort == "443" {
			if len(port) == 1 {
				port = make([]string, 0)
			} else {
				port = append(port[:i], port[i+1:]...)
			}
			break
		}
		if isSsl == 1 {
			sslPort = v
			if len(port) == 1 {
				port = make([]string, 0)
			} else {
				port = append(port[:i], port[i+1:]...)
			}

		} else {
			sslPort = ""
		}
		break
	}
	if isSsl == 0 {
		sslPort = ""
	}
	return port, []string{sslPort}
}

func ReadSliceLog() string {
	readStr, err := public.ReadFile(SliceSiteLogPath)
	if err != nil {
		return ""
	}
	return readStr
}
func ReplaceDate(nowStr string) string {
	nowStr = strings.Replace(nowStr, " ", "_", -1)
	nowStr = strings.Replace(nowStr, ":", "", -1)

	return nowStr
}

func SliceSiteLog() {
	public.WriteFile(SliceSiteLogPath, "\n\n\n"+ReadSliceLog()+"\n"+public.GetNowTimeStr()+"开始切割网站日志...")
	jsonData, err := os.ReadFile(types.SiteIdPath)
	if err != nil {
		public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"读取文件失败:"+types.SiteIdPath+"\n退出日志切割任务"+err.Error())
		return
	}
	var siteId map[string]string
	err = json.Unmarshal(jsonData, &siteId)
	if err != nil {
		public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"反序列化数据失败:"+types.SiteIdPath+"\n退出日志切割任务"+err.Error())
		return
	}
	for id, _ := range siteId {
		isAddJson := false
		siteslicejson := types.SliceSiteLogJson + id + ".json"
		data := make([]map[string]string, 0)
		if public.FileExists(siteslicejson) {
			jsonData, err := os.ReadFile(siteslicejson)
			if err != nil {
				continue
			}
			err = json.Unmarshal(jsonData, &data)
			if err != nil {
				continue
			}
		}
		logjson := make(map[string]string)
		nowStr := ReplaceDate(public.GetNowTimeStr())
		backupPath := types.HistoryBackupPath + "logs/" + id + "/"
		backupPathAccess := backupPath + "access_log/"
		backupPathError := backupPath + "error_log/"
		backupPathSlow := backupPath + "slow_log/"
		backupFileAccess := backupPathAccess + id + "_access_" + nowStr + ".log"
		backupFileError := backupPathError + id + "_error_" + nowStr + ".log"
		backupFileSlow := backupPathSlow + id + "_slow_" + nowStr + ".log"
		backupPaths := []string{backupPath, backupPathAccess, backupPathError, backupPathSlow}
		logjson["access"] = backupFileAccess + ".zip"
		logjson["error"] = backupFileError + ".zip"
		logjson["slow"] = backupFileSlow + ".zip"

		for _, v := range backupPaths {
			if !public.FileExists(backupPath) {
				err := os.MkdirAll(v, 0755)
				if err != nil {
					public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 创建目录失败:"+filepath.Dir(v)+"\n"+err.Error())
					continue
				}
			}
		}
		backupLogFile := []string{types.LogRootPath + id + ".log", types.LogRootPath + id + ".error.log", types.LogRootPath + id + ".slow.log"}
		for _, v := range backupLogFile {
			logPaths := []string{backupPathAccess, backupPathError, backupPathSlow}
			for _, v1 := range logPaths {
				if !public.FileExists(v1) {
					err := os.MkdirAll(v1, 0755)
					if err != nil {
						public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 创建目录失败:"+filepath.Dir(v)+"\n"+err.Error())
						continue
					}
				}
			}
			zipName := backupFileAccess
			if public.FileExists(v) {
				switch {
				case strings.HasSuffix(v, ".error.log"):
					zipName = backupFileError
				case strings.HasSuffix(v, ".slow.log"):
					zipName = backupFileSlow
				}

				types.LogLock.Lock()
				err := compress.Zip(zipName+".zip", v)
				if err != nil {
					public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 压缩日志文件失败:"+v+"\n"+err.Error())
				}
				if public.FileExists(zipName + ".zip") {
					err = os.Truncate(v, 0)
					if err != nil {
						os.Remove(v)
						boolV, err := public.WriteFile(v, "")
						if !boolV {
							public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"清理过期日志文件失败:"+err.Error())
						}
						public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"清理过期日志文件成功:"+v)
					}
					isAddJson = true
					public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 压缩日志文件成功:"+v+"\n压缩后文件名为："+zipName+".zip")
				} else {
					public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 压缩日志文件失败:"+v)
				}
				types.LogLock.Unlock()

			} else {
				public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 日志文件不存在:"+v+",跳过此日志文件日志切割")
			}
		}
		err = ReloadNginx()
		if err != nil {
			ReloadNginx()
			public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+" 重载nginx失败:"+err.Error())
		}

		if !isAddJson {
			continue
		} else {
			data = append(data, logjson)
		}
		backupNum := 180
		if len(data) > backupNum {
			for _, v := range data[:len(data)-backupNum] {
				for _, v1 := range v {
					if public.FileExists(v1) {
						err = os.Remove(v1)
						if err != nil {
							public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"清理过期日志文件失败:"+err.Error())
							continue
						}
						public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"清理过期日志文件成功:"+v1)
					}
					data = data[1:]
					if len(data) <= backupNum {
						break
					}
				}
			}
		}
		jsonStr, err := json.Marshal(data)
		if err != nil {
			public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"转换json失败:"+err.Error())
			continue
		}
		boolV, err := public.WriteFile(siteslicejson, string(jsonStr))
		if !boolV {
			public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"写入json配置文件失败:"+err.Error())
			continue
		}

	}
	public.WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+public.GetNowTimeStr()+"切割网站日志任务已执行\n")
}

func CheckDomainParseByAddress(domain, checkAddress string) bool {
	addresses, err := net.LookupHost(domain)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if address == checkAddress {
			return true
		}
	}
	return false
}

func CheckDomainParseByDomain(domain string) bool {
	addresses, err := net.LookupHost(domain)
	if err != nil {
		return false
	}
	if len(addresses) == 0 {
		return false
	}
	return true
}

func (s *Wafmastersite) GetParseRecordByDomain(request *http.Request) core.Response {
	domain := struct {
		Domain string `json:"domain"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &domain); err != nil {
		return core.Fail(err)
	}
	addresses, err := net.LookupHost(domain.Domain)
	if err != nil {
		return core.Fail("无法获取解析记录")
	}

	for _, address := range addresses {
		logging.Debug("解析记录:", address)
	}
	return core.Success("同步网站配置已执行")
}

func GetNodeRealTimeData() {

	siteIds, err := public.M("site_info").Field([]string{"site_id"}).Select()
	if err != nil {
		return
	}
	for _, siteId := range siteIds {
		query := public.M("site_info").
			Field([]string{"site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
			Order("create_time", "desc").
			Where("site_id=?", siteId["site_id"])
		res, err := query.Find()
		if err != nil {
			continue
		}
		if res["load_group_id"].(int64) == 0 {
			continue
		}
		loadBalance, err := public.M("load_balance").Field([]string{"nodes"}).Where("id=?", []any{res["load_group_id"].(int64)}).Find()
		nodes := []*types.LoadNodes{}
		if err := json.Unmarshal([]byte(loadBalance["nodes"].(string)), &nodes); err != nil {
			continue
		}
	}
	return
}

func (s *Wafmastersite) GetLogList(request *http.Request) core.Response {
	params := struct {
		SiteId      string `json:"site_id"`
		Types       string `json:"types"`
		LoadGroupId int64  `json:"load_group_id"`
		NodeId      string `json:"node_id"`
		Itself      int    `json:"itself"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	result, _ := s.getFilesInDirectory(params.LoadGroupId, params.NodeId, params.SiteId, params.Types, params.Itself)
	return core.Success(result)
}

func (s *Wafmastersite) getFilesInDirectory(groudId int64, nodeId string, siteId string, logType string, itself int) (any, error) {
	if logType != "error" && logType != "access" && logType != "slow" {
		logType = "access"
	}
	dirPath := "/www/cloud_waf/vhost/history_backups/logs/" + siteId + "/" + logType + "_log"
	var fileInfos []map[string]interface{}
	dir, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
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

func (s *Wafmastersite) ModifyResolver(request *http.Request) core.Response {
	params, err := public.ParamsCheck(request, []string{"site_id", "status", "inspection_time"}, "参数错误")
	if err != nil {
		return core.Fail(err)
	}
	siteId := public.InterfaceToString(params["site_id"].(interface{}))
	status := public.InterfaceToInt(params["status"].(interface{}))
	inspectionTime := public.InterfaceToInt(params["inspection_time"].(interface{}))
	siteName := ""
	ress, err := public.M("site_info").Field([]string{"site_name"}).Where("site_id=?", siteId).Find()
	if err != nil {
		return core.Fail(err)
	}
	siteName = ress["site_name"].(string)
	if status == 1 {
		sourceSlice, err := GetSiteReturnDomain(siteId)
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
	public.WriteOptLog(fmt.Sprintf(siteName+"网站-回源域名地址巡检成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("配置成功")

}

func GetSiteReturnDomain(siteId string) (map[string]string, error) {
	sourceSlice := make(map[string]string, 0)
	data, err := GetSiteJson(siteId)
	if err != nil {
		return sourceSlice, err
	}
	if len(data.Server.Upstream.Server) > 0 {
		for _, v := range data.Server.Upstream.Server {
			address := strings.TrimSpace(v.Address)
			address = ReplaceHttp(address)
			if strings.Contains(address, ":") {
				address = strings.Split(address, ":")[0]
			}
			if public.IsIpv4(address) {
				continue
			}

			if _, ok := sourceSlice[address]; !ok {
				sourceSlice[address] = "1"
			}
		}
	}
	return sourceSlice, nil
}

func SiteSourceAddressAutoCheck() {
	res, err := public.M("site_return_domain_check").Select()
	if err != nil {
		return
	}
	isReload := false
	for _, v := range res {
		var oldDomainParse map[string]map[string]string
		if err := json.Unmarshal([]byte(v["parse_info"].(string)), &oldDomainParse); err != nil {
			continue
		}
		if len(oldDomainParse) < 1 {
			continue
		}
		siteId := v["site_id"].(string)
		sourceSlice, err := GetSiteReturnDomain(siteId)
		if err != nil {
			continue
		}
		newDomainParse, err := public.GetDomainParse(sourceSlice)
		if err != nil {
			continue
		}
		isUpdate := false
		for k, _ := range newDomainParse {
			newParseSame := true
			for i := 0; i < 4; i++ {
				newDomainParseTmp, err := public.GetDomainParse(sourceSlice)
				if err != nil {
					continue
				}
				if len(newDomainParse) != len(newDomainParseTmp) {
					newParseSame = false
					break
				}
			}
			if !newParseSame {
				continue

			}
			if _, ok := oldDomainParse[k]; !ok {
				isUpdate = true
			}
			if len(oldDomainParse[k]) != len(newDomainParse[k]) {
				isUpdate = true
			}
			for k1, _ := range newDomainParse[k] {
				if _, ok := oldDomainParse[k][k1]; !ok {
					isUpdate = true
				}
			}
		}
		if len(oldDomainParse) != len(newDomainParse) {
			isUpdate = true
		}
		if isUpdate {
			isReload = true
			newDomainParseJson, err := json.Marshal(newDomainParse)
			if err != nil {
				continue
			}
			public.M("site_return_domain_check").Where("site_id=?", siteId).Update(map[string]any{"parse_info": string(newDomainParseJson), "last_exec_time": time.Now().Unix()})
		}
	}
	if isReload {
		ReloadNginx()
	}
}

func (s *Wafmastersite) DownloadLog(request *http.Request) core.Response {
	params := struct {
		SiteId      string  `json:"site_id"`
		Types       string  `json:"types"`
		FileName    string  `json:"filename"`
		Delete      float64 `json:"delete"`
		Download    float64 `json:"download"`
		LoadGroupId int64   `json:"load_group_id"`
		NodeId      string  `json:"node_id"`
		Itself      int     `json:"itself"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	count, err := public.M("site_info").Where("site_id=? and site_name=?", params.SiteId).Count()
	if err != nil {
		return core.Fail("查询站点失败")
	}
	if count == 0 {
		return core.Fail("查询站点失败")
	}
	if params.Types != "error" && params.Types != "access" && params.Types != "slow" {
		params.Types = "access"
	}
	dir_path := core.AbsPath("/www/cloud_waf/vhost/history_backups/logs/") + params.SiteId + "/" + params.Types + "_log/"

	files, err := os.ReadDir(dir_path)
	if err != nil {
		return core.Fail(err)
	}
	var flag = false
	for _, file := range files {
		if file.Name() == params.FileName {
			flag = true
			break
		}
	}
	if !flag {
		return core.Fail("文件不存在")
	}

	if _, err := os.Stat(dir_path + params.FileName); err != nil {
		if os.IsNotExist(err) {
			return core.Fail("文件不存在")
		}
		return core.Fail(err)
	}

	file_name := dir_path + params.FileName
	if params.Download == 1 {
		response, err := core.DownloadFile(file_name, params.FileName)
		if err != nil {
			return core.Fail(err)
		}
		return response
	}

	return core.Success("操作成功")
}

func (s *Wafmastersite) GetSiteAllNode(request *http.Request) core.Response {
	siteJson := types.SyncSiteJson{}
	if err := core.GetParamsFromRequestToStruct(request, &siteJson); err != nil {
		return core.Fail(err)
	}
	nodes, err := public.M("cluster_nodes").Field([]string{"sid", "itself", "remark"}).Where("is_online=? and group_id=?", []any{1, siteJson.LoadGroupId}).Select()
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(nodes)
}

func SyncRenewalCertSite(siteId string) {
	SslInfo, totla, err := GetSiteSslInfos(siteId)
	if err != nil {
		return
	}
	if totla == 0 {
		return
	}
	if len(SslInfo) == 0 {
		return
	}
	var SiteJson types.SiteJson
	for _, v := range SslInfo {
		SiteJson = v
		break
	}
	if SiteJson.Server.Ssl == nil || SiteJson.Server.Ssl.IsSsl == 0 {
		return
	}
	if SiteJson.Server.Ssl.SslType != "Let's Encrypt" {
		return
	}
	SslDay := SiteJson.Server.Ssl.NotAfter.Unix() - time.Now().Unix()
	Day := SslDay / 86400
	if Day < 20 {
		if SiteJson.Server.Ssl.ForceHttps == 1 {
			params := map[string]interface{}{
				"site_id": SiteJson.SiteID,
				"types":   "closeForceHttps",
				"server": map[string]interface{}{
					"ssl": map[string]interface{}{
						"force_https": 0,
					},
				},
			}
			paramss := struct {
				SiteId string `json:"site_id"`
				Types  string `json:"types"`
				server struct {
					Ssl struct {
						ForceHttps int `json:"force_https"`
					}
				}
			}{}
			if err := core.MapToStruct(params, &paramss); err != nil {
				return
			}
			_, err := core.CallModuleActionSimulateAssertJson("Wafmastersite", "ModifySite", params)
			if err != nil {
				return
			}
		}
		_, err := ApplyCert(SiteJson.Server.Ssl.Domains, SiteJson.Server.Ssl.ApplyType, GetSslEmail(), siteId)
		if err != nil {
			return
		}
	}
}

/*
@name 每天2点或者3点随机时间执行 续签SSL
*/
func SyncRenewalCert() {
	SiteList, err := public.M("site_info").Field([]string{"site_id"}).Select()
	if err != nil {
		return
	}
	for v := range SiteList {
		SiteId := SiteList[v]["site_id"].(string)
		SyncRenewalCertSite(SiteId)
	}

}
