package providers

import (
	"CloudWaf/core/logging"
	"CloudWaf/modules"
	"CloudWaf/public"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/types"
	"fmt"
	"os"
)

func init() {
	nw := &nginxWafProvider{}
	registerProviderAlways(nw.addRceRule)
	registerProviderAlways(nw.addIsCcUrl)
	registerProviderAlways(nw.setHeaderLenContentType)
	registerProviderAlways(nw.cdnSiteConfig)
	registerProviderAlways(nw.WithImageRepairSiteConfig)
	registerProviderAlways(nw.addConfigRouteToken)
	registerProviderAlways(nw.SetLastestRule)
	registerProviderAlways(nw.installAcme)
	registerProviderAlways(nw.nginxConfCover)
}

type nginxWafProvider struct{}

func (nw *nginxWafProvider) addRceRule() {
	rceInfo := types.ConfigOrdinaryInfo{
		Mode: 2,
		Ps:   "命令执行拦截",
	}
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return
	}
	if _, ok := jsonData.(map[string]interface{})["rce"]; !ok {
		jsonData.(map[string]interface{})["rce"] = rceInfo
	}
	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return
	}
	siteIds, err := public.GetSiteId()
	if err != nil {
		fmt.Println("Error :", err)
		return
	}
	siteWafJsonData, err := public.GetWafSiteConfigRules()
	if err != nil {
		return
	}
	for id, _ := range siteIds {
		if _, ok := siteWafJsonData.(map[string]interface{})[id]; !ok {
			continue
		}
		if _, ok := siteWafJsonData.(map[string]interface{})[id].(map[string]interface{})["rce"]; !ok {
			siteWafJsonData.(map[string]interface{})[id].(map[string]interface{})["rce"] = rceInfo
		}

	}

	err = public.WriteSiteConfig(siteWafJsonData)
	if err != nil {
		return
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

}

func (nw *nginxWafProvider) setHeaderLenContentType() {
	jsonData, err := public.GetGlobalConfigRules()
	if err != nil {
		return
	}
	if _, ok := jsonData.(map[string]interface{})["header_len"]; ok {
		jsonData.(map[string]interface{})["header_len"].(map[string]interface{})["content-type"] = 512
	}
	if _, ok := jsonData.(map[string]interface{})["password"]; !ok {
		jsonData.(map[string]interface{})["password"] = types.ConfigOrdinaryInfo{
			Mode: 1,
			Ps:   "实时检测弱密码登录并拦截",
		}
	}
	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)

}

func (nw *nginxWafProvider) cdnSiteConfig() {
	siteIds, err := public.GetSiteId()
	if err != nil {
		return
	}
	for siteId, _ := range siteIds {

		if public.GetCdnRule(siteId) {
			siteJson, err := modules.GetSiteJson(siteId)
			if err != nil {
				continue
			}
			err = modules.ParseSiteJson(siteJson)
			if err != nil {
				continue
			}
		}
	}

}

func (nw *nginxWafProvider) WithImageRepairSiteConfig() {
	siteIds, err := public.GetSiteIdByDatabase()
	if err != nil {
		return
	}
	for siteId, _ := range siteIds {

		siteJson, err := modules.GetSiteJson(siteId)
		if err != nil {
			continue
		}
		err = modules.ParseSiteJson(siteJson)
		if err != nil {
			continue
		}
	}

}

func (nw *nginxWafProvider) addIsCcUrl() {
	isCcUrl := true
	filePathS := map[string]string{"global": public.GlobalConfig, "site": public.SiteConfig}

	for k, v := range filePathS {
		jsonData, err := public.ReadInterfaceFileBytes(v)
		if err != nil {
			continue
		}
		switch k {
		case "global":
			accessCc := jsonData.(map[string]interface{})["cc"].(map[string]interface{})
			if _, ok := accessCc["is_cc_url"]; !ok {
				accessCc["is_cc_url"] = isCcUrl
				jsonData.(map[string]interface{})["cc"] = accessCc
				err = public.WriteGlobalConfig(jsonData)
				if err != nil {
					continue
				}
			}
		case "site":
			for siteId, value := range jsonData.(map[string]interface{}) {
				if _, ok := value.(map[string]interface{})["cc"].(map[string]interface{}); ok {
					accessSiteCc := value.(map[string]interface{})["cc"].(map[string]interface{})
					if _, ok = accessSiteCc["is_cc_url"]; !ok {
						accessSiteCc["is_cc_url"] = isCcUrl
						jsonData.(map[string]interface{})[siteId] = value
						err = public.WriteSiteConfig(jsonData)
						if err != nil {
							continue
						}
					}
				}

			}
		}
	}
	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()

}

func (nw *nginxWafProvider) addConfigRouteToken() {
	routeToken := public.RandomStr(32)
	jsonData, err := public.ReadInterfaceFileBytes(public.GlobalConfig)
	if err != nil {
		return
	}
	if _, ok := jsonData.(map[string]interface{})["route_token"].(string); !ok {
		jsonData.(map[string]interface{})["route_token"] = routeToken
	} else {
		if jsonData.(map[string]interface{})["route_token"].(string) == "" {
			jsonData.(map[string]interface{})["route_token"] = routeToken
		}
	}
	err = public.WriteGlobalConfig(jsonData)
	if err != nil {
		return
	}

	public.UpdateWafConfig("config", 2)
	public.UpdateWafConfig("rule", 2)
	public.BackupWebWafConfig()
}

func (nw *nginxWafProvider) SetLastestRule() {
	oldFile := "/www/cloud_waf/console/config/waf_site.json"
	newFile := "/www/cloud_waf/console/config/waf_site_new.json"
	defer os.Remove(newFile)
	if public.FileExists(newFile) {
		writeString, err := public.ReadFile(newFile)
		if err != nil {
			return
		}
		_, err = public.WriteFile(oldFile, writeString)
		if err != nil {
			return
		}
	}
	return
}

func (nw *nginxWafProvider) installAcme() {
	err := modules.InstallAcme(modules.GetSslEmail(), "letsencrypt")
	if err != nil {
		logging.Error("安装acme失败:", err)
		return
	}
	return

}

func (nw *nginxWafProvider) nginxConfCover() {
	if clusterCommon.ClusterState() != clusterCommon.CLUSTER_DISABLED {
		newNginx := "/www/cloud_waf/nginx/conf/nginx_conf.new"
		oldNginx := "/www/cloud_waf/nginx/conf/nginx.conf"
		if public.FileExists(newNginx) {
			if public.FileExists(oldNginx) {
				err := os.Rename(oldNginx, oldNginx+".bak")
				if err != nil {
					return
				}
				err = os.Rename(newNginx, oldNginx)
				if err != nil {
					return
				}
				err = public.ReloadNginx()
				if err != nil {
					return
				}

			}
		}
	}
}
