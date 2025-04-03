package public

import (
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	WafPath       = NginxPath + "conf.d/waf"
	WafConfigPath = WafPath + "/config/"
	SiteConfig    = WafConfigPath + "site.json"
	GlobalConfig  = WafConfigPath + "config.json"

	RegionalRestrictionsPaths = []string{ProvinceConfig, CityConfig}
	ConfigPaths               = []string{SiteGlobalConfig, GlobalConfig}
	WafSitePaths              = []string{SiteWafConfigJson, SiteConfig}
	WebWafConfig              = []string{DomainConfig, SiteConfig, GlobalConfig}
	SiteMode                  = map[int]string{0: "关闭防护模式", 1: "只记录模式", 2: "拦截模式", 3: "显示维护页模式"}
	SiteWafMode               = map[int]string{0: "关闭防护模式", 1: "观察模式", 2: "标准模式", 3: "严格模式"}
)

func init() {
	CheckWebWafConfig()
	CheckWafConfig()
	CheckWafSiteConfig()
}

func CheckWafConfig() {
	if !FileExists(SiteGlobalConfig) {
		jsonData, err := GetGlobalConfigRules()
		if err != nil {
			return
		}
		WriteInterfaceFile(SiteGlobalConfig, jsonData)
	}
}

func CheckWafSiteConfig() {
	if !FileExists(SiteWafConfigJson) {
		jsonData, err := GetWafSiteConfigRules()
		if err != nil {
			return
		}
		WriteInterfaceFile(SiteWafConfigJson, jsonData)
	}
}

func WriteInterfaceFile(filePath string, jsonData interface{}) error {
	writeData, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}
	boolV, err := WriteFile(filePath, string(writeData))
	if !boolV {
		return err
	}
	return nil
}

func WriteGlobalConfig(jsonData interface{}) error {
	for _, v := range ConfigPaths {
		err := WriteInterfaceFile(v, jsonData)
		if err != nil {
			fmt.Println("err:", err)
			return err
		}
	}
	return nil
}

func WriteSiteConfig(jsonData interface{}) error {
	for _, v := range WafSitePaths {
		err := WriteInterfaceFile(v, jsonData)
		if err != nil {
			fmt.Println("err:", err)
			return err
		}
	}
	return nil
}

func WriteListInterfaceFile(filePath string, jsonData []interface{}) error {
	writeData, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}
	boolV, err := WriteFile(filePath, string(writeData))
	if !boolV {
		return err
	}
	return nil
}

func GetWafSiteConfigRules() (interface{}, error) {
	for _, v := range WafSitePaths {
		if FileExists(v) {
			jsonData, err := ReadInterfaceFileBytes(v)
			if err == nil {
				return jsonData, nil
			}

		}
	}
	siteId, err := GetSiteId()
	if err != nil {
		return nil, errors.New("未找到配置文件")
	}
	if len(siteId) == 0 {
		return nil, errors.New("未找到配置文件")
	}

	for _, v := range siteId {
		isCdn := false
		data, err := GetSiteJson(v)
		if err == nil {
			isCdn = data.IsCDN
		}
		err = CreateWafConfigJson(v, isCdn)
		if err != nil {
			fmt.Println("Error :", err)
		}
	}
	return nil, errors.New("未找到配置文件")
}

func GetGlobalConfigRules() (interface{}, error) {
	for _, v := range ConfigPaths {
		if FileExists(v) {
			jsonData, err := ReadInterfaceFileBytes(v)
			if err == nil {
				return jsonData, nil
			}

		}
	}
	return nil, errors.New("未找到配置文件")
}

func GetSpecifyGlobalConfigRules(types string) (interface{}, error) {
	jsonData, err := GetGlobalConfigRules()
	if err != nil {
		return false, err
	}
	if _, ok := jsonData.(map[string]interface{})[types]; ok {
		return jsonData.(map[string]interface{})[types], nil
	}
	return nil, errors.New("未找到" + types + "对应配置")
}

func BackupWebWafConfig() {
	BackupFile(WebWafConfig, HistoryBackupConfig, "src")
}

func CheckWebWafConfig() {
	for _, v := range WebWafConfig {
		if FileExists(v) {
			readStr, err := ReadFile(v)
			if err == nil && readStr != "" {
				continue
			}
		}
		fileName := filepath.Base(v)
		if fileName == "" {
			continue
		}
		BackupFile := HistoryBackupConfig + fileName

		if !FileExists(BackupFile) {
			continue
		}
		readStr, err := ReadFile(BackupFile)
		if err != nil || readStr == "" {
			continue
		}
		writeStr, err := ReadFile(BackupFile)
		if err != nil || writeStr == "" {
			continue
		}
		WriteFile(v, writeStr)
	}
}

func DelSiteRegion(siteId string, filePath string) error {
	jsonData, err := ReadListInterfaceFileBytes(filePath)
	if err != nil {
		return err
	}
	for i, v := range jsonData {
		if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})[siteId]; ok {
			jsonData = append(jsonData[:i], jsonData[i+1:]...)
		}
	}
	err = WriteListInterfaceFile(filePath, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func ReadMapStringInterfaceFile(filePath string) (map[string]interface{}, error) {
	jsonStr, err := ReadFileBytes(filePath)
	if err != nil {
		return nil, err
	}
	var jsonData map[string]interface{}
	if err = json.Unmarshal(jsonStr, &jsonData); err != nil {
		fmt.Println("err:", err)
		return nil, err
	}
	return jsonData, nil
}

func GetSmartCcOpen(siteId string) (bool, error) {
	jsonData, err := ReadMapStringInterfaceFile(SiteConfig)
	if err != nil {
		return false, err
	}
	siteData, ok := jsonData[siteId].(map[string]interface{})
	if !ok {
		return false, errors.New("网站配置不存在")
	}
	smartCCData, ok := siteData["smart_cc"].(map[string]interface{})
	if !ok {
		return false, errors.New("智能CC配置不存在")
	}
	open, ok := smartCCData["open"].(bool)
	if !ok {
		return false, errors.New("智能CC防御未开启")
	}

	return open, nil
}

func GetAllSmartCcOpen() map[string]string {
	resultMap := make(map[string]string, 0)
	jsonData, err := ReadMapStringInterfaceFile(SiteConfig)
	if err != nil {
		return resultMap
	}
	siteId, err := GetSiteId()
	if err != nil {
		return resultMap
	}

	for _, v := range siteId {
		siteData, ok := jsonData[v].(map[string]interface{})
		if !ok {
			continue
		}
		smartCCData, ok := siteData["smart_cc"].(map[string]interface{})
		if !ok {
			continue
		}

		open, ok := smartCCData["open"].(bool)
		if !ok {
			continue
		}
		if open {
			resultMap[v] = "1"
		}
	}
	return resultMap
}

func WriteMapStringInterfaceFile(filePath string, jsonData map[string]interface{}) error {
	writeData, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}
	boolV, err := WriteFile(filePath, string(writeData))
	if !boolV {
		return err
	}
	return nil
}

func SetSingleUriRules(uri string, cycle int, frequency int, types string) (bool, error) {
	jsonData, err := GetGlobalConfigRules()
	if err != nil {
		return false, err
	}
	if _, ok := jsonData.(map[string]interface{})["cc_uri_frequency"]; ok {
		switch types {
		case "add", "modify":
			jsonData.(map[string]interface{})["cc_uri_frequency"].(map[string]interface{})[uri] = map[string]interface{}{"frequency": frequency, "cycle": cycle}
		case "del":
			delete(jsonData.(map[string]interface{})["cc_uri_frequency"].(map[string]interface{}), uri)
		}
	} else {
		jsonData.(map[string]interface{})["cc_uri_frequency"] = map[string]interface{}{uri: map[string]interface{}{"frequency": frequency, "cycle": cycle}}
	}
	err = WriteGlobalConfig(jsonData)
	if err != nil {
		return false, err
	}
	return true, nil
}

func GetStartRulesByAllRegion() map[string]string {
	resultMap := make(map[string]string, 0)
	for _, v := range RegionalRestrictionsPaths {
		jsonData, err := ReadListInterfaceFileBytes(v)
		if err != nil {
			continue
		}

		for _, v := range jsonData {
			if v.(map[string]interface{})["status"].(bool) {
				if _, ok := v.(map[string]interface{})["site"].(map[string]interface{}); !ok {
					continue
				}
				for k, _ := range v.(map[string]interface{})["site"].(map[string]interface{}) {
					resultMap[k] = "1"
				}
			}
		}
	}
	return resultMap
}

func GetStartRulesByAllSite() map[string]string {
	resultMap := make(map[string]string, 0)
	jsonData, err := GetWafSiteConfigRules()
	if err != nil {
		return resultMap
	}
	for k, v := range jsonData.(map[string]interface{}) {
		if v.(map[string]interface{})["status"].(bool) {
			resultMap[k] = "1"
		}
	}
	return resultMap
}

func GetAllRegionRules(result_slice []interface{}, file_path string, searchStr string) []interface{} {
	var jsonData []map[string]interface{}
	jsonStr, err := ReadFileBytes(file_path)
	if err != nil {
		return result_slice
	}
	if err = json.Unmarshal(jsonStr, &jsonData); err != nil {
		return result_slice
	}
	replaceMap := map[string]string{"中国": "中国大陆(不包括[中国特别行政区:港,澳,台])", "海外": "中国大陆以外的地区(包括[中国特别行政区:港,澳,台])", "allsite": "全部网站"}
	isWrite := false
	jsonDataLen := len(jsonData)
	for i := jsonDataLen - 1; i > -1; i-- {
		v := jsonData[i]
		addV := v
		IsAdd := false
		siteName := ""
		if _, ok := v["site"].(map[string]interface{}); !ok {
			continue
		}
		site_id := ""
		for k, _ := range v["site"].(map[string]interface{}) {
			site_id = strings.ReplaceAll(k, ".", "_")
			if k == "allsite" {
				IsAdd = true
				siteName = replaceMap["allsite"]
			} else {
				if err != nil {
					break
				}
				siteName, _ = GetSiteNameBySiteId(k)
			}
			break
		}
		if siteName == "" {
			res, err := M("site_info").Field([]string{"site_name"}).Where("site_id=?", site_id).Find()
			if err == nil && len(res) > 0 {
				siteName = res["site_name"].(string)
			}
		}
		addV["site"] = siteName
		switch searchStr {
		case "":
			IsAdd = true
		default:
			if v["region_id"].(string) == searchStr {
				IsAdd = true
			}
			for k, _ := range v["region"].(map[string]interface{}) {
				if k == "中国" || k == "海外" {
					k = replaceMap[k]
				}
				if strings.Contains(k, searchStr) {
					IsAdd = true
				}
			}

			if strings.Contains(siteName, searchStr) {
				IsAdd = true
			}
		}
		if site_id != "allsite" && !FileExists(VhostPath+site_id+".conf") && !FileExists(SiteJsonPath+site_id+".json") {
			jsonData = append(jsonData[:i], jsonData[i+1:]...)
			UpdateSiteAuthInfo(siteName, "location", "disable")
			IsAdd = false
			isWrite = true

		}
		if IsAdd {
			result_slice = append(result_slice, addV)
		}
	}
	if isWrite {
		writeData, err := json.Marshal(jsonData)
		if err != nil {
			return result_slice

		}
		os.WriteFile(file_path, writeData, 0666)

	}
	return result_slice
}

func AddSpecifyRegionRules(site_ids []string, types string, region []string, region_id string, file_path string, uri string) error {
	jsonStr, err := ReadFileBytes(file_path)
	if err != nil {
		return err
	}
	var jsonData []interface{}
	if err = json.Unmarshal(jsonStr, &jsonData); err != nil {
		return err
	}
	addSiteS := make(map[string]interface{})
	for _, v := range site_ids {
		if v == "allsite" {
			addSiteS[v] = "1"
		} else {
			addSiteS[v] = "1"
		}
	}

	regionMap := make(map[string]interface{})
	for _, v := range region {
		regionMap[v] = "1"
	}

	jsonData = append(jsonData, map[string]interface{}{"types": types, "site": addSiteS, "region": regionMap, "uri": uri, "region_id": region_id, "status": true, "time": time.Now().Unix(), "count": 0})
	writeData, err := json.Marshal(jsonData)
	if err != nil {
		return err
	}

	if err := os.WriteFile(file_path, writeData, 0644); err != nil {
		return err
	}

	return nil
}

func GetSiteNameByRegionId(region_id string) (string, bool, error) {
	overseas := false
	for _, v := range RegionalRestrictionsPaths {
		jsonData, err := ReadListInterfaceFileBytes(v)
		if err != nil {
			continue
		}

		for _, v := range jsonData {
			if v.(map[string]interface{})["region_id"].(string) == region_id {
				if _, ok := v.(map[string]interface{})["region"].(map[string]interface{})["海外"]; ok {
					overseas = true
				}
				for k, _ := range v.(map[string]interface{})["site"].(map[string]interface{}) {
					return k, overseas, nil
				}
			}
		}
	}
	return "", overseas, errors.New("未找到对应的网站")
}

func StopSpecifyRegionStatus() error {
	for _, v := range RegionalRestrictionsPaths {
		jsonData, err := ReadListInterfaceFileBytes(v)
		if err != nil {
			return err
		}
		for _, v := range jsonData {
			v.(map[string]interface{})["status"] = false
		}
		err = WriteListInterfaceFile(v, jsonData)
		if err != nil {
			continue
		}
	}
	return nil
}

func SetSpecifyRegionStatus(regionId string, status bool, filePath string) error {
	jsonData, err := ReadListInterfaceFileBytes(filePath)
	if err != nil {
		return err
	}

	for _, v := range jsonData {
		if v.(map[string]interface{})["region_id"].(string) == regionId {
			v.(map[string]interface{})["status"] = status
		}
	}
	err = WriteListInterfaceFile(filePath, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func GetRulesBySiteId(siteId string) (map[string]interface{}, error) {
	resultSlice := make(map[string]interface{})
	jsonData, err := GetWafSiteConfigRules()
	if err != nil {
		return resultSlice, err
	}
	for k, v := range jsonData.(map[string]interface{}) {
		if k == siteId {
			resultSlice = v.(map[string]interface{})
		}
	}
	return resultSlice, nil
}

func ResetSpecifyRegionCount(regionId string, filePath string) error {
	jsonData, err := ReadListInterfaceFileBytes(filePath)
	if err != nil {
		return err
	}

	for _, v := range jsonData {
		if v.(map[string]interface{})["region_id"].(string) == regionId {
			v.(map[string]interface{})["count"] = 0
		}
	}
	err = WriteListInterfaceFile(filePath, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func DelRegionalRestrictionsRules(regionId []string, filePath string) (string, string, error) {
	types := ""
	regionList := ""
	jsonData, err := ReadListInterfaceFileBytes(filePath)
	if err != nil {
		return "", "", err
	}
	delIndex := make([]int, 0)
	for i, v := range jsonData {
		for _, v1 := range regionId {
			if v.(map[string]interface{})["region_id"].(string) == v1 {
				types = types + v.(map[string]interface{})["types"].(string)
				for k, _ := range v.(map[string]interface{})["region"].(map[string]interface{}) {
					if regionList == "" {
						regionList = k
						continue
					} else {
						regionList = regionList + "," + k
					}
				}
				delIndex = append(delIndex, i)
			}
		}
	}
	sort.Slice(delIndex, func(i, j int) bool {
		return delIndex[i] > delIndex[j]
	})
	for i, _ := range delIndex {
		jsonData = append(jsonData[:delIndex[i]], jsonData[delIndex[i]+1:]...)
	}
	err = WriteListInterfaceFile(filePath, jsonData)
	if err != nil {
		return "", "", err
	}
	return types, regionList, nil
}

func WafRuleBackup() {
	ruleFiles := []string{"args", "cc", "city", "cookie", "customize", "customize_count", "ip_black", "ip_group", "ip_white", "malicious_ip", "malicious_ip_total", "province", "replacement", "rule_hit_list", "scan", "speed", "speed_show", "ua_black", "ua_white", "url", "url_black", "url_white", "user_agent", "white"}
	timestamp := InterfaceToString(time.Now().Unix())
	AppendFile(types.WafRuleLogPath, "开始执行waf rule规则备份任务---------------------", true)
	for _, v := range ruleFiles {
		vBackupPath := types.WafRuleHistoryPath + v + "/"
		sourceFile := types.RulePath + v + ".json"
		AppendFile(types.WafRuleLogPath, "开始备份文件："+sourceFile, true)
		if !FileExists(vBackupPath) {
			AppendFile(types.WafRuleLogPath, "备份目录不存在，正在创建备份目录："+vBackupPath, true)
			err := os.MkdirAll(vBackupPath, 0755)
			if err != nil {
				AppendFile(types.WafRuleLogPath, "创建备份目录失败："+err.Error()+"\n", true)
				continue
			}
			if !FileExists(types.WafRuleHistoryPath + v) {
				AppendFile(types.WafRuleLogPath, "跳过此文件备份："+sourceFile+"\n", true)
				continue
			}
		}
		if !FileExists(sourceFile) {
			AppendFile(types.WafRuleLogPath, "以下文件不存在文件，跳过此文件备份："+sourceFile+"\n", true)
			continue
		}
		writeString, err := ReadFile(sourceFile)
		if err != nil {
			AppendFile(types.WafRuleLogPath, "读取文件失败："+sourceFile+"\n", true)
		}
		writeFile := vBackupPath + timestamp + ".json"
		AppendFile(types.WafRuleLogPath, "备份文件："+writeFile, true)
		boolV, err := WriteFile(writeFile, writeString)
		if !boolV {
			AppendFile(types.WafRuleLogPath, "备份文件失败："+sourceFile+"\n", true)
			AppendFile(types.WafRuleLogPath, "error:"+err.Error(), true)
		} else {
			AppendFile(types.WafRuleLogPath, "备份文件成功："+sourceFile+"\n", true)
		}
	}
	AppendFile(types.WafRuleLogPath, "已执行waf rule规则备份任务---------------------\n\n", true)

}

func WafRuleRestore() {
	ruleFiles := []string{"args", "cc", "city", "cookie", "customize", "customize_count", "ip_black", "ip_group", "ip_white", "malicious_ip", "malicious_ip_total", "province", "replacement", "rule_hit_list", "scan", "speed", "speed_show", "ua_black", "ua_white", "url", "url_black", "url_white", "user_agent", "white"}
	jsonFiles := map[string]string{"customize": "1", "customize_count": "1", "ip_group": "1", "malicious_ip": "1", "replacement": "1", "rule_hit_list": "1", "scan": "1", "speed": "1"}
	IntFiles := map[string]string{"malicious_ip_total": "1"}
	AppendFile(types.WafRuleRestoreLogPath, "开始执行waf rule规则文件检测恢复任务---------------------", true)
	isReloadNginx := false
	for _, v := range ruleFiles {
		vBackupPath := types.WafRuleHistoryPath + v + "/"
		sourceFile := types.RulePath + v + ".json"
		if FileExists(sourceFile) {
			isRestore := false
			sourceString, err := ReadFile(sourceFile)
			if err != nil {
				isRestore = true
			}
			var sourceJson interface{}
			err = json.Unmarshal([]byte(sourceString), &sourceJson)
			if err != nil {
				isRestore = true
			}
			backupString := "[]"
			if _, ok := jsonFiles[v]; ok {
				backupString = "{}"
			}
			if _, ok := IntFiles[v]; ok {
				backupString = "0"
			}
			if isRestore {
				backupFiles, err := GetFiles(vBackupPath)
				if err == nil && len(backupFiles) > 0 {
					for _, file := range backupFiles {
						backupFile := vBackupPath + file + ".json"
						tmpBackupString, err := ReadFile(backupFile)
						if err == nil && backupString != "" {
							var backupJson interface{}
							err = json.Unmarshal([]byte(backupString), &backupJson)
							if err == nil {
								backupString = tmpBackupString
								break
							}
						}
					}
				}
				boolV, err := WriteFile(sourceFile, backupString)
				if boolV {
					isReloadNginx = true
				}
			}
		}
	}
	if isReloadNginx {
		AppendFile(types.WafRuleRestoreLogPath, "检测到配置文件损坏，已修复，正在重载nginx......", true)
		OnlyReloadNginx()
		AppendFile(types.WafRuleRestoreLogPath, "已执行重载nginx", true)
	}
	AppendFile(types.WafRuleRestoreLogPath, "已执行waf rule规则文件检测恢复任务---------------------\n\n", true)

}

func GetFiles(dirPath string) ([]string, error) {
	fileSlice := make([]string, 0)
	fileList, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return fileSlice, err
	}
	for _, file := range fileList {
		if file.IsDir() {
			continue
		}

		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		splitSlice := strings.Split(file.Name(), ".")
		if len(splitSlice) < 5 {
			_, err := strconv.ParseInt(splitSlice[0], 10, 64)
			if err != nil {
				continue
			}
			fileSlice = append(fileSlice, splitSlice[0])
		}
	}
	sort.Slice(fileSlice, func(i, j int) bool {
		return fileSlice[i] > fileSlice[j]
	})
	return fileSlice, err
}

func GetConfigRouteToken() (string, error) {
	routeToken := ""
	jsonData, err := ReadInterfaceFileBytes(GlobalConfig)
	if err != nil {
		return routeToken, err
	}
	if _, ok := jsonData.(map[string]interface{})["route_token"]; ok {
		if jsonData.(map[string]interface{})["route_token"].(string) != "" {
			routeToken = jsonData.(map[string]interface{})["route_token"].(string)
			return routeToken, nil
		}

	}
	return routeToken, err
}
