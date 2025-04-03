package providers

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"os"
	"strings"
)

func init() {
	cp := &configProvider{
		mysqlConfFile:    core.AbsPath("./config/mysql.json"),
		mysqlPwdFile:     core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/mysql_default.pl"),
		manm_path:        "/www/cloud_waf/nginx/conf.d/waf/rule/cc.json",
		manm_path_backup: "/www/cloud_waf/nginx/conf.d/waf/rule/cc_backup.json",
		ipWhite:          "/www/cloud_waf/nginx/conf.d/waf/rule/ip_white.json",
		ipBlack:          "/www/cloud_waf/nginx/conf.d/waf/rule/ip_black.json",
		uaWhite:          "/www/cloud_waf/nginx/conf.d/waf/rule/ua_white.json",
		uaBlack:          "/www/cloud_waf/nginx/conf.d/waf/rule/ua_black.json",
		urlWhite:         "/www/cloud_waf/nginx/conf.d/waf/rule/url_white.json",
		urlBlack:         "/www/cloud_waf/nginx/conf.d/waf/rule/url_black.json",
	}

	cp.InitMysqlConf()
	cp.InitSiteIdConf()
	cp.InitBlackWhiteConf()
	cp.InitManConf()
	cp.InitIdcConf()
	core.GetServerVersion()
}

type configProvider struct {
	mysqlConfFile    string
	mysqlPwdFile     string
	ipWhite          string
	ipBlack          string
	uaWhite          string
	uaBlack          string
	urlWhite         string
	urlBlack         string
	manm_path        string
	manm_path_backup string
}

func (c *configProvider) InitSiteIdConf() {
	if !public.FileExists(public.SiteIdPath) {
		public.WriteFile(public.SiteIdPath, "{}")
		return
	}
}

func (c *configProvider) InitMysqlConf() {

	m := make(map[string]db.MySqlConfig)

	config := db.MySqlConfig{
		Host:     "127.0.0.1",
		Port:     33060,
		UserName: "root",
		DbName:   "btwaf",
		PreFix:   "",
	}
	if _, err := os.Stat(c.mysqlConfFile); err == nil {
		if bs, err := os.ReadFile(c.mysqlConfFile); err == nil {
			if err = json.Unmarshal(bs, &m); err != nil {
				json.Unmarshal(bs, &config)
			}

			if v, ok := m["default"]; ok {
				config = v
			}
		}
	}
	if _, err := os.Stat(c.mysqlPwdFile); err != nil {
		return
	}

	bs, err := os.ReadFile(c.mysqlPwdFile)

	if err != nil {
		return
	}

	config.Password = strings.TrimSpace(string(bs))

	m["default"] = config

	bs, err = json.Marshal(m)

	if err != nil {
		return
	}

	if err = os.WriteFile(c.mysqlConfFile, bs, 0644); err != nil {
		return
	}
}

func (c *configProvider) InitIpBlackWriteConf() {
	ipConfig := make([]string, 0)
	ipConfig = append(ipConfig, c.ipWhite, c.ipBlack)

	for _, filePath := range ipConfig {
		fileData, err := public.ReadFile(filePath)
		if err != nil {
			fileData = string([]byte("[]"))
		}
		ipData := make([][]interface{}, 0, 256)
		err = json.Unmarshal([]byte(fileData), &ipData)
		if err != nil {
			return
		}
		if ipData == nil {
			return
		}
		flag := false
		for i, values := range ipData {
			if len(values) == 7 {
				ipIndex := public.RandomStr(20)
				values = append(values, ipIndex)
				ipData[i] = values

				flag = true
			}
		}
		if !flag {
			return
		}
		text, status := json.Marshal(ipData)
		if status != nil {
			public.WriteFile(filePath, "[]")
			return
		}

		_, err = public.WriteFile(filePath, string(text))
		if err != nil {
			return
		}
	}
}

func (c *configProvider) InitUaBlackWriteConf() {
	uaConfig := make([]string, 0)
	uaConfig = append(uaConfig, c.uaWhite, c.uaBlack)

	for _, filePath := range uaConfig {
		fileData, err := public.ReadFile(filePath)
		if err != nil {
			fileData = string([]byte("[]"))
		}
		uaData := make([]types.UARule, 0)
		err = json.Unmarshal([]byte(fileData), &uaData)
		if err != nil {
			return
		}
		if uaData == nil {
			return
		}
		flag := false

		for i, values := range uaData {
			if values.Index == "" {
				urlIndex := public.RandomStr(20)
				values.Index = urlIndex
				uaData[i] = values

				flag = true
			}
		}
		if !flag {
			return
		}
		text, status := json.Marshal(uaData)
		if status != nil {
			public.WriteFile(filePath, "[]")
			return
		}

		_, err = public.WriteFile(filePath, string(text))
		if err != nil {
			return
		}

	}
}

func (c *configProvider) InitUrlBlackWriteConf() {
	urlConfig := make([]string, 0)
	urlConfig = append(urlConfig, c.urlWhite, c.urlBlack)

	for _, filePath := range urlConfig {
		fileData, err := public.ReadFile(filePath)
		if err != nil {
			fileData = string([]byte("[]"))
		}
		urlData := make([]types.URLRule, 0)
		err = json.Unmarshal([]byte(fileData), &urlData)
		if err != nil {
			return
		}
		if urlData == nil {
			return
		}
		flag := false
		for i, values := range urlData {
			if values.Index == "" {

				urlIndex := public.RandomStr(20)
				values.Index = urlIndex
				urlData[i] = values

				flag = true
			}
		}

		if !flag {
			return
		}
		text, status := json.Marshal(urlData)
		if status != nil {
			public.WriteFile(filePath, "[]")
			return
		}
		_, err = public.WriteFile(filePath, string(text))
		if err != nil {
			return
		}

	}
}

func (c *configProvider) InitBlackWhiteConf() {
	c.InitIpBlackWriteConf()
	c.InitUaBlackWriteConf()
	c.InitUrlBlackWriteConf()
}

func (c *configProvider) InitManConf() {
	json_data, err := public.ReadFile(c.manm_path)
	if err != nil {
		return
	}

	var num int
	file_data := make([]types.ManData, 0)
	err = json.Unmarshal([]byte(json_data), &file_data)
	if err != nil {
		return
	}
	for i := range file_data {
		if file_data[i].Key == "" {
			num++
			file_data[i].Key = public.RandomStr(20)
		}
	}
	if num == 0 {
		return
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	public.WriteFile(c.manm_path, string(rules_js))
	public.WriteFile(c.manm_path_backup, string(rules_js))
}

func (c *configProvider) InitIdcConf() {
	jsonData, err := public.Rconfigfile("/www/cloud_waf/nginx/conf.d/waf/config/config.json")
	if err != nil {
		return
	}
	if jsonData["idc"] == nil {
		jsonData["idc"] = map[string]any{
			"mode": 0,
			"ps":   "IDC限制",
		}
		public.Wconfigfile(core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/config/config.json"), jsonData)
	}
	if jsonData["malicious_ip"] == nil || public.InterfaceToInt(jsonData["malicious_ip"].(map[string]any)["mode"]) == 0 {
		jsonData["malicious_ip"] = map[string]any{
			"mode": 1,
			"ps":   "云端恶意IP库",
		}
		public.Wconfigfile(core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/config/config.json"), jsonData)
	}
	if _, err := os.Stat(public.MALICIOUS_IP_FILE); err != nil {
		os.WriteFile(public.MALICIOUS_IP_FILE, []byte("{}"), 0644)
	}
	if _, err := os.Stat(public.IP_GROUP_FILE); err != nil {
		os.WriteFile(public.IP_GROUP_FILE, []byte("{}"), 0644)
	}

	if _, err := os.Stat(public.MALICIOUS_IP_SHARE_PLAIN_STATUS); err != nil {
		if _, err := os.Stat(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE); err != nil {
			os.WriteFile(public.MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE, []byte(""), 0644)
		}
		os.WriteFile(public.MALICIOUS_IP_SHARE_PLAIN_STATUS, []byte(""), 0644)
	}
}

func (c *configProvider) InitCustomizeConf() {
	if _, err := os.Stat(public.CUSTOMIZE_RULE_FILE); err != nil {
		os.WriteFile(public.CUSTOMIZE_RULE_FILE, []byte(`{"rules": {},"allsite":[]}`), 0644)
	}
	if _, err := os.Stat(public.CUSTOMIZE_RULE_HIT_FILE); err != nil {
		os.WriteFile(public.CUSTOMIZE_RULE_HIT_FILE, []byte(`{}`), 0644)
	}
}

func (c *configProvider) InitWafConf() {
	c.InitBlackWhiteConf()
	c.InitManConf()
	c.InitIdcConf()
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=config", 2)
}
