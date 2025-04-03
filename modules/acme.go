package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/compress"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Acmesh struct{}

var (
	AcmeshRoot = "/www/cloud_waf/console/acme_sh/acme.sh"
	SslEmail   = ""
	TestCert   = ""
	KeyLength  = " -k 2048"
)

func init() {
	core.RegisterModule(&Acmesh{})
	MkdirPaths := []string{types.GlobalVhostPath, types.SslPath, types.SiteJsonPath, types.CertPath, types.BackupPath, types.ZipPath, types.HistoryBackupPath, types.HistoryBackupConfig, types.SliceSiteLogJson, types.NginxJsonPath, types.NginxStreamPath}
	for _, v := range MkdirPaths {
		if !public.FileExists(v) {
			os.MkdirAll(v, 0600)
		}
	}

}

func (as *Acmesh) ApplyCert(request *http.Request) core.Response {
	params := types.AcmeInfo{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	err := InstallAcme(GetSslEmail(), "letsencrypt")
	if err != nil {
		return core.Fail("安装acme失败:" + err.Error())
	}
	result, err := ApplyCert(params.Domain, params.Types, GetSslEmail(), params.SiteId)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(result)
}

func GetSiteSslInfos(SiteId string) ([]types.SiteJson, int, error) {
	siteList := make([]types.SiteJson, 0)
	tatal := 0
	query := public.M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time"}).
		Order("create_time", "desc")
	if SiteId != "" {
		query.Where("site_id = ?", []any{SiteId})
	}
	count, err := query.Count()
	if err != nil {
		return siteList, tatal, fmt.Errorf("获取列表失败：%w", err)
	}
	tatal = int(count)
	params := types.SiteListParams{}
	params.SiteId = SiteId
	params.P = 1
	params.PSize = 10
	params.SiteName = ""
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

func (as *Acmesh) RenewalCert(request *http.Request) core.Response {
	params := types.AcmeIn{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	err := InstallAcme(GetSslEmail(), "letsencrypt")
	if err != nil {
		return core.Fail("续签失败:" + err.Error())
	}
	result, err := RenewalCert(params.SiteId)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(result)
}

func RenewalCert(siteId string) (string, error) {
	SslInfo, totla, err := GetSiteSslInfos(siteId)
	if err != nil {
		return "", errors.New("没有找到网站信息")
	}
	if totla == 0 {
		return "没有找到网站信息", errors.New("没有找到网站信息")
	}
	if len(SslInfo) == 0 {
		return "没有找到网站信息", errors.New("没有找到网站信息")
	}
	var SiteJson types.SiteJson
	for _, v := range SslInfo {
		SiteJson = v
		break
	}
	if SiteJson.Server.Ssl == nil || SiteJson.Server.Ssl.IsSsl == 0 {
		return "", errors.New("该网站未开启SSL 无法续签")
	}
	if SiteJson.Server.Ssl.IsSsl == 1 {
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
				return "", err
			}
			_, err := core.CallModuleActionSimulateAssertJson("Wafmastersite", "ModifySite", params)
			if err != nil {
				return "", errors.New("关闭强制HTTPS失败、无法续签")
			}
		}
		result, err := ApplyCert(SiteJson.Server.Ssl.Domains, SiteJson.Server.Ssl.ApplyType, GetSslEmail(), SiteJson.SiteID)
		if err != nil {
			return "", err
		}
		return result, nil

	}

	return "", nil
}

func (as *Acmesh) RenewCert(request *http.Request) core.Response {
	params := types.AcmeInfo{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	result, err := RenewCert(params.Domain, GetSslEmail(), params.Types, params.SiteId)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(result)
}

func ApplyCert(domain []string, typeString string, email string, siteId string) (string, error) {
	stdOut := ""
	addDomain := ""
	sslName := domain[0]
	for _, v := range domain {
		if !validate.IsHost(v) {
			continue
		}
		addDomain += " -d " + v
	}
	if addDomain == "" {
		return "", errors.New("域名格式不正确，请检查域名格式")
	}
	count, err := public.M("site_info").Where("site_id = ?", []any{siteId}).Count()
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("siteId不存在，请检查siteId是否正确")
	}
	if typeString != "dns" && typeString != "http" {
		return "", errors.New("typeString只能为dns或者http")
	}

	cmd := AcmeshRoot + " --set-default-ca --server letsencrypt"
	stdOut, err = public.ExecCommandCombined("bash", "-c", cmd)
	if err != nil {
		return stdOut, err
	}
	cmd = AcmeshRoot + " --register-account -m " + email
	stdOut, err = public.ExecCommandCombined("bash", "-c", cmd)
	if err != nil {
		return stdOut, err
	}

	siteSslPath := types.SslPath + "/" + domain[0]
	for i := 0; i < 1000; i++ {
		if !public.FileExists(siteSslPath) {
			break
		}
		sslName = domain[0] + "_" + public.InterfaceToString(i)
		siteSslPath = types.SslPath + "/" + sslName
	}

	if public.M("ssl_info").Where("site_id = ? and ssl_type = ? and ssl_path = ?", []any{siteId, "letsencrypt", types.SslPath}).Exists() {
		res, err := public.M("ssl_info").Where("site_id = ? and ssl_type = ? and ssl_path = ?", []any{siteId, "letsencrypt", types.SslPath}).Find()
		if err != nil {
			return stdOut, err
		}
		tmp := types.SslEntryJson{}
		if err := core.MapToStruct(res, &tmp); err != nil {
			return stdOut, err
		}
		var domainMap map[string]string
		if err = json.Unmarshal([]byte(tmp.Domains), &domainMap); err != nil {
			return stdOut, err
		}
		if len(domainMap) == len(domain) {
			isExist := true
			for _, v := range domainMap {
				if _, ok := domainMap[v]; !ok {
					isExist = false
					break
				}
			}
			if isExist {
				return "证书已经申请过", errors.New(`证书已经申请过,请在证书后期前一天续签即可！`)
			}
		}

	}

	recordFile := "/var/www/letsencrypt/dns.txt"
	os.MkdirAll("/var/www/letsencrypt", 0755)
	switch typeString {
	case "dns":
		cmd = "echo \"\">" + recordFile + " && " + AcmeshRoot + " --issue --dns --force " + addDomain + TestCert + KeyLength + " --yes-I-know-dns-manual-mode-enough-go-ahead-please  >>" + recordFile + " 2>&1"
		stdOut, err := public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			if public.FileExists("/var/www/letsencrypt/dns.txt") {
				readString, err := public.ReadFile(recordFile)
				if err != nil {
					return stdOut, err
				}
				checkString := "Add the following TXT record:"
				if strings.Contains(readString, checkString) {
					recordAll := GetTxtRecord(readString)
					return recordAll, nil
				}

				returnError, boolV := ParseErrorInfo(readString)
				if !boolV {
					return "证书申请失败", errors.New(returnError)
				} else {
					return returnError, nil
				}
			}
			return stdOut, err
		}
	case "http":
		public.WriteFile(types.SsLHttpDebug, "1")
		query := public.M("site_info").
			Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
			Where("site_id = ?", []any{siteId})
		result, err := query.Find()
		if err != nil {
			return stdOut, err
		}
		siteJson, err := SiteJsonToBack(result)
		if err != nil {
			return stdOut, err
		}
		err = ParseSiteJson(siteJson)
		if err != nil {
			return stdOut, err
		}
		os.RemoveAll(types.SsLHttpDebug)
		recordFile = "/var/www/letsencrypt/http.txt"
		cmd = "echo \"\">" + recordFile + " && " + AcmeshRoot + " --issue --force " + addDomain + TestCert + KeyLength + " --webroot /www/cloud_waf/wwwroot/" + siteId + "  >>" + recordFile + " 2>&1"
		stdOut, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			readString, err := public.ReadFile(recordFile)
			if err != nil {
				return stdOut, err
			}
			returnError, boolV := ParseErrorInfo(readString)
			if !boolV {
				return "证书申请失败", errors.New(returnError)
			} else {
				return returnError, nil
			}
		}
		if public.FileExists(recordFile) {
			readString, err := public.ReadFile(recordFile)
			if err != nil {
				return stdOut, err
			}
			checkString := "Cert success"
			if strings.Contains(readString, checkString) {
				result, err := RenewCert(domain, email, typeString, siteId)
				if err != nil {
					return result, err
				}
				sslJson := types.SslJson{}
				sslJson.SiteIDs = []string{siteId}
				sslJson.SslName = sslName
				sslJson.SslType = "letsencrypt"
				sslJson.SslPath = types.SslPath
				sslJson.Domains = domain
				sslJson.ApplyType = typeString
				sslJson.PrivateKey, _ = public.ReadFile(siteSslPath + "/privkey.pem")
				sslJson.Fullchain, _ = public.ReadFile(siteSslPath + "/fullchain.pem")
				err = DeploySsl(sslJson, true)
				if err != nil {
					return "证书部署到网站失败", err
				}
				return "证书申请并部署到证书夹成功", nil

			}
		}
		return "证书申请失败：", err

	}

	return stdOut, nil
}

func RenewCert(domain []string, email string, typeString string, siteId string) (string, error) {
	result := ""
	cmd := AcmeshRoot + " --set-default-ca --server letsencrypt"
	stdOut, err := public.ExecCommandCombined("bash", "-c", cmd)
	if err != nil {
		return stdOut, err
	}
	cmd = AcmeshRoot + " --register-account -m " + email

	stdOut, err = public.ExecCommandCombined("bash", "-c", cmd)
	if err != nil {
		return result, err
	}
	addDomain := ""
	sslName := domain[0]
	for _, v := range domain {
		addDomain += " -d " + v
	}
	siteSslPath := types.SslPath + "/" + domain[0]
	for i := 0; i < 1000; i++ {
		if !public.FileExists(siteSslPath) {
			break
		}
		sslName = domain[0] + "_" + public.InterfaceToString(i)
		siteSslPath = types.SslPath + "/" + sslName
	}
	if typeString == "dns" {
		cmd = "echo \"\">/var/www/letsencrypt/dns_renew.txt && " + AcmeshRoot + " --renew --force" + addDomain + TestCert + KeyLength + " --yes-I-know-dns-manual-mode-enough-go-ahead-please  >>/var/www/letsencrypt/dns_renew.txt  2>&1"
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			if public.FileExists("/var/www/letsencrypt/dns_renew.txt") {
				readString, _ := public.ReadFile("/var/www/letsencrypt/dns_renew.txt")
				if !strings.Contains(readString, "Cert success") {
					checkString := "Add the following TXT record:"
					checkError := "429"
					if strings.Contains(readString, checkError) {
						checkError = "Create new order error. Le_OrderFinalize not found."
						if strings.Contains(readString, checkError) {
							checkError = "Error creating new order :: too many certificates"
							if strings.Contains(readString, checkError) {
								return stdOut, errors.New("指定时间内颁发了太多的证书！")
							}
						}
					}
					if strings.Contains(readString, checkString) {
						recordAll := GetTxtRecord(readString)
						return recordAll, nil
					}
					if public.FileExists("/var/www/letsencrypt/dns.txt") {
						readString, err := public.ReadFile("/var/www/letsencrypt/dns.txt")
						if err != nil {
							return stdOut, err
						}
						checkString := "Add the following TXT record:"
						if strings.Contains(readString, checkString) {
							recordAll := GetTxtRecord(readString)
							return recordAll, nil
						}
						returnError, boolV := ParseErrorInfo(readString)
						if !boolV {
							return "证书申请失败", errors.New(returnError)
						} else {
							return returnError, nil
						}
					}
					returnError, boolV := ParseErrorInfo(readString)
					if !boolV {
						return "证书申请失败", errors.New(returnError)
					} else {
						return returnError, nil
					}
				}
			}
			return result, err
		}
	}
	siteSslPath = types.SslPath + "/" + domain[0]
	for i := 0; i < 1000; i++ {
		if !public.FileExists(siteSslPath) {
			break
		}
		siteSslPath = types.SslPath + "/" + domain[0] + "_" + public.InterfaceToString(i)
	}
	SiteSslPrivateKey := siteSslPath + "/privkey.pem"
	SiteSslFullChain := siteSslPath + "/fullchain.pem"
	if !public.FileExists(siteSslPath) {
		err := os.MkdirAll(siteSslPath, 0600)
		if err != nil {
			return result, err
		}
	}

	cmd = AcmeshRoot + " --install-cert " + addDomain + " --key-file " + SiteSslPrivateKey + " --fullchain-file " + SiteSslFullChain
	stdOut, err = public.ExecCommandCombined("bash", "-c", cmd)
	if err != nil {
		return result, err
	}
	WritePrivateKeyFile := []string{SiteSslPrivateKey, SiteSslFullChain}
	for _, v := range WritePrivateKeyFile {
		if !public.FileExists(v) {
			logging.Error(v + "文件不存在")
		} else {
			logging.Error(v + "文件存在")
		}
	}
	if typeString == "dns" {
		sslJson := types.SslJson{}
		sslJson.SiteIDs = []string{siteId}
		sslJson.SslName = sslName
		sslJson.SslType = "letsencrypt"
		sslJson.SslPath = types.SslPath
		sslJson.Domains = domain
		sslJson.PrivateKey, _ = public.ReadFile(siteSslPath + "/privkey.pem")
		sslJson.Fullchain, _ = public.ReadFile(siteSslPath + "/fullchain.pem")
		err = DeploySsl(sslJson, true)
		if err != nil {
			return "证书部署到网站失败", err
		}
		return "证书申请并部署到网站成功", nil
	}
	return "证书申请并部署到证书夹成功", nil
}

func (as *Acmesh) GetBtAccountInfo(request *http.Request) core.Response {
	userinfo, err := GetBtAccountInfo()
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(userinfo)
}

func (as *Acmesh) CheckBtAccountInfo(request *http.Request) core.Response {
	userinfo, err := GetBtAccountInfo()
	if err != nil {
		return core.Fail(err)
	}
	if userinfo.Uid > 0 {
		return core.Success("success")
	}
	return core.Fail("请先登录堡塔账号，再进行操作")
}

func GetBtAccountInfo() (types.BtAccountInfo, error) {
	userinfo := types.BtAccountInfo{}

	if _, err := os.Stat(public.BT_USERINFO_FILE); err == nil {
		bs, err := os.ReadFile(public.BT_USERINFO_FILE)

		if err == nil {
			if err = json.Unmarshal(bs, &userinfo); err == nil {
				return userinfo, nil
			} else {
				return userinfo, err
			}
		} else {
			return userinfo, err
		}
	}
	userinfo.Username = GetSslEmail()
	return userinfo, nil
}

func InstallAcme(email string, server string) error {
	CreateSslEmail()
	stdOut, _, err := ExecNginxCommand("which", "socat")
	if err != nil || stdOut == "" {
		if public.FileExists("/usr/bin/apt") || public.FileExists("/usr/Sbin/apt") {
			_, _, err := ExecNginxCommand("apt", "install", "-y", "socat")
			if err != nil {
				return err
			}
		} else {
			_, _, err := ExecNginxCommand("yum", "install", "-y", "socat")
			if err != nil {
				return err
			}
		}
		stdOut, _, err := ExecNginxCommand("which", "socat")
		if err != nil || stdOut == "" {
			return err
		}
	}
	acmeshZip := "/www/cloud_waf/waf-acme_sh.zip"
	if !public.FileExists(AcmeshRoot) || !public.FileExists("/root/.acme.sh/acme.sh") {
		os.RemoveAll("/root/.acme.sh")
		os.RemoveAll("/www/cloud_waf/console/.acme.sh/")
		os.MkdirAll("/www/cloud_waf/console/.acme.sh/", 0755)
		os.MkdirAll("/root/.acme.sh/", 0755)
		if !public.FileExists(acmeshZip) {
			return errors.New("acme.sh压缩包不存在")
		}
		err := compress.Unzip(acmeshZip, "./acme_sh")
		if err != nil {
			return err
		}
		cmd := "chmod -R +x /www/cloud_waf/console/acme_sh && cp -r " + AcmeshRoot + " /root/.acme.sh"
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}
		cmd = "source /root/.bashrc"
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}
		cmd = AcmeshRoot + " --install -m " + email
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}

		cmd = AcmeshRoot + " --set-default-ca --server " + server
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}
		cmd = AcmeshRoot + " --register-account -m " + email
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}
		cmd = AcmeshRoot + " --upgrade --auto-upgrade"
		_, err = public.ExecCommandCombined("bash", "-c", cmd)
		if err != nil {
			return err
		}
		if !public.FileExists("/var/www/letsencrypt") {
			os.MkdirAll("/var/www/letsencrypt", 0755)
		}

	}
	return nil
}

func CreateSslEmail() {
	emailStruct := struct {
		SslEmail   string `json:"ssl_email"`
		CreateTime int64  `json:"create_time"`
	}{}
	emailStruct.SslEmail = public.RandomStr(32) + "@bt.cn"
	emailStruct.CreateTime = time.Now().Unix()
	if !public.M("ssl_email").Where("id = ?", []any{1}).Exists() {
		public.M("ssl_email").Insert(emailStruct)
		public.M("ssl_email").Where("ssl_email = ?", []any{emailStruct.SslEmail}).Update(map[string]interface{}{"id": 1})
	}
}

func GetSslEmail() string {
	sslEmail := public.RandomStr(32) + "@bt.cn"
	emailStruct := struct {
		SslEmail string `json:"ssl_email"`
	}{}
	res, err := public.M("ssl_email").Where("id = ?", []any{1}).Find()
	if err != nil {
		return sslEmail
	}
	if err := core.MapToStruct(res, &emailStruct); err != nil {
		return sslEmail
	}
	return emailStruct.SslEmail
}

func ParseErrorInfo(readString string) (string, bool) {
	returnError := "证书申请失败，错误信息如下：<br/>" + readString
	if strings.Contains(readString, "Invalid status") && strings.Contains(readString, "429") {
		if strings.Contains(readString, "Create new order error. Le_OrderFinalize not found.") {
			if strings.Contains(readString, "Error creating new order :: too many certificates") {
				returnError = "证书申请失败，指定时间内颁发了太多的证书！错误信息如下：<br/>" + readString
				return returnError, false
			}
		}
		returnError = "证书申请失败，429错误<br/>" + readString
		return returnError, false
	}
	if strings.Contains(readString, "Invalid status") && strings.Contains(readString, "403") {
		returnError = "证书申请失败，403错误<br/>" + readString
		return returnError, false
	}
	if strings.Contains(readString, "Invalid status") && strings.Contains(readString, "Verify error detail:DNS problem:") {
		returnError = "证书申请失败，DNS错误<br/>" + readString
		return returnError, false

	}
	if strings.Contains(readString, "Error creating new order :: too many certificates") {
		returnError = "证书申请失败，指定时间内颁发了太多的证书！报错如下：<br/>" + readString
		return returnError, false
	}
	if strings.Contains(readString, "Create new order error") {
		returnError = "证书申请失败，生成新订单出错：<br/>" + readString
		return returnError, false
	}
	if strings.Contains(readString, "Cert success") {
		return "证书申请成功", true
	}
	return returnError, false
}

func GetTxtRecord(readString string) string {
	recordAll := ""
	readStringArr := strings.Split(readString, "\n")
	for _, v := range readStringArr {
		recordBefore := ""
		recordValue := ""
		if strings.Contains(v, "Domain: ") {
			tmpValue := strings.Split(v, "Domain: '")
			recordBefore = tmpValue[1]
			if recordAll != "" {
				recordAll = recordAll + "\n"
			}
			recordAll = recordAll + recordBefore[:len(recordBefore)-1]
		}
		if strings.Contains(v, "TXT value: ") {
			tmpValue := strings.Split(v, "TXT value: '")
			recordValue = tmpValue[1]
			recordAll = recordAll + "       " + recordValue[:len(recordValue)-1]
		}
	}
	return recordAll
}
