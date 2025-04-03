package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/jwt"
	"CloudWaf/core/language"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/public/validate"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func init() {

	core.RegisterModule(&Config{
		cert_path:   core.AbsPath("./ssl/certificate.pem"),
		key_path:    core.AbsPath("./ssl/privateKey.pem"),
		config_path: core.AbsPath("./config/sysconfig.json"),
		two_auth:    core.AbsPath("./config/two_auth.json"),
		basic_auth:  "./config/basic_auth.json",
		port:        core.AbsPath("./data/.server-port"),
		logoPath:    core.AbsPath("./config/logo.txt"),
		blockPage:   "/www/cloud_waf/nginx/conf.d/waf/html/black.html",
	})
}

type Config struct {
	cert_path   string
	key_path    string
	config_path string
	two_auth    string
	basic_auth  string
	port        string
	logoPath    string
	blockPage   string
}

func (config *Config) GetConfig(request *http.Request) core.Response {
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	times := time.Now().Unix()
	data["cur_time"] = times
	if data["worker"] == nil {
		data["worker"] = true
	}
	if data["warning_open"] == nil {
		data["warning_open"] = true
	}
	if data["interceptPage"] == nil {
		data["interceptPage"] = "抱歉您的请求似乎存在威胁或带有不合法参数，<br />已被管理员设置的拦截规则所阻断，请检查提交内容或联系网站管理员处理"
	}

	data["interceptPage"] = html.UnescapeString(data["interceptPage"].(string))
	response, _ := public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", []interface{}{uid}).
			Field([]string{"pwd_update_time"}).
			Find()

		if err != nil {
			logging.Info("获取用户信息失败：", err)
		}
		data["password_expire_time"] = public.InterfaceToInt(userInfo["pwd_update_time"]) + public.InterfaceToInt(data["password_expire"])*86400
		return userInfo, nil
	})

	if response == nil {
		return core.Fail("获取密码更新时间失败，未知错误")
	}
	twoAuth, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}

	status := public.InterfaceToBool(twoAuth["open"])
	basicAuth, err := public.Rconfigfile(config.basic_auth)
	if err != nil {
		return core.Fail(err)
	}
	s := time.Now().String()
	systemTime := s[:19] + " " + s[30:39]
	return core.Success(map[string]interface{}{
		"config":        data,
		"port":          core.GetServerPort(),
		"two_step_auth": status,
		"basic_auth":    basicAuth,
		"systemdate":    systemTime,
	})
}

func (config *Config) SetCert(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if _, ok := params["certContent"]; !ok {
		return core.Fail("请输入证书内容")
	}
	if _, ok := params["keyContent"]; !ok {
		return core.Fail("请输入证书私钥")
	}
	public.WriteFile(config.cert_path, params["certContent"].(string))
	public.WriteFile(config.key_path, params["keyContent"].(string))
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()
	public.WriteOptLog(fmt.Sprintf("证书设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("证书设置成功")
}

func (config *Config) GetCert(request *http.Request) core.Response {
	cert_pem, err := public.ReadFile(config.cert_path)
	if err != nil {
		return core.Fail(err)
	}
	key_pem, err := public.ReadFile(config.key_path)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(map[string]interface{}{
		"cert_pem": cert_pem,
		"key_pem":  key_pem,
	})
}

func (config *Config) SetPort(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["port"]; !ok {
		return core.Fail("请输入端口")
	}
	number := public.InterfaceToInt(params["port"])
	if number < 1 || number > 65535 {
		return core.Fail("端口范围为1-65535")
	}
	if err != nil {
		return core.Fail(err)
	}
	if public.CheckPort(number) {
		err := public.AllowPort(strconv.Itoa(number))
		if err != nil {
			return nil
		}
		oldPort, err := public.ReadFile(config.port)
		if err != nil {
			return core.Fail(err)
		}
		if oldPort != strconv.Itoa(number) {
			err := public.DeletePort(strings.Trim(oldPort, "\n"))
			if err != nil {
				return nil
			}
		}
	} else {
		return core.Success("端口已被占用,请重新设置")
	}
	_, err = public.WriteFile(config.port, strconv.Itoa(number))
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("端口设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()

	return core.Success("端口设置成功")
}

func (config *Config) SetIp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	acceptIp := []string{}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	accept_ip := params["accept_ip"].(string)
	if _, err := params["accept_ip"]; err {
		if accept_ip != "" {
			for _, ip := range strings.Split(accept_ip, ",") {
				ip = strings.TrimSpace(ip)
				if !public.IsIpAddr(ip) {
					return core.Fail("IP格式不合法")
				}
				if !config.stringInSlice(ip, acceptIp) {
					acceptIp = append(acceptIp, ip)
				}
			}
			data["accept_ip"] = acceptIp
		} else {
			data["accept_ip"] = make([]string, 0)
		}

	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("授权IP设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("授权IP设置成功")
}

func (config *Config) stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if strings.HasPrefix(s, str) {
			return true
		}
	}
	return false
}

func (config *Config) SetDomain(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}

	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["accept_domain"]; ok {
		domain := params["accept_domain"].(string)
		if domain != "" {
			if !validate.IsHost(params["accept_domain"].(string)) {
				return core.Fail("域名格式不合法")
			} else {
				data["accept_domain"] = params["accept_domain"]
			}
		} else {
			data["accept_domain"] = ""
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("域名设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("绑定域名设置成功")
}

func (config *Config) Setntp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	status := false
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["open"]; ok {
		switch public.InterfaceToInt(params["open"]) {
		case 1:
			data["ntptime"] = true
			status = true
		case 0:
			data["ntptime"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := "关闭"
	if status {
		status_msg = "开启"
	}
	public.WriteOptLog(fmt.Sprintf("%s时间同步设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("时间同步设置成功")
}

func (config *Config) SetTimeout(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()

	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["session_timeout"]; !ok {
		return core.Fail("会话超时时间不能为空")
	}
	timeout := params["session_timeout"]
	if public.InterfaceToInt(timeout) < 0 {
		return core.Fail("会话超时时间不合法!")
	}
	if timeout == nil || public.InterfaceToInt(timeout) == 0 {
		data["session_timeout"] = 120
	} else {
		data["session_timeout"] = public.InterfaceToInt(timeout)
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("会话超时时间设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("会话超时时间设置成功")
}

func (config *Config) SetBasicAuth(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.basic_auth)
	if err != nil {
		return core.Fail(err)
	}
	isopen := false
	if _, ok := params["open"]; ok {
		switch public.InterfaceToInt(params["open"]) {
		case 1:
			data["open"] = true
			isopen = true
			basicUser := strings.TrimSpace(params["basic_user"].(string))
			if basicUser == "" {
				return core.Fail("用户名不能为空")
			}
			basicPwd := strings.TrimSpace(params["basic_pwd"].(string))
			if basicPwd == "" {
				return core.Fail("密码不能为空")
			}

			data["basic_user"], err = public.StringMd5(basicUser)
			if err != nil {
				return core.Fail("用户名加密失败")
			}
			data["basic_pwd"], err = public.StringMd5(basicPwd)
			if err != nil {
				return core.Fail("密码加密失败")
			}
		case 0:
			data["open"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}
	err = public.Wconfigfile(config.basic_auth, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := "关闭"
	if isopen {
		status_msg = "开启"
	}

	public.WriteOptLog(fmt.Sprintf("%sBasicAuth设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("BasicAuth设置成功")
}

func (config *Config) SetTwoAuth(request *http.Request) core.Response {
	params := struct {
		Open   int    `json:"open"`
		Secret string `json:"secret_key"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()

	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	isopen := false
	if params.Open != 0 {
		switch public.InterfaceToInt(params.Open) {
		case 1:
			data["open"] = true
			isopen = true
			username := public.RandomStr(8)
			data["username"] = username
			serverIp, localIp := core.GetServerIp()

			if serverIp == "127.0.0.1" {
				serverIp = localIp
			}

			if len(params.Secret) < 16 {
				potp, err := totp.Generate(totp.GenerateOpts{
					Issuer:      "BTWAF--" + serverIp,
					AccountName: username,
				})
				if err != nil {
					return core.Fail(err)
				}
				data["secret_key"] = potp.Secret()
				data["qrcode_url"] = potp.URL()

			} else {
				potp, err := totp.Generate(totp.GenerateOpts{
					Issuer:      "BTWAF--" + serverIp,
					AccountName: username,
					Secret:      []byte(params.Secret),
				})
				if err != nil {
					return core.Fail(err)
				}
				data["secret_key"] = potp.Secret()
				data["qrcode_url"] = potp.URL()
			}
		case 0:
			data["open"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}

	if params.Open == 0 {
		data["open"] = false
	} else if params.Open == 1 {

		data["open"] = true
		isopen = true
		username := public.RandomStr(8)
		data["username"] = username
		serverIp, localIp := core.GetServerIp()

		if serverIp == "127.0.0.1" {
			serverIp = localIp
		}
		if len(params.Secret) < 16 {
			potp, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "BTWAF--" + serverIp,
				AccountName: username,
			})
			if err != nil {
				return core.Fail(err)
			}
			data["secret_key"] = potp.Secret()
			data["qrcode_url"] = potp.URL()

		} else {
			potp, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "BTWAF--" + serverIp,
				AccountName: username,
				Secret:      []byte(params.Secret),
			})

			if err != nil {
				return core.Fail(err)
			}
			data["qrcode_url"] = potp.URL()
		}
	} else {
		return core.Fail("参数不合法!")
	}
	err = public.Wconfigfile(config.two_auth, data)
	if err != nil {
		return core.Fail(err)
	}
	status_msg := "关闭"
	if isopen {
		status_msg = "开启"
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, err = public.ExecCommandCombined("bash", "-c", "cat /www/cloud_waf/console/data/.pid |xargs kill -9;nohup /www/cloud_waf/console/CloudWaf >> /www/cloud_waf/console/logs/error.log 2>&1 &")
	}()

	public.WriteOptLog(fmt.Sprintf("%s动态口令认证设置", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("动态口令认证设置成功")
}

func (config *Config) CheckTwoAuth(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	secret := public.InterfaceToString(data["secret_key"])
	passcode := public.InterfaceToString(params["passcode"])
	if data["open"] == true {
		check, err := totp.ValidateCustom(
			passcode,
			secret,
			time.Now().UTC(),
			totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			},
		)

		if err != nil {
			return core.Fail(err)
		}
		if check == true {
			return core.Success("认证成功")
		} else {
			return core.Fail("认证失败")
		}
	}
	return core.Fail("动态口令认证未开启")
}

func (config *Config) GetTwoAuth(request *http.Request) core.Response {
	data, err := public.Rconfigfile(config.two_auth)
	if err != nil {
		return core.Fail(err)
	}
	return core.Success(data)
}

func (config *Config) SetPwd(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	pwd_complexity := false
	if val, ok := params["password_complexity"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			pwd_complexity = true
			data["password_complexity"] = true
		case 0:
			data["password_complexity"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	status_msg := "关闭"
	if pwd_complexity {
		status_msg = "开启"
	}

	public.WriteOptLog(fmt.Sprintf("%s密码复杂度验证", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("密码复杂度验证设置成功")
}

func (config *Config) SetPwdExpire(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["password_expire"]; !ok {
		return core.Fail("缺少参数password_expire!")
	}
	if public.InterfaceToInt(params["password_expire"]) < 0 {
		return core.Fail("密码过期时间不合法!")
	}

	data["password_expire"] = public.InterfaceToInt(params["password_expire"])
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("密码过期时间设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("密码过期时间设置成功")
}

func (config *Config) SetAdminPath(request *http.Request) core.Response {

	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["admin_path"]; ok {
		adminPath := params["admin_path"].(string)
		if len(adminPath) < 8 {
			return core.Fail("安全入口最小八位")
		}
		if !validate.IsAdminPath(adminPath) {
			return core.Fail("安全入口格式不正确!")
		}
		data["admin_path"] = "/" + adminPath
	} else {
		data["admin_path"] = ""
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("安全入口设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("安全入口设置成功")
}

func (config *Config) SyncDate(request *http.Request) core.Response {
	uid := public.GetUid(request)
	resp, err := public.HttpGet("https://www.bt.cn/api/index/get_time", 6)
	if err != nil {
		return core.Fail("连接时间服务器失败!")
	}
	body, err := strconv.Atoi(resp)
	if err != nil {
		return core.Fail("连接时间服务器失败!")
	}
	timeStr := strings.TrimSpace(strconv.Itoa(body))
	newTime, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return core.Fail("连接时间服务器失败!")
	}

	newTime -= 28800
	addTime, err := exec.Command("date", `+%z`).Output()
	if err != nil {
		return core.Fail("获取当前时区失败!!")
	}
	addTimeStr := strings.TrimSpace(string(addTime))
	add1 := false
	if addTimeStr[0] == '+' {
		add1 = true
	}
	addV, err := strconv.Atoi(addTimeStr[1 : len(addTimeStr)-2])
	if err != nil {
		return core.Fail("解析时区偏差失败!")
	}
	num, _ := strconv.Atoi(addTimeStr[len(addTimeStr)-2:])

	addV = addV*3600 + num*60

	if add1 {
		newTime += int64(addV)
	} else {
		newTime -= int64(addV)
	}
	dateStr := time.Unix(newTime, 0).Format("2006-01-02 15:04:05")
	cmd := exec.Command("date", "-s", dateStr)
	err = cmd.Run()
	if err != nil {
		return core.Fail("设置服务器时间失败!")
	}
	public.WriteOptLog(fmt.Sprintf("同步服务器时间成功!"), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("同步服务器时间成功!")
}

func (config *Config) SetHelp(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	status := false
	if val, ok := params["open"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			status = true
			data["worker"] = true
		case 0:
			data["worker"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	status_msg := "关闭"
	if status {
		status_msg = "开启"
	}

	public.WriteOptLog(fmt.Sprintf("%s在线客服设置成功", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("在线客服设置成功")
}

func (config *Config) SetTitle(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	if _, ok := params["title"]; !ok {
		return core.Fail("缺少参数title!")
	}

	if _, ok := params["logo"]; !ok {
		return core.Fail("缺少参数logo!")
	}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["title"]; ok {
		data["title"] = params["title"].(string)
	} else {
		data["title"] = ""
	}

	_, err = os.Stat(config.logoPath)
	if err != nil {
		file, err := os.Create(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		defer file.Close()
	}

	logoData := []byte(public.InterfaceToString(params["logo"]))
	if float64(len(logoData))*0.7 > 100*1024 {
		return core.Success("logo文件大小不能超过100KB")
	}
	_, err = public.WriteFile(config.logoPath, params["logo"].(string))
	if nil != err {
		return core.Fail(err)
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}

	public.WriteOptLog(fmt.Sprintf("企业名【%s】设置成功", params["title"].(string)), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success("设置成功")
}

func (config *Config) Title(request *http.Request) core.Response {
	data, err := public.Rconfigfile(core.AbsPath("./config/sysconfig.json"))
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := data["title"]; !ok {
		data["title"] = "堡塔云WAF"
	}
	_, err = os.Stat(config.logoPath)
	if err != nil {
		file, err := os.Create(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		defer file.Close()
	}

	logoData, err := public.ReadFile(config.logoPath)
	if err != nil {
		return core.Fail(err)
	}
	au, _ := core.Auth()

	status := true
	if au.Auth.Extra.Type == 0 {
		status = false
	}

	return core.Success(map[string]interface{}{
		"title":  data["title"],
		"logo":   logoData,
		"status": status,
	})
}

func (config *Config) SetWarningOpen(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	if _, ok := params["warning_open"]; !ok {
		return core.Fail("缺少参数warning_open!")
	}

	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	warning_open := false
	if val, ok := params["warning_open"]; ok {
		switch public.InterfaceToInt(val) {
		case 1:
			warning_open = true
			data["warning_open"] = true
		case 0:
			data["warning_open"] = false
		default:
			return core.Fail("参数不合法!")
		}
	}
	status_msg := "关闭"
	if warning_open {
		status_msg = "开启"
	}
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteOptLog(fmt.Sprintf("告警%s成功", status_msg), public.OPT_LOG_TYPE_SYSTEM, uid)
	return core.Success(fmt.Sprintf("全局告警已%s", status_msg))

}

func (config *Config) SetInterceptPage(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}

	if _, ok := params["data"]; !ok {
		return core.Fail("缺少参数data!")
	}
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	uid := token.Uid()
	au, _ := core.Auth()

	if au.Auth.Extra.Type == 0 {
		return core.Success("免费版不支持修改拦截页")
	}
	content, err := public.ReadFile("/www/cloud_waf/nginx/conf.d/waf/html/black.html")

	if _, ok := params["type"]; ok && params["type"] == "logo" {
		logo := regexp.MustCompile(`(<image[^>]+?xlink:href=")[^"]+`)
		logoData, err := public.ReadFile(config.logoPath)
		if err != nil {
			return core.Fail(err)
		}
		content = html.UnescapeString(logo.ReplaceAllString(content, "${1}"+logoData))
	}
	reg := regexp.MustCompile(`(?s)(<div class=\"desc\">).*?(</div>)`)
	content = reg.ReplaceAllString(content, "${1}"+html.UnescapeString(params["data"].(string))+"${2}")
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}

	data["interceptPage"] = params["data"].(string)
	err = public.Wconfigfile(config.config_path, data)
	if err != nil {
		return core.Fail(err)
	}
	public.WriteFile("/www/cloud_waf/nginx/conf.d/waf/html/black.html", content)
	public.WriteOptLog(fmt.Sprintf("拦截页说明设置成功"), public.OPT_LOG_TYPE_SYSTEM, uid)
	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=config", 2)
	return core.Success("设置成功")
}

func (config *Config) SetLanguage(request *http.Request) core.Response {
	params := struct {
		Lan string `json:"lan"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Lan == "" {
		return core.Fail("语言类型不能为空")
	}
	if !public.InArray(params.Lan, language.VALID_LANGUAGE) {
		return core.Fail("无效的语言类型 " + params.Lan)
	}
	data, err := public.Rconfigfile(config.config_path)
	if err != nil {
		return core.Fail(err)
	}
	data["language"] = params.Lan
	if err := public.Wconfigfile(config.config_path, data); err != nil {
		return core.Fail(err)
	}

	return core.Success("操作成功")
}
