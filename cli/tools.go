package cli

import (
	"CloudWaf/public"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/db"
	"CloudWaf/public/validate"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	config_path = "./config/sysconfig.json"
	two_auth    = "./config/two_auth.json"
	ipWhite     = "/www/cloud_waf/nginx/conf.d/waf/rule/ip_white.json"
	ipBlack     = "/www/cloud_waf/nginx/conf.d/waf/rule/ip_black.json"
	uaWhite     = "/www/cloud_waf/nginx/conf.d/waf/rule/ua_white.json"
	uaBlack     = "/www/cloud_waf/nginx/conf.d/waf/rule/ua_black.json"
	urlWhite    = "/www/cloud_waf/nginx/conf.d/waf/rule/url_white.json"
	urlBlack    = "/www/cloud_waf/nginx/conf.d/waf/rule/url_black.json"
)

var (
	fMap = map[string]func(params ...string){
		"create_default_user":   createDefaultUser,
		"reset_password":        resetPassword,
		"reset_username":        resetUsername,
		"get_username":          getUsername,
		"default_user_created":  defaultUserCreated,
		"set_auth_path":         setAuthPath,
		"get_auth_path":         getAuthPath,
		"disable_auth_path":     disableAuthPath,
		"auth_path_status":      authPathStatus,
		"disable_accept_ip":     disableAcceptIp,
		"disable_accept_domain": disableAcceptDomain,
		"disable_two_auth":      disableTwoAuth,
		"add_ip_list":           addIpList,
		"clear_list":            clearList,
		"get_ip":                getIp,
		"delete_ip":             deleteIp,

		"cluster_get_upper_ip": ClusterGetUpperIp,
		"cluster_set_upper_ip": ClusterSetUpperIp,
	}

	log_type = map[string]int{
		"0": public.OPT_LOG_TYPE_IP_WHITE,
		"1": public.OPT_LOG_TYPE_IP_BLACK,
		"2": public.OPT_LOG_TYPE_UA_WHITE,
		"3": public.OPT_LOG_TYPE_UA_BLACK,
		"4": public.OPT_LOG_TYPE_URL_WHITE,
		"5": public.OPT_LOG_TYPE_URL_BLACK,
	}
)

func Exec(params []string) {
	if f, ok := fMap[strings.ToLower(params[0])]; ok {
		if len(params) > 1 {
			f(params[1:]...)
			return
		}
		f()
		return
	}
	printDefault()
}

func printDefault() {
	fmt.Println("Command not supported")
}

func createDefaultUser(params ...string) {
	if len(params) < 2 {
		printDefault()
		return
	}

	public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		salt := public.RandomStr(20)
		username := params[0]
		passwd := params[1]

		md5_passwd, err := public.StringMd5WithSalt(passwd, salt)
		if err != nil {
			fmt.Println("Generate password failed: ", err)
			return nil, nil
		}

		id, err := conn.NewQuery().
			Table("users").
			Insert(map[string]interface{}{
				"id":         1,
				"username":   username,
				"md5_passwd": md5_passwd,
				"salt":       salt,
			}, db.EXTRA_IGNORE)

		if err != nil {
			fmt.Println("Create default account failed: ", err)
			return nil, nil
		}

		if id == 0 {
			fmt.Println("Create default account failed: account exists")
			return nil, nil
		}

		fmt.Println("Create default account success")
		fmt.Println("username: ", username)
		fmt.Println("password: ", passwd)

		return nil, nil
	})
}

func resetPassword(params ...string) {
	public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		passwd := public.RandomStr(10)
		if len(params) > 0 {
			passwd = params[0]
		}
		if len(passwd) < 8 {
			fmt.Println("Password length cannot less than 8")
			return nil, nil
		}
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(1)).
			Field([]string{"salt"}).
			Find()

		if err != nil {
			fmt.Println("Reset password failed: ", err)
			return nil, nil
		}
		saltedPasswd, err := public.StringMd5WithSalt(passwd, userInfo["salt"].(string))

		if err != nil {
			fmt.Println("Reset password failed: ", err)
			return nil, nil
		}
		_, err = conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(1)).
			Update(map[string]interface{}{
				"md5_passwd":      saltedPasswd,
				"pwd_update_time": time.Now().Unix(),
			})

		if err != nil {
			fmt.Println("Reset password failed: ", err)
			return nil, nil
		}

		fmt.Println("Reset password success: ", passwd)
		return nil, nil
	})
}

func resetUsername(params ...string) {
	if len(params) < 1 {
		printDefault()
		return
	}

	public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		_, err := conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(1)).
			Update(map[string]interface{}{
				"username": params[0],
			})

		if err != nil {
			fmt.Println("Reset username failed: ", err)
			return nil, nil
		}

		fmt.Println("Reset username success: ", params[0])
		return nil, nil
	})
}

func getUsername(params ...string) {
	public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(1)).
			Field([]string{"username"}).
			Find()

		if err != nil {
			fmt.Println("Get username failed: ", err)
			return nil, nil
		}

		fmt.Println(userInfo["username"])
		return nil, nil
	})
}

func defaultUserCreated(params ...string) {
	public.SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		userInfo, err := conn.NewQuery().
			Table("users").
			Where("id = ?", public.GetSqlParams(1)).
			Field([]string{"username"}).
			Find()

		if err != nil || userInfo == nil {
			return nil, nil
		}
		return nil, nil
	})
}

func setAuthPath(params ...string) {

	data, err := public.Rconfigfile(config_path)
	if err != nil {
		return
	}
	if len(params) < 1 {
		fmt.Println("安全入口最小八位")
		return
	}
	adminPath := params[0]
	if len(adminPath) < 8 {
		fmt.Println("安全入口最小八位")
		return
	}
	if !validate.IsAdminPath(adminPath) {
		fmt.Println("安全入口格式不正确")
		return
	}
	data["admin_path"] = "/" + adminPath
	err = public.Wconfigfile(config_path, data)
	if err != nil {
		return
	}
	fmt.Println("Reset auth path success: ", params[0])
}

func getAuthPath(params ...string) {
	data, err := public.Rconfigfile(config_path)
	if err != nil {
		return
	}
	adminPath := data["admin_path"]
	fmt.Printf("%s", adminPath)
}

func disableAuthPath(params ...string) {
	fmt.Println("Disable auth path success")
}

func authPathStatus(params ...string) {
	fmt.Println("0")
}

func disableAcceptIp(params ...string) {
	ips, err := public.Rconfigfile(config_path)
	if err != nil {
		return
	}
	ips["accept_ip"] = make([]string, 0)
	err = public.Wconfigfile(config_path, ips)
	if err != nil {
		return
	}
	fmt.Printf("关闭授权IP成功！")
}

func disableAcceptDomain(params ...string) {
	domain, err := public.Rconfigfile(config_path)
	if err != nil {
		return
	}
	domain["accept_domain"] = ""
	err = public.Wconfigfile(config_path, domain)
	if err != nil {
		return
	}

	fmt.Printf("关闭授权域名成功！")
}

func disableTwoAuth(params ...string) {
	twoAuth, err := public.Rconfigfile(two_auth)
	if err != nil {
		return
	}
	twoAuth["open"] = false
	err = public.Wconfigfile(two_auth, twoAuth)
	if err != nil {
		return
	}

	fmt.Printf("关闭动态口令成功！")
}

func addIpList(params ...string) {
	if len(params) > 0 {
		ip_type := params[0]
		types := params[1]
		startIP := params[2]
		endIP := ""
		endLog := ""
		if len(params) > 3 {
			endIP = params[3]
			endLog = params[3]
		}

		createTime := time.Now().Unix()
		open := 1
		var log_flag string

		if startIP == "" {
			fmt.Println("起始IP不能为空")
			return
		}

		notes := ""
		ipType := "v4"
		OneIP := uint32(0)
		TwoIP := uint32(0)
		if ip_type == "0" {
			if !public.IsIpv4(params[2]) {
				fmt.Println("IP格式不合法")
				return
			}

			OneIP = public.IpToLong(startIP)

			if len(endIP) > 0 {
				if !public.IsIpv4(endIP) {
					fmt.Println("IP格式不合法")
					return
				}
				if public.IpToLong(startIP) > public.IpToLong(endIP) {
					fmt.Println("起始IP不能大于结束IP")
					return
				}
				TwoIP = public.IpToLong(endIP)
			} else {
				TwoIP = public.IpToLong(startIP)
				endLog = params[2]
			}
		}
		if ip_type == "1" {
			parts := strings.Split(params[2], "/")
			if len(parts) > 1 && public.IsIpv6(parts[0]) {
				l, ok := strconv.Atoi(parts[1])
				if ok != nil {
					fmt.Println(ok)
					return
				}

				if l < 5 || l > 128 {
					fmt.Println("IP格式不合法")
					return
				}
			} else {
				if !public.IsIpv6(parts[0]) {
					fmt.Println("IP格式不正确")
					return
				}
			}

			startIP = params[2]
			endIP = ""
			endLog = ""
			ipType = "v6"
		}

		path := ""
		name := ""

		switch types {
		case "0":
			path = ipWhite
			name = "IP白名单"
			log_flag = "0"

		case "1":
			path = ipBlack
			name = "IP黑名单"
			log_flag = "1"

		default:
			fmt.Println("参数不合法!")
			return
		}
		fileData, err := rIPFile(path)
		if err != nil {
			fmt.Println("读取文件失败!")
			return
		}
		for _, values := range fileData {
			if ip_type == "0" && public.InterfaceToString(values[6]) == "v4" {
				if uint32(values[0].(float64)) == OneIP && uint32(values[1].(float64)) == TwoIP {
					fmt.Println("IP已添加")
					return
				}
			}
			if ip_type == "1" && public.InterfaceToString(values[6]) == "v6" {
				if strings.Contains(values[0].(string), startIP) {
					fmt.Println("IP已添加")
					return
				}
			}
		}

		ipIndex := public.RandomStr(20)
		count := 0
		ranges := make([]interface{}, 0)

		if ip_type == "0" {
			ranges = append(ranges, OneIP, TwoIP, notes, createTime, open, count, ipType, ipIndex)
		}

		if ip_type == "1" {
			ranges = append(ranges, startIP, endIP, notes, createTime, open, count, ipType, ipIndex)
		}

		fileData = append(fileData, ranges)

		sort.Slice(fileData, func(i, j int) bool {
			return public.InterfaceToInt(fileData[i][3]) > public.InterfaceToInt(fileData[j][3])
		})
		text, status := json.Marshal(fileData)
		if status != nil {
			public.WriteFile(path, "[]")
			fmt.Println("status")
			return
		}

		_, err = public.WriteFile(path, string(text))
		if err != nil {
			fmt.Println("err")
			return
		}
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
		ipLog := f(params[2], endLog)
		public.WriteOptLog(fmt.Sprintf("%s设置【%s】成功", name, ipLog), log_type[log_flag], 1)
		fmt.Println("设置成功!")
	}
}

func rIPFile(path string) ([][]interface{}, error) {
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

func f(ip1, ip2 string) string {
	if ip2 == "" {
		return ip1
	}

	if ip1 == ip2 {
		return ip1
	}

	return ip1 + "-" + ip2
}

func clearList(params ...string) {
	if params == nil {
		fmt.Println("参数不能为空")
		return
	}

	types := params[0]
	path := ""
	name := ""
	var log_flag string
	switch types {
	case "0":
		path = ipWhite
		name = "IP白名单"
		log_flag = "0"
	case "1":
		path = ipBlack
		name = "IP黑名单"
		log_flag = "1"
	case "2":
		path = uaWhite
		name = "UA白名单"
		log_flag = "2"
	case "3":
		path = uaBlack
		name = "UA黑名单"
		log_flag = "3"
	case "4":
		path = urlWhite
		name = "URI白名单"
		log_flag = "4"
	case "5":
		path = urlBlack
		name = "URI黑名单"
		log_flag = "5"
	default:
		fmt.Println("参数不合法!")
	}

	_, err := public.WriteFile(path, "[]")
	if err != nil {
	}

	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
	public.WriteOptLog(fmt.Sprintf("清空%s成功", name), log_type[log_flag], 1)
	fmt.Printf("清空%s成功\n", name)
}

func getIp(params ...string) {
	if params == nil {
		fmt.Println("参数不能为空")
		return
	}

	types := params[0]
	path := ""

	switch types {
	case "0":
		path = ipWhite
	case "1":
		path = ipBlack

	default:
		fmt.Println("参数不合法!")
	}

	fileData, err := rIPFile(path)
	if err != nil {
		fmt.Println("读取文件失败!")
	}
	var lines []interface{}

	for _, values := range fileData {
		if values[6].(string) == "ip_group" {
			continue
		}

		if values[6].(string) == "v6" {
			lines = append(lines, values)
			continue
		}

		values[0] = public.LongToIp(uint32(values[0].(float64)))
		values[1] = public.LongToIp(uint32(values[1].(float64)))
		lines = append(lines, values)
	}

	fmt.Println(lines)
}

func deleteIp(params ...string) {
	if params == nil {
		fmt.Println("参数不能为空")
		return
	}

	types := params[0]
	id := params[1]
	index := make([]string, 0)
	index = append(index, id)
	path := ""
	name := ""
	var log_flag string
	switch types {
	case "0":
		path = ipWhite
		name = "IP白名单"
		log_flag = "0"
		fileData, err := rIPFile(path)
		if err != nil {
			fmt.Println("读取文件失败!")
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
			delContent := f(start, end)
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")

		rules_js, err := json.Marshal(fileData)
		if err != nil {
			fmt.Println("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			fmt.Println("写入IP白名单配置失败")
		}
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), log_type[log_flag], 1)
		fmt.Println("删除成功")

	case "1":
		path = ipBlack
		name = "IP黑名单"
		log_flag = "1"
		fileData, err := rIPFile(path)
		if err != nil {
			fmt.Println("读取文件失败!")
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
			delContent := f(start, end)
			if len(del_rules) > 1 {
				rule_log_del += delContent + ","
			} else {
				rule_log_del += delContent
			}
		}
		rule_log_del = strings.TrimSuffix(rule_log_del, ",")

		rules_js, err := json.Marshal(fileData)
		if err != nil {
			fmt.Println("转json失败：")
		}
		_, err = public.WriteFile(path, string(rules_js))
		if err != nil {
			fmt.Println("写入IP黑名单配置失败")
		}
		public.WriteOptLog(fmt.Sprintf("%s删除【%s】", name, rule_log_del), log_type[log_flag], 1)
		public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)
		fmt.Println("删除成功")
	}
}

func ClusterGetUpperIp(params ...string) {
	if clusterCommon.ClusterState() != clusterCommon.CLUSTER_LOWER {
		printDefault()
		return
	}

}

func ClusterSetUpperIp(params ...string) {
	if clusterCommon.ClusterState() != clusterCommon.CLUSTER_LOWER {
		printDefault()
		return
	}

	if len(params) < 1 {
		fmt.Println("Missing parameters")
		return
	}
	if !validate.IsHost(params[0]) {
		fmt.Println("Incorrect upper ip")
		return
	}

	fmt.Println("Success")
}
