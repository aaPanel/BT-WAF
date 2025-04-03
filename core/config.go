package core

import (
	"CloudWaf/core/cache"
	"CloudWaf/core/common"
	"CloudWaf/core/language"
	"CloudWaf/public/validate"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	serverPortFile    = common.AbsPath("./data/.server-port")
	serverVersionFile = common.AbsPath("./.ver")
	//go:embed .auth-ignore
	authIgnoreText   string
	authIgnoreMap    = make(map[string]struct{}, 16)
	authIgnorePrefix = make([]string, 0, 16)
	debugStateLoaded = false
	isDebug          = false
	demoStateLoaded  = false
	isDemo           = false
	LoginList        = map[string]bool{
		"/api/user/login":             true,
		"/api/user/get_validate_code": true,
		"/api/user/check_two_auth":    true,
		"/api/config/title":           true,
	}
)

func init() {
	parseAuthIgnore()
}

func parseAuthIgnore() {
	parts := strings.Split(authIgnoreText, "\n")

	for _, v := range parts {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.HasSuffix(v, "*") {
			authIgnorePrefix = append(authIgnorePrefix, strings.TrimRight(v, "*"))
			continue
		}
		authIgnoreMap[v] = struct{}{}
	}
}

func IgnoredApi(uri string) bool {
	if _, ok := LoginList[uri]; ok {
		return true
	}
	return false
}

func GetServerIp() (serverIp, localIp string) {
	cacheKey := "GLOBAL_SERVER_IP_AND_LOCAL_IP"
	if cache.Has(cacheKey) {
		cachedData := cache.Get(cacheKey).([]string)
		return cachedData[0], cachedData[1]
	}
	response, err := (&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}).Get("https://api.bt.cn/api/getIpAddress")

	if err == nil {
		defer response.Body.Close()
		bs, err := io.ReadAll(response.Body)
		if err == nil {
			serverIp = strings.Trim(string(bs), "[]")
			if net.ParseIP(serverIp) == nil {
				serverIp = ""
			}
		}
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		ip, _, err := net.SplitHostPort(conn.LocalAddr().String())
		if err == nil {
			localIp = ip
		}
	}
	if serverIp != "" {
		_ = cache.Set(cacheKey, []string{serverIp, localIp}, 86400)
	}
	if serverIp == "" {
		serverIp = "127.0.0.1"
	}
	if localIp == "" {
		localIp = "127.0.0.1"
	}
	return serverIp, localIp
}

func GetServerPort() (serverPort string) {
	os.MkdirAll(filepath.Dir(serverPortFile), 0644)
	defaultPort := "8379"
	_, err := os.Stat(serverPortFile)
	if err != nil {
		serverPort = defaultPort
		err = os.WriteFile(serverPortFile, []byte(serverPort), 0644)
		if err != nil {
			fmt.Println("持久化Web服务端口失败: ", err)
		}
	}
	if serverPort == "" {
		bs, err := os.ReadFile(serverPortFile)
		if err != nil {
			fmt.Println("获取Web服务端口失败: ", err)
			serverPort = defaultPort
		} else {
			serverPort = string(bs)
		}
	}
	if serverPort == "" {
		serverPort = defaultPort
		err = os.WriteFile(serverPortFile, []byte(serverPort), 0644)
		if err != nil {
			fmt.Println("持久化Web服务端口失败: ", err)
		}
	}
	return strings.TrimSpace(serverPort)
}

func SetServerPort(serverPort string) error {
	fp, err := os.OpenFile(serverPortFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)

	if err != nil {
		return err
	}
	defer fp.Close()
	if !validate.IsPort(serverPort) {
		return errors.New(fmt.Sprintf("端口范围错误: %s", serverPort))
	}
	_, err = fp.Write([]byte(serverPort))
	return err
}

func GetServerVersion() (version string) {
	os.MkdirAll(filepath.Dir(serverVersionFile), 0644)
	defaultVersion := "1.0"
	_, err := os.Stat(serverVersionFile)

	if err != nil {
		version = defaultVersion
		err = os.WriteFile(serverVersionFile, []byte(version), 0644)
		if err != nil {
			fmt.Println("1-获取版本号失败: ", err)
		}

	}
	if version == "" {
		bs, err := os.ReadFile(serverVersionFile)
		if err != nil {
			fmt.Println("2-获取版本号失败: ", err)
			version = defaultVersion
		} else {
			version = string(bs)
		}
	}
	if version == "" {
		version = defaultVersion
		err = os.WriteFile(serverVersionFile, []byte(version), 0644)
		if err != nil {
			fmt.Println("3-获取版本号失败: ", err)
		}
	}
	return strings.TrimSpace(version)
}

func GetSupportedStaticFileSuffix() []string {
	return []string{
		".html",
		".js",
		".css",
		".png",
		".jpg",
		".gif",
		".ico",
		".svg",
		".woff",
		".woff2",
		".ttf",
		".otf",
		".eot",
		".map",
	}
}

func Rconfigfile(path string) (map[string]interface{}, error) {
	k := path + "CONFIG"
	if cache.Has(k) {
		if v, ok := cache.Get(k).(map[string]interface{}); ok {
			return v, nil
		}
	}
	fp, err := os.Open(AbsPath(path))
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	data := make(map[string]any)
	if err := json.NewDecoder(fp).Decode(&data); err != nil {
		return nil, err
	}
	if err := cache.Set(k, data, 300); err != nil {
		return nil, err
	}

	return data, nil
}

func Wconfigfile(path string, data map[string]interface{}) error {
	k := path + "CONFIG"
	err := cache.Remove(k)
	if err != nil {
		return err
	}
	bs, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(AbsPath(path), bs, 0644); err != nil {
		return err
	}
	return nil
}

func AdminPath() string {
	data, err := Rconfigfile("./config/sysconfig.json")
	if err != nil {
		return ""
	}
	if _, ok := data["admin_path"]; !ok {
		return ""
	}
	if v, ok := data["admin_path"].(string); ok {
		return strings.TrimSpace(v)
	}

	return ""
}

func IsDebug() bool {
	if !debugStateLoaded {
		debugStateLoaded = true
		if _, err := os.Stat(AbsPath("./data/.debug")); err == nil {
			isDebug = true
		}
	}
	return isDebug
}

func IsDemo() bool {
	if !demoStateLoaded {
		demoStateLoaded = true
		if _, err := os.Stat(AbsPath("./data/.demo")); err == nil {
			isDemo = true
		}
	}
	return isDemo
}

func Language() string {
	data, err := Rconfigfile("./config/sysconfig.json")
	if err != nil {
		return ""
	}
	if _, ok := data["language"]; !ok {
		return language.CN
	}
	if v, ok := data["language"].(string); ok {
		return strings.ToUpper(strings.TrimSpace(v))
	}
	return language.CN
}

func Lan(key string, args ...any) string {
	currentLanguage := Language()

	m, ok := language.TRANS_MAP[currentLanguage]

	if !ok {
		panic("Invalid language [" + currentLanguage + "]")
	}

	v, ok := m[key]

	if !ok {
		panic("Invalid language trans-key [" + key + "]")
	}

	return fmt.Sprintf(v, args...)
}
