package public

import (
	"CloudWaf/core"
	"CloudWaf/core/authorization"
	"CloudWaf/core/cache"
	"CloudWaf/core/jwt"
	"CloudWaf/core/language"
	"CloudWaf/core/logging"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/db"
	"CloudWaf/public/system"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	url "net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maxmind/mmdbinspect/pkg/mmdbinspect"
	"github.com/oschwald/maxminddb-golang"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type ipIndex struct {
	startip, endip             uint32
	local_offset, local_length uint32
}

type prefixIndex struct {
	start_index, end_index uint32
}

type ipSearch struct {
	data               *maxminddb.Reader
	prefixMap          map[uint32]prefixIndex
	firstStartIpOffset uint32
	prefixStartOffset  uint32
	prefixEndOffset    uint32
	prefixCount        uint32
}

type IpInfo struct {
	Continent   string `json:"continent"`
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Carrier     string `json:"carrier"`
	Division    string `json:"division"`
	EnCountry   string `json:"en_country"`
	EnShortCode string `json:"en_short_code"`
	Longitude   string `json:"longitude"`
	Latitude    string `json:"latitude"`
}

type ApiInfo struct {
	Open      bool     `json:"open"`
	Token     string   `json:"token"`
	LimitAddr []string `json:"limit_addr"`
}

type mysqlConnStore struct {
	conn  *db.MySql
	timer *time.Timer
}

type sqliteConnStore struct {
	conn  *db.Sqlite
	timer *time.Timer
}

var (
	ips                 *ipSearch = nil
	systeminfo                    = &system.Sys{}
	mysqlConnMutex                = sync.RWMutex{}
	mysqlConnIdleDelay            = 60 * time.Second
	mysqlConnections              = make(map[string]*mysqlConnStore)
	sqliteConnMutex               = sync.RWMutex{}
	sqliteConnIdleDelay           = 60 * time.Second
	sqliteConnections             = make(map[string]*sqliteConnStore)
	mutex                         = sync.Mutex{}
	ArgsCheckListInt              = map[string]bool{
		"site_id": true,
	}
)

type Record struct {
	Network string `json:"Network"`
	Record  struct {
		Country struct {
			City      string  `json:"city"`
			Country   string  `json:"country"`
			Longitude float64 `json:"longitude"`
			Latitude  float64 `json:"latitude"`
			EnCountry string  `json:"en_short_code"`
			Province  string  `json:"province"`
		} `json:"country"`
	} `json:"Record"`
}

func ipSearchNew() (ipSearch, error) {
	if ips == nil {
		var err error
		ips, err = loadIpDat()
		if err != nil {
			logging.Error("the IP Dat loaded failed!")
			return *ips, err
		}
	}
	return *ips, nil
}

func loadIpDat() (*ipSearch, error) {
	p := ipSearch{}
	reader, err := mmdbinspect.OpenDB("/www/cloud_waf/console/data/Bt-GeoLite2-City.mmdb")
	if err != nil {
		logging.Error("the IP Dat loaded failed!")
		return nil, err
	}
	p.data = reader
	return &p, nil
}

func (p ipSearch) Get(ip string) string {
	var record []Record
	if p.data == nil {
		return ""
	}
	records, err := mmdbinspect.RecordsForNetwork(*p.data, true, ip)
	if err != nil {
		logging.Error("the IP Dat loaded failed!")
		return ""
	}
	prettyJSON, err := mmdbinspect.RecordToString(records)
	if err != nil {
		logging.Error("the IP Dat loaded failed!")
		return ""
	}
	err = json.Unmarshal([]byte(prettyJSON), &record)
	if err != nil {
		return ""
	}
	return record[0].Record.Country.City + "|" + record[0].Record.Country.Country + "|" + record[0].Record.Country.Province + "|" + record[0].Record.Country.EnCountry + "|" + fmt.Sprintf("%f", record[0].Record.Country.Latitude) + "|" + fmt.Sprintf("%f", record[0].Record.Country.Longitude)
}

func IpToLong(ip string) uint32 {
	quads := strings.Split(ip, ".")
	var result uint32 = 0
	a, _ := strconv.Atoi(quads[3])
	result += uint32(a)
	b, _ := strconv.Atoi(quads[2])
	result += uint32(b) << 8
	c, _ := strconv.Atoi(quads[1])
	result += uint32(c) << 16
	d, _ := strconv.Atoi(quads[0])
	result += uint32(d) << 24
	return result
}

func GetIPAreaSrc(ip string) string {
	if !IsIpv4(ip) {
		return ""
	}
	p, _ := ipSearchNew()
	ipstr := p.Get(ip)
	return ipstr
}

func GetIPAreaIpInfo(ip string) IpInfo {
	ip_area := GetIPAreaSrc(ip)
	if !strings.Contains(ip_area, "|") {
		ip_area = "||||||||||"
	}
	ip_area_arr := strings.Split(ip_area, "|")

	ip_info := IpInfo{}
	ip_info.Country = ip_area_arr[1]
	ip_info.Province = ip_area_arr[2]
	ip_info.City = ip_area_arr[0]
	ip_info.EnCountry = ip_area_arr[3]
	ip_info.Longitude = ip_area_arr[5]
	ip_info.Latitude = ip_area_arr[4]
	curLanguage := core.Language()
	if curLanguage == language.EN {
		ip_info.City = ""
		ip_info.Province = ""
		ip_info.Country = ip_info.EnShortCode
	}
	if ip_info.Country == "" || ip_info.Country == "保留" {
		if curLanguage == language.EN {
			ip_info.Country = "intranet"
		} else {
			ip_info.Country = "内网地址"
		}
	}
	return ip_info
}

func GetIPAreaBrief(ip string) string {
	ip_info := GetIPAreaIpInfo(ip)
	_arr := []string{ip_info.Country, ip_info.Province, ip_info.City, ip_info.Region, ip_info.Carrier}
	ip_area_brief := strings.Join(_arr, " ")
	ip_area_brief = strings.Replace(ip_area_brief, "  ", " ", -1)
	ip_area_brief = strings.Trim(ip_area_brief, " ")
	return ip_area_brief
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func FileSize(filename string) int64 {
	fi, err := os.Stat(filename)

	if err != nil {
		return 0
	}

	return fi.Size()
}

func ReadFileBytes(filename string) ([]byte, error) {
	if !FileExists(filename) {
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

func ReadFile(filename string) (string, error) {
	context, err := ReadFileBytes(filename)
	return string(context), err
}

func WriteFile(filename string, context string) (bool, error) {
	fd, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return false, err
	}
	defer fd.Close()

	fd.WriteString(context)
	return true, nil
}

func GetHttpClient(timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	HttpClient := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}
	return HttpClient
}

func HttpPost(url string, data url.Values, timeout int) (string, error) {
	client := GetHttpClient(timeout)
	resp, err := client.PostForm(url, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(context), nil
}

func HttpPostJson(url string, data string, timeout int) (string, error) {
	client := GetHttpClient(timeout)
	resp, err := client.Post(url, "application/json", strings.NewReader(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(context), nil
}

func HttpPostByToken(urlString string, timeout int) (string, error) {
	contextString := ""
	client := GetHttpClient(timeout)

	token, err := GetConfigRouteToken()
	if err != nil {
		return contextString, err
	}
	dataValues, err := url.ParseQuery("token=" + token)
	if err != nil {
		return "", err
	}
	resp, err := client.PostForm(urlString, dataValues)
	if err != nil {
		return contextString, err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(context), nil
}

func HttpPutJson(url string, data string, timeout int) (string, error) {
	client := GetHttpClient(timeout)
	req, err := http.NewRequest("PUT", url, strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	client.CloseIdleConnections()
	return string(context), nil
}

func HttpDeleteJson(url string, data string, timeout int) (string, error) {
	client := GetHttpClient(timeout)
	req, err := http.NewRequest("DELETE", url, strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(context), nil
}

func HttpGet(url string, timeout int) (string, error) {
	client := GetHttpClient(timeout)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	context, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(context), nil
}

func StringMd5(str string) (string, error) {
	obj := md5.New()
	_, err := obj.Write([]byte(str))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(obj.Sum(nil)), nil
}

func StringMd5WithSalt(password, salt string) (string, error) {
	saltedPassword := []byte(password + salt)
	hash := md5.New()
	hash.Write(saltedPassword)
	hashedPassword := hash.Sum(nil)
	return hex.EncodeToString(hashedPassword), nil
}

func FileMd5(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const bufferSize = 65536
	obj := md5.New()
	for buf, reader := make([]byte, bufferSize), bufio.NewReader(f); ; {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		obj.Write(buf[:n])
	}
	return hex.EncodeToString(obj.Sum(nil)), nil
}

func JsonDecode(json_str string) (map[string]interface{}, error) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(json_str), &data)
	return data, err
}

func JsonEncode(data map[string]interface{}) (string, error) {
	json_str, err := json.Marshal(data)
	return string(json_str), err
}

func InterfaceArray_To_StringArray(data []interface{}) []string {
	var str []string
	for _, v := range data {
		str = append(str, InterfaceToString(v))
	}
	return str
}

func InterfaceArray_To_IntArray(data []interface{}) []int {
	var str []int
	for _, v := range data {
		str = append(str, InterfaceToInt(v))
	}
	return str
}

func Iso8601_To_Time(timestr string) int64 {
	result, err := time.ParseInLocation("2006-01-02T15:04:05+08:00", timestr, time.Local)
	if err != nil {
		return -1
	}
	return result.Unix()
}

func Is_Array_ByString(keys []string, key string) bool {
	for _, v := range keys {
		if v == key {
			return true
		}
	}
	return false
}

func IntToString(i int) string {
	return strconv.Itoa(i)
}

func Int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}

func Float64ToString(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func GetNowDate() string {
	return time.Now().Format("2006-01-02")
}

func GetNowTime() int64 {
	return time.Now().Unix()
}

func GetNowTimeStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func InterfaceToString(data interface{}) string {
	if data == nil {
		return ""
	}
	res := ""
	switch v := data.(type) {
	case string:
		res = v
	case int:
		res = strconv.Itoa(v)
	case int16:
		res = strconv.Itoa(int(v))
	case int32:
		res = strconv.Itoa(int(v))
	case int64:
		res = strconv.Itoa(int(v))
	case uint:
		res = strconv.Itoa(int(v))
	case uint16:
		res = strconv.Itoa(int(v))
	case uint32:
		res = strconv.Itoa(int(v))
	case uint64:
		res = strconv.Itoa(int(v))
	case float32:
		res = strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		res = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		res = strconv.FormatBool(data.(bool))
	default:
		return res
	}

	return strings.TrimSpace(res)
}

func InterfaceToInt(data interface{}) int {
	if data == nil {
		return 0
	}
	switch data.(type) {
	case string:
		result, _ := strconv.Atoi(data.(string))
		return result
	case int:
		return data.(int)
	case int64:
		return int(data.(int64))
	case float64:
		return int(data.(float64))
	case bool:
		if data.(bool) {
			return 1
		} else {
			return 0
		}
	default:
		return 0
	}
}

func InterfaceToInt64(data interface{}) int64 {
	if data == nil {
		return 0
	}

	switch data.(type) {
	case string:
		result, _ := strconv.ParseInt(data.(string), 10, 64)
		return result
	case int:
		return int64(data.(int))
	case int64:
		return data.(int64)
	case float64:
		return int64(data.(float64))
	case bool:
		if data.(bool) {
			return 1
		} else {
			return 0
		}
	default:
		return 0
	}
}

func InterfaceToFloat64(data interface{}) float64 {
	if data == nil {
		return 0
	}

	switch data.(type) {
	case string:
		result, _ := strconv.ParseFloat(data.(string), 64)
		return result
	case int:
		return float64(data.(int))
	case int64:
		return float64(data.(int64))
	case float64:
		return data.(float64)
	case bool:
		if data.(bool) {
			return 1
		} else {
			return 0
		}
	default:
		return 0
	}
}

func InterfaceToBool(data interface{}) bool {
	if data == nil {
		return false
	}

	switch data.(type) {
	case string:
		result, _ := strconv.ParseBool(data.(string))
		return result
	case int:
		if data.(int) == 1 {
			return true
		} else {
			return false
		}
	case int64:
		if data.(int64) == 1 {
			return true
		} else {
			return false
		}
	case float64:
		if data.(float64) == 1 {
			return true
		} else {
			return false
		}
	case bool:
		return data.(bool)
	default:
		return false
	}
}

func StringToInt(data string) int {
	result, _ := strconv.Atoi(data)
	return result
}

func StringToInt64(data string) int64 {
	result, _ := strconv.ParseInt(data, 10, 64)
	return result
}

func StringToFloat64(data string) float64 {
	result, _ := strconv.ParseFloat(data, 64)
	return result
}

func StringToBool(data string) bool {
	result, _ := strconv.ParseBool(data)
	return result
}

func IsIpAddr(ip string) bool {
	ipAddr := net.ParseIP(ip)
	return ipAddr != nil
}

func IsIpv4(ip string) bool {
	return IsIpAddr(ip) && strings.Contains(ip, ".")

}

func IsIpv6(ip string) bool {
	return IsIpAddr(ip) && strings.Contains(ip, ":")
}

func UrlDecode(str string) string {
	if len(str) < 2 {
		return str
	}
	body, err := url.QueryUnescape(str)
	if err != nil {
		return UrlDecode(str[:len(str)-2])
	}
	return body
}

func UrlEncode(str string) string {
	return url.QueryEscape(str)
}

func InArray(key string, arr []string) bool {
	for _, v := range arr {
		if v == key {
			return true
		}
	}
	return false
}

func GetSqlParams(args ...any) []interface{} {
	var params []interface{}
	if args == nil {
		return params
	}
	params = append(params, args...)
	return params
}

func RandomStr(n int) string {
	s, err := jwt.RandomStr(n)

	if err == nil {
		return s
	}
	r := mRand.New(mRand.NewSource(time.Now().UnixNano()))
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	num := len(letterBytes)
	for i := range b {
		b[i] = letterBytes[r.Intn(num)]
	}
	return string(b)
}

func PanicTrace(err interface{}) string {
	return core.PanicTrace(err)
}

func GetMySqlConfig(configName string) db.MySqlConfig {
	if !FileExists(MYSQL_CONFIG_FILE) {
		panic("MySQL数据库配置 " + configName + " 不存在")
	}

	configBs, err := ReadFileBytes(MYSQL_CONFIG_FILE)
	if err != nil {
		panic("MySQL数据库配置 " + configName + " 失败：" + err.Error())
	}

	m := make(map[string]db.MySqlConfig)

	err = json.Unmarshal(configBs, &m)
	if err != nil {
		tmp := db.MySqlConfig{}
		if err := json.Unmarshal(configBs, &tmp); err != nil {
			panic("读取MySQL数据库配置 " + configName + " 失败：" + err.Error())
		}

		m = make(map[string]db.MySqlConfig)
		m["default"] = tmp

		bs, err := json.MarshalIndent(m, "", "    ")
		if err != nil {
			panic("读取MySQL数据库配置 " + configName + " 失败：" + err.Error())
		}

		if err := os.WriteFile(MYSQL_CONFIG_FILE, bs, 0644); err != nil {
			panic("读取MySQL数据库配置 " + configName + " 失败：" + err.Error())
		}
	}

	configName = strings.TrimSpace(configName)

	if configName == "" {
		configName = "default"
	}

	if v, ok := m[configName]; ok {
		return v
	}

	panic("MySQL数据库配置 " + configName + " 不存在")
}

func GetSqliteConfig(configName string) (string, string) {
	configBs, err := ReadFileBytes(SQLITE_CONFIG_FILE)
	if err != nil {
		panic("SQLITE数据库配置 " + configName + " 不存在")
	}
	type SqliteConf struct {
		DbFile string
		PreFix string
	}
	m := make(map[string]SqliteConf)
	err = json.Unmarshal(configBs, &m)
	if err != nil {
		tmp := SqliteConf{}
		if err := json.Unmarshal(configBs, &tmp); err != nil {
			panic("读取SQLITE数据库配置 " + configName + " 失败：" + err.Error())
		}

		m = make(map[string]SqliteConf)
		m["default"] = tmp

		bs, err := json.MarshalIndent(m, "", "    ")
		if err != nil {
			panic("读取SQLITE数据库配置 " + configName + " 失败：" + err.Error())
		}

		if err := os.WriteFile(SQLITE_CONFIG_FILE, bs, 0644); err != nil {
			panic("读取SQLITE数据库配置 " + configName + " 失败：" + err.Error())
		}
	}
	configName = strings.TrimSpace(configName)
	if configName == "" {
		configName = "default"
	}

	if v, ok := m[configName]; ok {
		return core.AbsPath(v.DbFile), v.PreFix
	}
	panic("SQLITE数据库配置 " + configName + " 不存在")
}

func WriteOptLog(content string, logType, uid int) (err error) {
	if clusterCommon.ClusterState() == clusterCommon.CLUSTER_LOWER {
		return nil
	}
	_, err = SqliteWithClose(func(conn *db.Sqlite) (interface{}, error) {
		return conn.NewQuery().
			Table("logs").
			Insert(map[string]interface{}{
				"uid":      uid,
				"log_type": logType,
				"content":  language.Locate(content),
			})
	})

	return err
}

func IsComplexPassword(password string) bool {
	password = strings.TrimSpace(password)
	if len(password) < 7 {
		return false
	}
	score := 0
	data, err := Rconfigfile("./config/sysconfig.json")
	if err != nil {
		return false
	}

	dataStruct := struct {
		PasswordComplexity bool `json:"password_complexity"`
	}{}

	if err = MapToStruct(data, &dataStruct); err == nil {
		if !dataStruct.PasswordComplexity {
			return true
		}
	}
	if regexp.MustCompile(`[A-Z]+`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[a-z]+`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[0-9]+`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[^A-Za-z0-9]+`).MatchString(password) {
		score++
	}

	return score > 2
}

func SqliteWithClose(handler func(conn *db.Sqlite) (interface{}, error), args ...any) (interface{}, error) {
	configName := "default"

	if len(args) > 0 {
		if v, ok := args[0].(string); ok {
			configName = v
		}
	}
	conn, err := db.NewSqlite(GetSqliteConfig(configName))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return handler(conn)
}

func MySqlWithClose(handler func(conn *db.MySql) (interface{}, error), args ...any) (interface{}, error) {
	configName := "default"
	if len(args) > 0 {
		if v, ok := args[0].(string); ok {
			configName = v
		}
	}
	conn, err := db.NewMySql(GetMySqlConfig(configName))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return handler(conn)
}

func SimplePage(query *db.Query, params any) (interface{}, error) {
	defaultP := 1
	defaultPSize := 20
	var (
		p     int
		pSize int
	)

	m := StructToMap(params)

	if v, ok := m["p"]; ok {
		p = InterfaceToInt(v)
	}
	if v, ok := m["p_size"]; ok {
		pSize = InterfaceToInt(v)
	}
	if p == 0 {
		p = defaultP
	}
	if pSize == 0 {
		pSize = defaultPSize
	}
	total, err := query.Count(false)

	if err != nil {
		return nil, err
	}
	lst, err := query.Limit([]int64{int64((p - 1) * pSize), int64(pSize)}).Select()

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total": total,
		"list":  lst,
	}, nil
}

func AddQueryWithKeyword(params map[string]interface{}, handler func(keyword string)) {
	keyword := ""
	if v, ok := params["keyword"]; ok {
		keyword = InterfaceToString(v)
	}
	if keyword == "" {
		return
	}
	handler(keyword)
}

func ConvertByte2String(byte []byte, charset Charset) (str string) {
	switch charset {
	case GB18030:
		decodeBytes, err := simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		if err != nil {
			return string(byte)
		}
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}
	return str
}

func ExecCommand(command string, args ...string) (stdout, stderr string, err error) {
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
	return ConvertByte2String(stdoutBuf.Bytes(), "GB18030"), ConvertByte2String(stderrBuf.Bytes(), "GB18030"), nil
}

func ExecCommandCombined(command string, args ...string) (result string, err error) {
	cmd := exec.Command(command, args...)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	err = cmd.Run()
	if err != nil {
		errMsg := err.Error() + ": " + stderrBuf.String()
		return result, errors.New(errMsg)
	}
	stdoutBuf.Write(stderrBuf.Bytes())
	if runtime.GOOS == "linux" {
		return stdoutBuf.String(), nil
	}
	return ConvertByte2String(stdoutBuf.Bytes(), "GB18030"), nil
}

func Rconfigfile(path string) (map[string]interface{}, error) {
	return core.Rconfigfile(path)
}

func Wconfigfile(path string, data map[string]interface{}) error {
	return core.Wconfigfile(path, data)
}

func ZeroTimestamp(ts ...time.Time) int64 {
	var now time.Time

	if len(ts) > 0 {
		now = ts[0]
	} else {
		now = time.Now()
	}

	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
}

func ParseDateStr(layout, value string, loc ...*time.Location) (int64, error) {
	t, err := ParseDateStrToTime(layout, value, loc...)

	if err != nil {
		return 0, err
	}

	return t.Unix(), nil
}

func ParseDateStrToTime(layout, value string, loc ...*time.Location) (time.Time, error) {
	var (
		t   time.Time
		err error
	)

	if len(loc) > 0 {
		t, err = time.ParseInLocation(layout, value, loc[0])
	} else {
		t, err = time.ParseInLocation(layout, value, time.Local)
	}

	if err != nil {
		return t, err
	}

	return t, nil
}

func GetLastDaysByTimestamp(days int) (int64, int64) {

	endTime := time.Now().Unix()
	startTime := endTime - int64(days)*24*60*60
	return startTime, endTime
}

func GetTimestampInterval(localTime time.Time) (int64, int64) {
	startTime := time.Date(localTime.Year(), localTime.Month(), localTime.Day(), 0, 0, 0, 0, localTime.Location()).Unix()
	endTime := time.Date(localTime.Year(), localTime.Month(), localTime.Day(), 23, 59, 59, 0, localTime.Location()).Unix()
	return startTime, endTime
}

func GetQueryTimestamp(queryDate string) (int64, int64) {
	var startDate, endDate int64

	now := time.Now()
	todayStart, todayEnd := GetTimestampInterval(now)

	switch {
	case queryDate == "" || queryDate == "today":
		startDate, endDate = todayStart, todayEnd
	case queryDate == "yesterday":
		startDate, endDate = todayStart-24*60*60, todayEnd-24*60*60
	case strings.HasPrefix(queryDate, "l"):
		days, _ := strconv.Atoi(queryDate[1:])
		startDate, endDate = GetLastDaysByTimestamp(days)
	default:
		dateRange := strings.Split(queryDate, "-")
		if len(dateRange) == 2 {
			startDate, _ = strconv.ParseInt(dateRange[0], 10, 64)
			endDate, _ = strconv.ParseInt(dateRange[1], 10, 64)
		} else {
			if _, err := strconv.Atoi(queryDate); err == nil {
				layout := "20060102"
				date, err := ParseDateStrToTime(layout, queryDate)
				if err == nil {
					startDate, endDate = GetTimestampInterval(date)
				}
			} else {
				startDate, endDate = 0, 0
			}
		}
	}
	return startDate, endDate
}

func GetDomainCertificates(addr string) (res []*x509.Certificate, err error) {
	var (
		host string
		conn *tls.Conn
	)
	host, _, err = net.SplitHostPort(addr)
	if err != nil {
		return res, err
	}
	conn, err = tls.DialWithDialer(&net.Dialer{
		Timeout:  5 * time.Second,
		Deadline: time.Now().Add(9 * time.Second),
	}, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return res, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

func GetDomainCertEndTime(addr string) (int64, error) {
	certs, err := GetDomainCertificates(addr)

	if err != nil {
		return 0, err
	}
	if len(certs) == 0 {
		return 0, errors.New("该网站没有配置SSL证书")
	}
	return certs[0].NotAfter.Unix(), nil
}

func CheckTwoAuth(passcode string) bool {
	data, err := Rconfigfile(core.AbsPath("./config/two_auth.json"))
	if err != nil {
		return false
	}
	secret := InterfaceToString(data["secret_key"])
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
			return false
		}
		if check == true {
			return true
		} else {
			return false
		}
	}
	return true
}

func GetTwoAuth() bool {
	data, err := Rconfigfile(core.AbsPath("./config/two_auth.json"))
	if err != nil {
		return false
	}
	if data["open"] == true {
		return true
	}
	return false
}

func Command(arg string) (result string, err error) {
	name := "/bin/bash"
	c := "-c"
	if runtime.GOOS == "windows" {
		name = "cmd"
		c = "/C"
	}
	cmd := exec.Command(name, c, arg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return "", nil
	}
	outStr, _ := string(stdout.Bytes()), string(stderr.Bytes())
	return strings.TrimSpace(outStr), nil
}

func Base64Transform(s, t string) string {
	switch t {
	case "url":
		return strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(s, "+", "-"), "/", "_"), "=")
	case "base64":
		remainder := len(s) % 4
		if remainder > 0 {
			s += strings.Repeat("=", 4-remainder)
		}
		return strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/")
	default:
		return s
	}
}

func IsIpNetwork(data string) bool {
	pattern := `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`
	regex := regexp.MustCompile(pattern)
	if regex.MatchString(data) {
		return true
	}

	return false
}

func IsIpRange(data string) bool {
	pattern := `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`
	regex := regexp.MustCompile(pattern)
	if regex.MatchString(data) {
		return true
	}
	return false
}

func LongToIp(l uint32) string {
	a := (l >> 24) & 0xFF
	b := (l >> 16) & 0xFF
	c := (l >> 8) & 0xFF
	d := l & 0xFF

	return strconv.Itoa(int(a)) + "." + strconv.Itoa(int(b)) + "." + strconv.Itoa(int(c)) + "." + strconv.Itoa(int(d))
}

func StructToMap(obj any) (data map[string]any) {
	return core.StructToMap(obj)
}

func MapToStruct(m any, obj any) (err error) {
	return core.MapToStruct(m, obj)
}

func PanelEncrypt(data map[string]interface{}) string {
	s := make([]string, 0)

	for k, v := range data {
		switch t := v.(type) {
		case string:
			s = append(s, UrlEncode(k)+"="+UrlEncode(t))
		case []byte:
			s = append(s, UrlEncode(k)+"="+UrlEncode(string(t)))
		case int:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(t)))
		case int32:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(int(t))))
		case int64:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(int(t))))
		case uint32:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(int(t))))
		case uint64:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(int(t))))
		case float64:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.Itoa(int(t))))
		case bool:
			s = append(s, UrlEncode(k)+"="+UrlEncode(strconv.FormatBool(t)))
		default:
			switch reflect.TypeOf(v).Kind() {
			case reflect.Slice, reflect.Array, reflect.Map, reflect.Struct:
				bs, err := json.Marshal(v)

				if err != nil {
					panic(err)
				}

				s = append(s, UrlEncode(k)+"="+UrlEncode(string(bs)))
			default:
				panic("Unsupported type marshal querystring")
			}
		}
	}

	return hex.EncodeToString([]byte(strings.Join(s, "&")))
}

func PanelDecrypt(data string) (any, error) {
	bs, err := hex.DecodeString(data)

	if err != nil {
		return nil, err
	}

	var m any

	if err = json.Unmarshal(bs, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func PanelRequest(u string, data map[string]any) (any, any) {
	uInfo, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	userinfo := types.BtAccountInfo{}
	if _, err = os.Stat(BT_USERINFO_FILE); err == nil {
		bs, err := os.ReadFile(BT_USERINFO_FILE)

		if err == nil {
			if err = json.Unmarshal(bs, &userinfo); err != nil {
				return nil, err
			}
		}
	}
	switch uInfo.Host {
	case "www.bt.cn", "bt.cn", "old.bt.cn":
		data["uid"] = userinfo.Uid
		data["access_key"] = userinfo.AccessKey
		data["serverid"] = strings.Repeat(authorization.SID(), 2)
	case "api.bt.cn":
		if _, ok := data["data"]; !ok {
			data["data"] = make(map[string]any)
		}

		if w, ok := data["data"].(map[string]any); ok {
			w["secret_key"] = userinfo.SecretKey
			w["serverid"] = strings.Repeat(authorization.SID(), 2)
			if strings.ToLower(uInfo.Path) == "/authorization/login" {
				if x, ok := w["password"]; ok {
					if pwd, ok := x.(string); ok {
						pwdMd5, err := StringMd5(pwd)

						if err != nil {
							return nil, err
						}

						w["password"] = pwdMd5
					}
				}
			}
			data["access_key"] = userinfo.AccessKey
			data["data"] = PanelEncrypt(w)

			if data["access_key"] == "" {
				data["access_key"] = strings.Repeat("b", 48)
			}
		}
	default:
		return nil, errors.New("不支持的域名：" + uInfo.Host)
	}
	bs, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	client := GetHttpClient(60)
	resp, err := client.Post(u, "application/json", bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	resultBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode > 499 {
		return nil, errors.New("请求过程发生错误: Server Internal Error")
	}
	m := struct {
		Status  bool        `json:"status"`
		ErrNo   int         `json:"err_no"`
		Msg     string      `json:"msg"`
		Data    string      `json:"data"`
		Res     interface{} `json:"res"`
		Success bool        `json:"success"`
		Nonce   int64       `json:"nonce"`
	}{}
	if err = json.Unmarshal(resultBytes, &m); err != nil {
		return nil, err
	}
	errMsg := "绑定信息已失效，请重新绑定堡塔账号"
	if userinfo.Uid == 0 {
		errMsg = "此功能需要绑定堡塔账号，请先绑定堡塔账号"
	}
	switch uInfo.Host {
	case "www.bt.cn", "bt.cn", "old.bt.cn":
		if !m.Success {
			if resp.StatusCode == 401 {
				return nil, core.CreateJsonResponse(2001, errMsg, 400)
			}

			if v, ok := m.Res.(string); ok {
				if strings.Contains(v, "请先登录") || strings.Contains(v, "绑定信息已失效，请重新绑定堡塔账号") {
					return nil, core.CreateJsonResponse(2001, errMsg, 400)
				}
				return nil, errors.New(v)
			}

			return nil, errors.New("请求失败")
		}

		return m.Res, nil
	case "api.bt.cn":
		if !m.Status {
			if m.ErrNo == 2001 {
				return nil, core.CreateJsonResponse(2001, errMsg, 400)
			}
			return nil, errors.New(m.Msg)
		}
		result, err := PanelDecrypt(m.Data)
		if err != nil {
			return nil, err
		}
		if strings.ToLower(uInfo.Path) == "/authorization/login" {
			bs, err := json.MarshalIndent(result, "", "    ")

			if err != nil {
				return nil, err
			}
			if err = os.WriteFile(BT_USERINFO_FILE, bs, 0644); err != nil {
				return nil, err
			}
		}
		return result, nil
	default:
		return nil, errors.New("不支持的域名：" + uInfo.Host)
	}
}

func PaginateData(data interface{}, pageNumber, pageSize int) map[string]interface{} {
	lst := make([]interface{}, 0, 256)
	dataV := reflect.Indirect(reflect.ValueOf(data))
	switch dataV.Type().Kind() {
	case reflect.Slice, reflect.Array:
		size := dataV.Len()
		for i := 0; i < size; i++ {
			lst = append(lst, dataV.Index(i).Interface())
		}
	default:
		panic("unsupported pagination type " + dataV.Type().String())
	}
	startIndex := (pageNumber - 1) * pageSize
	if startIndex >= len(lst) {
		return map[string]interface{}{
			"list":  lst,
			"total": len(lst),
		}
	}
	endIndex := startIndex + pageSize
	if endIndex > len(lst) {
		endIndex = len(lst)
	}
	return map[string]interface{}{
		"list":  lst[startIndex:endIndex],
		"total": len(lst),
	}
}

/*
@brief取两个数组的并集
*/
func UnionArrays(array1, array2 []string) []string {
	unionMap := make(map[string]bool)
	unionArray := []string{}

	for _, item := range array1 {
		unionMap[item] = true
	}

	for _, item := range array2 {
		unionMap[item] = true
	}

	for item := range unionMap {
		unionArray = append(unionArray, item)
	}

	return unionArray
}

func ParamsCheck(request *http.Request, check_params []string, error_info string) (map[string]interface{}, error) {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return nil, err
	}
	for _, value := range check_params {
		if value == "site_id" && params[value] != "" {

			count, err := M("site_info").Where("site_id=?", params[value]).Count()
			if err != nil {
				return nil, err
			}
			if count == 0 {
				return nil, errors.New("site_id不存在")
			}
		}
		if _, ok := params[value]; !ok {
			return nil, errors.New(error_info)
		}
	}
	return params, nil
}

func GetUid(request *http.Request) int {
	token, err := jwt.ParseTokenWithRequest(request)
	if err != nil {
		return 0
	}
	return token.Uid()
}

func ReadLastNumberLines(filePath string, n int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

func Tail(filename string, n int) (string, error) {
	result := make([]string, 0)

	err := ReadEachReverse(filename, func(row string, cnt int) bool {
		result = append([]string{row}, result...)
		return cnt < n
	})

	return strings.Join(result, "\n"), err
}

func ReadEachReverse(filename string, handler func(row string, cnt int) bool) error {
	fp, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fp.Close()
	endpos, err := fp.Seek(0, 2)
	if err != nil {
		return err
	}
	var offset int64
	lastOffset := endpos
	chunkSize := int64(4096)
	buf := make([]byte, chunkSize)
	last := ""
	loops := endpos / chunkSize
	i := int64(0)
	cnt := 0

	for ; i < loops; i++ {
		offset, err = fp.Seek(endpos+(chunkSize+chunkSize*i)*-1, 0)
		if err != nil {
			break
		}
		e := lastOffset - offset
		if _, err = fp.Read(buf); err != nil {
			break
		}
		lines := strings.Split(string(buf[:e]), "\n")
		j := len(lines) - 1
		if last != "" || buf[e-1] != '\n' {
			lines[j] = lines[j] + last
		}
		last = lines[0]
		for ; j > 0; j-- {
			cnt++
			if !handler(lines[j], cnt) {
				return nil
			}
		}
		lastOffset = offset
	}
	if i < loops {
		return nil
	}
	remainder := endpos % chunkSize
	if remainder == 0 {
		return nil
	}
	if _, err = fp.Seek(0, 0); err != nil {
		return err
	}
	if _, err = fp.Read(buf); err != nil {
		return err
	}
	lines := strings.Split(string(buf[:remainder]), "\n")
	j := len(lines) - 1

	if last != "" {
		lines[j] = lines[j] + last
		last = ""
	}
	for ; j > -1; j-- {
		cnt++
		if !handler(lines[j], cnt) {
			return nil
		}
	}
	return nil
}

func Head(filename string, n int) (string, error) {
	result := make([]string, 0)

	err := ReadEach(filename, func(row string, cnt int) bool {
		result = append(result, row)
		return cnt < n
	})

	return strings.Join(result, "\n"), err
}

func ReadEach(filename string, handler func(row string, cnt int) bool) error {
	fp, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fp.Close()
	reader := bufio.NewReader(fp)
	cnt := 0
	for {
		line, err := reader.ReadString('\n')

		if err != nil {
			break
		}

		if !handler(line, cnt) {
			break
		}
		cnt++
	}

	return nil
}

func Round(n float64, precision int) float64 {
	val, _ := strconv.ParseFloat(fmt.Sprintf("%."+strconv.Itoa(precision)+"f", n), 64)
	return val
}

func AddFilter(ip string) int {
	conn, err := net.Dial("unix", "/www/cloud_waf/nginx/conf.d/ip_filter.sock")
	if err != nil {
		return 0
	}
	defer conn.Close()
	message := "112!" + ip
	_, err = conn.Write([]byte(message))
	if err != nil {
		return 0
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return 0
	}

	return 1
}

func DelFilter(ip string) int {
	conn, err := net.Dial("unix", "/www/cloud_waf/nginx/conf.d/ip_filter.sock")
	if err != nil {
		return 0
	}
	defer conn.Close()
	message := "113!" + ip
	_, err = conn.Write([]byte(message))
	if err != nil {
		return 0
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return 0
	}

	return 1
}

func DelFilterallV4() int {
	conn, err := net.Dial("unix", "/www/cloud_waf/nginx/conf.d/ip_filter.sock")
	if err != nil {
		return 0
	}
	defer conn.Close()

	message := "109!bt_ip_filter"
	_, err = conn.Write([]byte(message))
	if err != nil {
		return 0
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return 0
	}

	return 1
}

func DelFilterallV6() int {
	conn, err := net.Dial("unix", "/www/cloud_waf/nginx/conf.d/ip_filter.sock")
	if err != nil {
		return 0
	}
	defer conn.Close()
	message := "109!bt_ip_filter_v6"
	_, err = conn.Write([]byte(message))
	if err != nil {
		return 0
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return 0
	}

	return 1
}

func TimeCost() func() {
	start := time.Now()
	return func() {
		tc := time.Since(start)
		fmt.Printf("Time cost = %v\n", tc)
	}
}

func IsDemo() bool {
	return core.IsDemo()
}

func GetSystemInfo() types.SystemInfo {
	return systeminfo.GetSystemInfo()
}

func M(tableName string, args ...any) *db.Query {
	var dbStore *mysqlConnStore
	configName := "default"
	if len(args) > 0 {
		if v, ok := args[0].(string); ok {
			configName = v
		}
	}
	mysqlConnMutex.RLock()
	if v, ok := mysqlConnections[configName]; ok {
		dbStore = v
	}
	mysqlConnMutex.RUnlock()
	if dbStore == nil {
		func() {
			mysqlConnMutex.Lock()
			defer mysqlConnMutex.Unlock()

			if v, ok := mysqlConnections[configName]; ok {
				dbStore = v
				return
			}
			var err error
			dbStore = &mysqlConnStore{
				timer: time.NewTimer(mysqlConnIdleDelay),
			}
			dbStore.conn, err = db.NewMySql(GetMySqlConfig(configName))
			if err != nil {
				panic(err)
			}
			mysqlConnections[configName] = dbStore
			core.RecoveryGo(func() {
				<-dbStore.timer.C
				defer func() {
					mysqlConnMutex.Lock()
					delete(mysqlConnections, configName)
					mysqlConnMutex.Unlock()
				}()
				dbStore.conn.Close()
			}).Run(nil)
		}()
	}
	if !dbStore.timer.Stop() {
		<-dbStore.timer.C
	}
	dbStore.timer.Reset(mysqlConnIdleDelay)

	return dbStore.conn.NewQuery().Table(tableName)
}

func S(tableName string, args ...any) *db.Query {
	var dbStore *sqliteConnStore

	configName := "default"

	if len(args) > 0 {
		if v, ok := args[0].(string); ok {
			configName = v
		}
	}

	sqliteConnMutex.RLock()
	if v, ok := sqliteConnections[configName]; ok {
		dbStore = v
	}
	sqliteConnMutex.RUnlock()
	if dbStore == nil {
		func() {
			sqliteConnMutex.Lock()
			defer sqliteConnMutex.Unlock()

			if v, ok := sqliteConnections[configName]; ok {
				dbStore = v
				return
			}
			var err error
			dbStore = &sqliteConnStore{
				timer: time.NewTimer(sqliteConnIdleDelay),
			}
			dbStore.conn, err = db.NewSqlite(GetSqliteConfig(configName))
			if err != nil {
				panic(err)
			}
			sqliteConnections[configName] = dbStore
			core.RecoveryGo(func() {
				<-dbStore.timer.C
				defer func() {
					sqliteConnMutex.Lock()
					delete(sqliteConnections, configName)
					sqliteConnMutex.Unlock()
				}()
				dbStore.conn.Close()
			}).Run(nil)
		}()
	}
	if !dbStore.timer.Stop() {
		<-dbStore.timer.C
	}
	dbStore.timer.Reset(sqliteConnIdleDelay)

	return dbStore.conn.NewQuery().Table(tableName)
}

func EscapeSymbols(str string, symbols []string) string {
	escapedStr := make([]byte, 0)

	for i := 0; i < len(str); i++ {
		for _, symbol := range symbols {
			if i > 0 && str[i] == symbol[0] && str[i-1] != '\\' {
				escapedStr = append(escapedStr, string('\\')...)
			}
		}
		escapedStr = append(escapedStr, str[i])
	}
	return string(escapedStr)
}

func AdminPath() string {
	return core.AdminPath()
}

func LatestVersion() (types.VersionInfo, error) {
	ver := types.VersionInfo{
		Version:     "-1",
		Description: "获取最新版本信息失败",
		CreateTime:  time.Now().Unix(),
	}
	typ := 0
	if clusterCommon.ClusterState() > clusterCommon.CLUSTER_DISABLED {
		typ = 1
	}
	res, errAny := PanelRequest(URL_BT_API+"/bt_waf/latest_version", map[string]any{
		"type": typ,
	})
	if errAny != nil {
		return ver, errors.New("获取最新版本号失败，无法与堡塔官网建立通信")
	}
	if err := MapToStruct(res, &ver); err != nil {
		return ver, errors.New("获取最新版本号失败：" + err.Error())
	}
	return ver, nil
}

func CompareVersion(curVersion string, cloudVersion string) bool {
	curVersionSlice := strings.Split(curVersion, ".")
	cloudVersionSlice := strings.Split(cloudVersion, ".")
	curVersionSliceLen := len(curVersionSlice)
	cloudVersionSliceLen := len(cloudVersionSlice)

	for i := 0; i < curVersionSliceLen; i++ {
		if i > curVersionSliceLen-1 {
			return false
		}
		vCur, _ := strconv.ParseInt(curVersionSlice[i], 10, 64)
		vCloud, _ := strconv.ParseInt(cloudVersionSlice[i], 10, 64)
		if vCur > vCloud {
			return false
		}
		if vCur < vCloud {
			return true
		}
	}
	vCur, _ := strconv.ParseInt(curVersionSlice[curVersionSliceLen-1], 10, 64)
	vCloud, _ := strconv.ParseInt(cloudVersionSlice[cloudVersionSliceLen-1], 10, 64)

	if vCur == vCloud {
		return false
	}

	return true
}

func UpdateMaliciousIp() {
	if clusterCommon.ClusterState() == clusterCommon.CLUSTER_LOWER {
		return
	}
	if _, err := os.Stat(MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE); err != nil {
		return
	}
	resAny, errAny := PanelRequest(URL_BT_GET_MALICIOUS_IP, map[string]any{
		"x_bt_token": "MzI3YjAzOGQ3Yjk3NjUxYjVlMDkyMGFm",
	})
	if errAny != nil {
		_ = AddTaskOnce(UpdateMaliciousIp, 6*time.Hour)
		return
	}
	res := make([]struct {
		Ip          string `json:"ip"`
		ReleaseTime int64  `json:"release_time"`
	}, 0)
	if err := MapToStruct(resAny, &res); err != nil {
		return
	}
	m := make(map[string]any)
	for _, v := range res {
		m[v.Ip] = map[string]any{
			"release_time": v.ReleaseTime,
		}
	}
	bs, err := json.Marshal(m)
	if err != nil {
		return
	}

	if err := os.WriteFile(MALICIOUS_IP_FILE, bs, 0644); err != nil {
		return
	}
	_, _ = HttpPostByToken("http://127.0.0.251/updateinfo?types=config", 2)
}

func NginxDownCheck() bool {
	failureCount := 0
	maxFailures := 5
	for failureCount < maxFailures {
		_, err := HttpPostByToken("http://127.0.0.251/get_global_status", 15)
		if err != nil {
			failureCount++
		} else {
			failureCount = 0
			break
		}
		time.Sleep(time.Second * 5)
	}

	return failureCount >= 3
}

func CheckPort(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer listener.Close()
	return true
}

func AllowPort(port string) error {
	if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
		_, err := Command(fmt.Sprintf("ufw allow %s/tcp && ufw reload", port))
		if err != nil {
			return err
		}
	}
	_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --add-port=%s/tcp > /dev/null 2>&1 && firewall-cmd --reload", port))
	if err != nil {
		return err
	}

	return nil
}

func DeletePort(port string) error {
	if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
		_, err := Command(fmt.Sprintf("ufw delete allow %s/tcp && ufw reload", port))
		if err != nil {
			return err
		}
	}
	_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --remove-port=%s/tcp > /dev/null 2>&1 && firewall-cmd --reload", port))
	if err != nil {
		return err
	}
	return nil
}

func IsLocalIP(ip string) bool {
	pattern := `^(192\.168|127|10|172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31))\.`
	regex := regexp.MustCompile(pattern)
	if regex.MatchString(ip) {
		return true
	}

	return false
}

func RequestRaw(method, url string, timeout int, headers map[string]string, body io.Reader, redirect bool, ctx context.Context) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	if !redirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest(method, url, body)

	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	return client.Do(req.WithContext(ctx))
}

func DomainCheck(siteName []string) []types.DomainCheck {
	data := make([]types.DomainCheck, 0)
	info := types.DomainCheck{}
	rg := core.NewRecoveryGoGroup(10)
	mutex := sync.Mutex{}
	for _, value := range siteName {
		rg.Immediate(func(value string) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*8)
			defer cancel()
			var DomainStatus bool
			var IsCDN bool
			var IsHttps bool
			var IsForceHTTPS bool
			intranetIp := make([]string, 0)
			extranet := make([]string, 0)
			rg2 := core.NewRecoveryGoGroup(3)
			rg2.Immediate(func() {
				ips, _ := net.LookupIP(value)
				for _, v := range ips {
					if IsLocalIP(v.String()) {
						if !Is_Array_ByString(intranetIp, v.String()) {
							intranetIp = append(intranetIp, v.String())
						}
						continue
					}
					if !Is_Array_ByString(extranet, v.String()) {
						extranet = append(extranet, v.String())
					}

				}
				if len(extranet) > 1 || len(intranetIp) > 1 {
					IsCDN = true
				}
			})
			rg2.Immediate(func() {
				response, err := RequestRaw("GET", "http://"+value, 15, map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
				}, nil, false, ctx)
				if err == nil {
					if response.StatusCode > 199 && response.StatusCode < 400 {
						DomainStatus = true
					}
					if response.StatusCode == 301 ||
						response.StatusCode == 302 ||
						response.StatusCode == 303 ||
						response.StatusCode == 307 ||
						response.StatusCode == 308 ||
						response.Header.Get("Upgrade-Insecure-Requests") == "1" ||
						strings.HasPrefix(response.Header.Get("Location"), "https") ||
						response.Header.Get("Content-Security-Policy") != "" {
						IsForceHTTPS = true
					}
					if response.Header.Get("X-Cache") != "" || response.Header.Get("Content-Delivery-Network") != "" {

						IsCDN = true
					}
				}
			})
			rg2.Immediate(func() {
				responseHttps, err := RequestRaw("GET", "https://"+value, 15, map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
				}, nil, false, ctx)
				if err != nil {
					return
				}
				if err == nil && responseHttps.StatusCode > 199 && responseHttps.StatusCode < 400 {
					IsHttps = true
				}
				if responseHttps.Header.Get("X-Cache") != "" || responseHttps.Header.Get("Content-Delivery-Network") != "" {

					IsCDN = true
				}
			})
			rg2.Wait()
			info = types.DomainCheck{
				SiteName:     value,
				Status:       DomainStatus,
				IsCDN:        IsCDN,
				IsHTTPS:      IsHttps,
				IsForceHTTPS: IsForceHTTPS,
			}

			info.SourceIPList.IntranetIPList = intranetIp
			info.SourceIPList.ExtranetIPList = extranet
			mutex.Lock()
			defer mutex.Unlock()
			data = append(data, info)
		}, value)
	}

	rg.Wait()
	return data
}

func DomainHttpsCross(domain string) (res bool) {
	domain = string(regexp.MustCompile(`(?i)^https?://`).ReplaceAll([]byte(domain), []byte("")))
	cs, err := GetDomainCertificates(domain)
	if err != nil || len(cs) < 1 {
		return false
	}
	for _, dn := range cs[0].DNSNames {
		if strings.HasPrefix(dn, "*") && strings.HasSuffix(domain, strings.TrimLeft(dn, "*")) {
			return false
		}
		if domain == dn {
			return false
		}
	}
	return true
}

func InterfaceArray_To_MapStringInterfaceArray(data []interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0)
	for _, v := range data {
		result = append(result, v.(map[string]interface{}))
	}
	return result
}

func NewBtAccountInfo() types.BtAccountInfo {
	btAccount := types.BtAccountInfo{}
	if FileExists(BT_USERINFO_FILE) {
		d, err := Rconfigfile(BT_USERINFO_FILE)
		if err != nil {
			return btAccount
		}

		if err := MapToStruct(d, &btAccount); err != nil {
			return btAccount
		}
	}

	return btAccount
}

func AllowPortByProtocol(port string, protocol string, isReload bool) error {
	if !validate.IsPort(port) {
		return errors.New("port is invalid")
	}
	protocolString := ""
	switch protocol {
	case "tcp":
		protocolString = "/tcp"
	case "udp":
		protocolString = "/udp"

	}
	if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
		_, err := Command(fmt.Sprintf("ufw allow %s%s", port, protocolString))
		if err != nil {
			return err
		}
	}
	_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --add-port=%s%s > /dev/null 2>&1", port, protocolString))
	if err != nil {
		return err
	}
	if isReload {
		ReloadFirewall()
	}

	return nil
}

func AllowPortsByProtocol(ports []string, protocol string, isReload bool) error {
	protocolString := ""
	switch protocol {
	case "tcp":
		protocolString = "/tcp"
	case "udp":
		protocolString = "/udp"

	}
	for _, port := range ports {
		if !validate.IsPort(port) {
			continue
		}
		if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
			_, err := Command(fmt.Sprintf("ufw allow %s%s", port, protocolString))
			if err != nil {
				continue
			}
			continue
		}
		if protocolString == "" {
			_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --add-port=%s/tcp > /dev/null 2>&1", port))
			if err != nil {
				logging.Error("firewall-cmd --permanent --zone=public --add-port=%s fail", port)
			}
			_, err = Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --add-port=%s/udp > /dev/null 2>&1", port))
			if err != nil {
				logging.Error("firewall-cmd --permanent --zone=public --add-port=%s fail", port)
			}
		} else {
			_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --add-port=%s%s > /dev/null 2>&1", port, protocolString))
			if err != nil {
				logging.Error("firewall-cmd --permanent --zone=public --add-port=%s%s fail", port, protocolString)
			}
		}
	}

	if isReload {
		ReloadFirewall()
	}
	return nil
}

func DeletePortByProtocol(port string, protocol string, isReload bool) error {
	if !validate.IsPort(port) {
		return errors.New("port is invalid")
	}
	protocolString := ""
	switch protocol {
	case "tcp":
		protocolString = "/tcp"
	case "udp":
		protocolString = "/udp"

	}
	if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
		_, err := Command(fmt.Sprintf("ufw delete allow %s%s", port, protocolString))
		if err != nil {
			return err
		}
	}
	if protocolString == "" {
		_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --remove-port=%s/tcp > /dev/null 2>&1", port))
		if err != nil {
			logging.Error("firewall-cmd --permanent --zone=public --remove-port=%s/tcp fail", port)
		}
		_, err = Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --remove-port=%s/udp > /dev/null 2>&1", port))
		if err != nil {
			logging.Error("firewall-cmd --permanent --zone=public --remove-port=%s/udp fail", port)
			return err
		}
	} else {
		_, err := Command(fmt.Sprintf("firewall-cmd --permanent --zone=public --remove-port=%s%s > /dev/null 2>&1", port, protocolString))
		if err != nil {
			return err
		}
	}
	if isReload {
		ReloadFirewall()
	}
	return nil
}

func ReloadFirewall() error {
	if FileExists("/usr/sbin/ufw") || FileExists("/usr/ufw") {
		_, err := Command("ufw reload")
		return err
	}
	_, err := Command("firewall-cmd --reload")
	if err != nil {
		return err
	}
	return nil
}

func SubmitNginxError() error {
	re := regexp.MustCompile(`(?i)(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(debug|info|notice|warn|error|crit|alert|emerg)\] `)
	tmp := make([]string, 0)
	lst := make([]string, 0)
	maxLine := 10000
	errorLogPath := core.AbsPath("/www/cloud_waf/nginx/logs/error.log")
	lastTimePath := core.AbsPath("./data/.nginx_error_log_last_time")
	lastTime := time.Now().Unix() - (86400 * 3)
	if bs, err := os.ReadFile(lastTimePath); err == nil {
		if i, err := strconv.Atoi(string(bs)); err == nil {
			lastTime = int64(i)
		}
	}
	curMaxTime := lastTime
	ReadEachReverse(errorLogPath, func(row string, cnt int) bool {
		tmp = append([]string{row}, tmp...)
		if m := re.FindStringSubmatch(row); len(m) == 3 {
			tUnix, err := ParseDateStr("2006/01/02 15:04:05", m[1])
			if err == nil {
				if tUnix <= lastTime {
					return false
				}
				if tUnix > curMaxTime {
					curMaxTime = tUnix
				}

				if m[2] == "error" || m[2] == "crit" || m[2] == "emerg" {
					lst = append([]string{strings.TrimSpace(strings.Join(tmp, "\n"))}, lst...)
				}
			}
			tmp = tmp[:0]
		}
		return cnt < maxLine
	})
	if err := os.WriteFile(lastTimePath, []byte(strconv.Itoa(int(curMaxTime))), 0644); err != nil {
		return err
	}
	if len(lst) == 0 {
		return nil
	}
	data := struct {
		XBtToken string `json:"x_bt_token"`
		Uid      int    `json:"uid"`
		ServerId string `json:"server_id"`
		Version  string `json:"version"`
		Error    string `json:"error"`
	}{}
	if FileExists(BT_USERINFO_FILE) {
		d, err := Rconfigfile(BT_USERINFO_FILE)
		if err != nil {
			return err
		}
		userinfo := types.BtAccountInfo{}
		if err := MapToStruct(d, &userinfo); err != nil {
			return err
		}

		data.Uid = userinfo.Uid
		data.ServerId = userinfo.ServerId
	}

	data.XBtToken = "ZjAzOTcwOTZkNjRlMGQ0ZjMyOTI0NDQw"
	data.Version = core.GetServerVersion()
	data.Error = strings.Join(lst, "\n")
	PanelRequest("https://api.bt.cn/bt_waf/submit_nginx_error", StructToMap(data))

	return nil
}

func DeleteFileAll(rootDir string) bool {
	if rootDir == "" || rootDir == "/" || rootDir == "." || rootDir == ".." || rootDir == "./" || rootDir == "../" {
		return false
	}
	if !strings.HasPrefix(rootDir, "/") {
		return false
	}
	if !strings.HasSuffix(rootDir, "/*") {
		return false
	}
	createDir := strings.Replace(rootDir, "/*", "/", -1)
	err := os.RemoveAll(createDir)

	if err != nil {
		return false
	}
	if !FileExists(createDir) {
		err := os.MkdirAll(createDir, 0755)
		if err != nil {
			return false
		}
	}

	return true
}

func ClearCoredumpFile() error {
	d, err := ExecCommandCombined("bash", "-c", "docker inspect -f '{{ .GraphDriver.Data.MergedDir }}' cloudwaf_nginx")
	if err != nil {
		return err
	}
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	if _, err = ExecCommandCombined("bash", "-c", "rm -f "+d+"/core.*"); err != nil {
		return err
	}

	return nil
}

func GetTableIdHelp(field string, value string) int64 {
	id := int64(0)
	fields := []string{"user_agent", "filter_rule", "risk_type", "incoming_value", "get_http_log", "http_log_path", "block_type", "ip", "method", "request_uri"}
	if !Is_Array_ByString(fields, field) {
		return id
	}
	skey, _ := StringMd5(field + value)
	is_exist := cache.Has(skey)
	if is_exist {
		id = cache.Get(skey).(int64)
		return id
	} else {
		id_ := selectDataHelp(field, value, field)
		if id_ == nil {
			id = insertDataHelp(field, value)
			if id < 0 {
				return 0
			}

		} else {
			id = id_.(int64)
		}
		cache.Set(skey, id, 86400)
	}

	return id
}

func insertDataHelp(table string, value string) int64 {
	query := M(table)
	if query == nil {
		return 0
	}
	pdata := make(map[string]interface{})
	pdata[table] = value

	id, err := query.Insert(pdata)
	if err != nil {
		return 0
	}
	return id

}

func selectDataHelp(table string, value string, field string) interface{} {
	query := M(table)
	if query == nil {
		return nil
	}

	val, err := query.Where(field+"=?", []interface{}{value}).Value("id")
	if err != nil {
		return nil
	}
	return val
}

func SelectDataByIdHelp(table string, id int64) interface{} {
	query := M(table)
	if query == nil {
		return nil
	}

	val, err := query.Where("id=?", []interface{}{id}).Value(table)
	if err != nil {
		return nil
	}
	return val
}

func GetNodeInfo() []map[string]interface{} {
	query := M("cluster_nodes")
	query.Field([]string{"id", "sid"}).
		Where("status=?", []interface{}{1}).
		Where("is_online = ? OR sid = ?", 1, authorization.SID())
	result, err := query.Select()
	if err != nil {
		return []map[string]interface{}{}
	}
	return result

}

func GetDayZeroTime(dateStr string) int64 {
	date, err := ParseDateStrToTime("2006-01-02", dateStr)
	if err != nil {
		return 0
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return 0
	}
	midnight := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, location)
	timestamp := midnight.Unix()
	return timestamp
}

func GetMasterSiteIdAndName() ([]*types.SiteIdAndName, error) {
	result := make([]*types.SiteIdAndName, 0)
	query := M("site_info").
		Field([]string{"site_id", "site_name", "create_time"}).
		Order("create_time", "desc")
	res, err := query.Select()

	if err != nil {
		return result, fmt.Errorf("获取列表失败：%w", err)
	}
	if err = MapToStruct(res, &result); err != nil {
		return result, fmt.Errorf("获取列表失败：%w", err)
	}
	return result, nil
}

func AddNodeToLoadBalance(groupId, nodeId int) error {
	if !M("load_balance").Where("id = ?", []any{groupId}).Exists() {
		return errors.New("集群规则[" + InterfaceToString(groupId) + "不存在")
	}
	query := M("load_balance").Field([]string{"nodes", "id"}).Where("id = ?", []any{groupId})
	res, err := query.Find()
	if err != nil {
		return err
	}
	nodes := []types.LoadNodes{}
	if err := json.Unmarshal([]byte(res["nodes"].(string)), &nodes); err != nil {
		return err
	}
	for _, v := range nodes {
		clusterNode, err := M("cluster_nodes").Field([]string{"id"}).Where("sid = ?", []any{v.Id}).Find()
		if err != nil {
			return err
		}
		if clusterNode["id"] == nodeId {
			return errors.New("节点[" + InterfaceToString(nodeId) + "已存在")
		}
	}
	clusterNode, err := M("cluster_nodes").Field([]string{"sid"}).Where("id = ?", []any{nodeId}).Find()
	if err != nil {
		return err
	}

	_, err = M("cluster_nodes").Where("id =?", []any{nodeId}).Update(map[string]any{"group_id": groupId})
	if err != nil {
		return err
	}
	node := types.LoadNodes{}
	node.Id = clusterNode["sid"].(string)
	node.Weight = 1
	node.Status = 1
	nodes = append(nodes, node)
	inDnsData, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	_, err = M("load_balance").Where("id = ?", []any{groupId}).Update(map[string]interface{}{"nodes": string(inDnsData)})
	if err != nil {
		return err
	}
	return nil
}

func DeleteNodeFromLoadBalance(groupId, nodeId int) error {
	if !M("load_balance").Where("id = ?", []any{groupId}).Exists() {
		return errors.New("集群规则[" + InterfaceToString(groupId) + "不存在")
	}
	query := M("load_balance").Field([]string{"nodes", "id"}).Where("id = ?", []any{groupId})
	res, err := query.Find()
	if err != nil {
		return err
	}
	nodes := []types.LoadNodes{}
	if err := json.Unmarshal([]byte(res["nodes"].(string)), &nodes); err != nil {
		return err
	}
	if len(nodes) == 1 {
		return errors.New("集群规则[" + InterfaceToString(groupId) + "]只有一个节点，不能删除")
	}
	deleteIndex := make([]int, 0)
	for k, v := range nodes {
		clusterNode, err := M("cluster_nodes").Field([]string{"id"}).Where("sid = ?", []any{v.Id}).Find()
		if err != nil {
			return err
		}
		if clusterNode["id"].(int64) == int64(nodeId) {
			deleteIndex = append(deleteIndex, k)
		}
	}
	sort.Slice(deleteIndex, func(i, j int) bool {
		return deleteIndex[i] > deleteIndex[j]
	})
	for _, v := range deleteIndex {
		if v == len(nodes)-1 {
			nodes = nodes[:v]
		} else {
			nodes = append(nodes[:v], nodes[v+1:]...)
		}
		_, err = M("cluster_nodes").Where("id =?", []any{nodeId}).Update(map[string]any{"group_id": 0})
		if err != nil {
			return err
		}
	}
	inDnsData, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	_, err = M("load_balance").Where("id = ?", []any{groupId}).Update(map[string]interface{}{"nodes": string(inDnsData)})
	if err != nil {
		return err
	}
	return nil

}

func IsUrl(url string) bool {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	if !validate.IsUrl(url) {
		return false
	}
	tmpUrl := ReplaceHttp(url)
	tmpUrl = strings.Split(tmpUrl, "/")[0]
	if !validate.IsHost(tmpUrl) {
		return false
	}
	return true
}

func IsCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	if err != nil {
		return false
	}
	return true
}

func OnlyReloadNginx() {
	_, steErr, err := ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-s", "reload")
	if err != nil {
		return
	}
	if steErr != "" {
		ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-s", "reload")
		return

	}
	return
}

func AppendFile(filename string, content string, withTime bool) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if withTime && content != "" {
		replaceLine := strings.ReplaceAll(content, "\n", "")
		if replaceLine != "" {
			content = GetNowTimeStr() + "   " + content
		}
	}
	_, err = file.WriteString("\n" + content)
	if err != nil {
		fmt.Println("无法写入文件:", err)
		return err
	}

	return nil
}

func IsTime(str string) bool {
	_, err := time.Parse("2006-01-02", str)
	if err != nil {
		return false
	}
	return true
}

func GetWAFApi() (ApiInfo, error) {
	apiInfo := ApiInfo{
		Open:      false,
		Token:     "",
		LimitAddr: []string{},
	}
	apiFilePath := "/www/cloud_waf/console/data/btwaf_api.json"
	content, err := ReadFile(apiFilePath)
	if err != nil {
		return apiInfo, fmt.Errorf("读取API配置文件失败: %v", err)
	}
	if err := json.Unmarshal([]byte(content), &apiInfo); err != nil {
		return apiInfo, fmt.Errorf("解析API配置文件失败: %v", err)
	}
	return apiInfo, nil
}

func (api *ApiInfo) WafAuthorization(requestTime string, requestToken string) bool {
	if !api.Open {
		return false
	}
	if requestTime == "" || requestToken == "" {
		return false
	}
	token_md5, err := StringMd5(api.Token)
	if err != nil {
		return false
	}
	newToken, err := StringMd5(requestTime + token_md5)
	if err != nil {
		return false
	}
	if newToken == requestToken {
		return true
	}

	return false
}

func (api *ApiInfo) CheckWafApiAccess(clientIP string) bool {
	if !api.Open {
		return false
	}
	for _, ip := range api.LimitAddr {
		if ip == "*" || ip == clientIP {
			return true
		}
	}
	return false
}
