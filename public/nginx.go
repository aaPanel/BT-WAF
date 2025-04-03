package public

import (
	"CloudWaf/core"
	"CloudWaf/core/cache"
	"CloudWaf/core/logging"
	clusterCommon "CloudWaf/public/cluster_core/common"
	"CloudWaf/public/compress"
	"CloudWaf/public/db"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
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
)

var (
	NginxPath             = "/www/cloud_waf/nginx/"
	VhostPath             = NginxPath + "conf.d/vhost/"
	NginxStreamPath       = NginxPath + "conf.d/stream/"
	UserPath              = NginxPath + "conf.d/user"
	SiteIdPath            = NginxPath + "conf.d/other/siteid.json"
	WafSiteConfigPath     = NginxPath + "conf.d/waf/config/site.json"
	DomainConfig          = NginxPath + "conf.d/waf/config/domains.json"
	NginxJsonPath         = GlobalVhostPath + "nginx_json"
	CityConfig            = NginxPath + "conf.d/waf/rule/city.json"
	ProvinceConfig        = NginxPath + "conf.d/waf/rule/province.json"
	WafSiteConfigJsonPath = core.AbsPath("./config/waf_site.json")
	SliceSiteLogJson      = GlobalVhostPath + "slice_log_json/"
	SliceSiteLogPath      = core.AbsPath("./logs/slice_site_log.log")
	DomainsJsonPath       = NginxPath + "conf.d/waf/config/domains.json"
	SiteRootPath          = "/www/cloud_waf/wwwroot/"

	LogRootPath = NginxPath + "logs/"

	CertPath          = NginxPath + "conf.d/cert"
	GlobalVhostPath   = "/www/cloud_waf/vhost/"
	SslPath           = GlobalVhostPath + "ssl/"
	SiteJsonPath      = GlobalVhostPath + "site_json/"
	BackupPath        = NginxPath + "conf.d/backup/"
	ZipPath           = NginxPath + "conf.d/zip/"
	HistoryBackupPath = GlobalVhostPath + "history_backups/"

	SiteDomainConfigJson = SiteJsonPath + "domains.json"
	SiteWafConfigJson    = SiteJsonPath + "site.json"
	SiteGlobalConfig     = SiteJsonPath + "config.json"

	HistoryBackupConfig = HistoryBackupPath + "config/"
	updateSiteInfoLock  = sync.RWMutex{}

	logLock          = sync.RWMutex{}
	ErrIpWithHttp    = "，请参考如下正确填写：<br />http://192.168.10.10:8080"
	ErrIpWithNotHttp = "，请参考如下正确填写：<br />192.168.10.10:8080"

	SslCiphersDefault   = "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5"
	SslProtocolsDefault = []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}
	DomainList          = []string{"tk", "com", "cn", "top", "xyz", "net", "work", "vip", "email", "club", "site", "live", "wang", "online", "tech", "cc", "fans", "group", "host", "cloud", "shop", "team", "beer", "ren", "technology", "fashion", "luxe", "yoga", "red", "love", "ltd", "chat", "pub", "run", "city", "kim", "pet", "space", "fun", "store", "pink", "ski", "design", "ink", "wiki", "video", "company", "plus", "center", "cool", "fund", "gold", "guru", "life", "show", "today", "world", "zone", "social", "bio", "black", "blue", "green", "lotto", "organic", "poker", "promo", "vote", "archi", "voto", "fit", "website", "press", "icu", "art", "law", "band", "media", "cab", "cash", "cafe", "games", "link", "fan", "info", "pro", "mobi", "asia", "studio", "biz", "vin", "news", "fyi", "tax", "tv", "market", "shopping", "mba", "sale", "co", "中国", "企业", "我爱你", "移动", "中文网", "集团", "在线", "游戏", "网店", "网址", "网站", "商店", "娱乐"}
	DomainSuffix        = map[string]int{"archi": 1, "art": 1, "asia": 1, "band": 1, "beer": 1, "bio": 1, "biz": 1, "black": 1, "blue": 1, "cab": 1, "cafe": 1, "cash": 1, "cc": 1, "center": 1, "chat": 1, "city": 1, "cloud": 1, "club": 1, "cn": 1, "co": 1, "com": 1, "company": 1, "cool": 1, "design": 1, "email": 1, "fan": 1, "fans": 1, "fashion": 1, "fit": 1, "fun": 1, "fund": 1, "fyi": 1, "games": 1, "gold": 1, "green": 1, "group": 1, "guru": 1, "host": 1, "icu": 1, "info": 1, "ink": 1, "kim": 1, "law": 1, "life": 1, "link": 1, "live": 1, "lotto": 1, "love": 1, "ltd": 1, "luxe": 1, "market": 1, "mba": 1, "media": 1, "mobi": 1, "net": 1, "news": 1, "online": 1, "organic": 1, "pet": 1, "pink": 1, "plus": 1, "poker": 1, "press": 1, "pro": 1, "promo": 1, "pub": 1, "red": 1, "ren": 1, "run": 1, "sale": 1, "shop": 1, "shopping": 1, "show": 1, "site": 1, "ski": 1, "social": 1, "space": 1, "store": 1, "studio": 1, "tax": 1, "team": 1, "tech": 1, "technology": 1, "tk": 1, "today": 1, "top": 1, "tv": 1, "video": 1, "vin": 1, "vip": 1, "vote": 1, "voto": 1, "wang": 1, "website": 1, "wiki": 1, "work": 1, "world": 1, "xyz": 1, "yoga": 1, "zone": 1, "中国": 1, "中文网": 1, "企业": 1, "商店": 1, "在线": 1, "娱乐": 1, "我爱你": 1, "游戏": 1, "移动": 1, "网址": 1, "网店": 1, "网站": 1, "集团": 1}
)

type IpInfoList struct {
	IntranetIpList []string `json:"intranet_ip_list"`
	ExtranetIpList []string `json:"extranet_ip_list"`
}
type AddDomainInfo struct {
	Status       bool       `json:"status"`
	SourceIpList IpInfoList `json:"source_ip_list"`
	IsHttps      bool       `json:"is_https"`
	IsForceHttps bool       `json:"is_force_https"`
	IsCdn        bool       `json:"is_cdn"`
}

type Upstream struct {
	SiteName  []string
	Name      []string
	Algorithm []string
	Arguments []string
}

type SSLConfig struct {
	SSLCertificate         string   `json:"ssl_certificate"`
	SSLCertificateKey      string   `json:"ssl_certificate_key"`
	SSLProtocols           []string `json:"ssl_protocols"`
	SSLCiphers             []string `json:"ssl_ciphers"`
	SSLPreferServerCiphers string   `json:"ssl_prefer_server_ciphers"`
	SSLSessionCache        []string `json:"ssl_session_cache"`
	SSLSessionTimeout      string   `json:"ssl_session_timeout"`
	AddHeader              []string `json:"add_header"`
	ErrorPage              []string `json:"error_page"`
}

type LocationJson struct {
	MatchPriority     string   `json:"match_priority,omitempty"`
	MatchArguments    string   `json:"match_arguments,omitempty"`
	ProxyPass         string   `json:"proxy_pass,omitempty"`
	ProxySetHeader    []string `json:"proxy_set_header,omitempty"`
	ProxyNextUpstream []string `json:"proxy_next_upstream,omitempty"`
	ProxyCache        string   `json:"proxy_cache,omitempty"`
	TryFiles          []string `json:"try_files,omitempty"`
	Expires           string   `json:"expires,omitempty"`
	AccessLog         string   `json:"access_log,omitempty"`
	ErrorLog          string   `json:"error_log,omitempty"`
	Return            string   `json:"return,omitempty"`
}

type LocationNew struct {
	LocationEqual [][]map[string]interface{} `json:"location =,omitempty"`
	LocationNot   [][]map[string]interface{} `json:"location ,omitempty"`
	LocationTilde [][]map[string]interface{} `json:"location ^~,omitempty"`
	LocationStar  [][]map[string]interface{} `json:"location ~*,omitempty"`
	LocationRegex [][]map[string]interface{} `json:"location ~,omitempty"`
	LocationAt    [][]map[string]interface{} `json:"location @,omitempty"`
	HostName      string                     `json:"host,omitempty"`
}

type Location struct {
	LocationEqual [][]LocationConfig `json:"location =,omitempty"`
	LocationNot   [][]LocationConfig `json:"location ,omitempty"`
	LocationTilde [][]LocationConfig `json:"location ^~,omitempty"`
	LocationStar  [][]LocationConfig `json:"location ~*,omitempty"`
	LocationRegex [][]LocationConfig `json:"location ~,omitempty"`
	LocationAt    [][]LocationConfig `json:"location @,omitempty"`
}

type SiteJson struct {
	DomainFirstName string     `json:"domain_first_name"`
	SiteName        string     `json:"site_name"`
	SiteID          string     `json:"site_id"`
	Server          ServerJson `json:"server"`
	IsSSL           bool       `json:"is_ssl"`
	IsCDN           bool       `json:"is_cdn"`
	SourceProtocol  string     `json:"source_protocol"`
	AddTime         int        `json:"add_time"`
	ForceHttps      bool       `json:"force_https"`
	ProxyInfo       ProxyInfo  `json:"proxy_timeout"`
	Client          Client     `json:"client"`
}

type ProxyInfo struct {
	ProxyConnectTimeout string `json:"proxy_connect_timeout,omitempty"`
	ProxySendTimeout    string `json:"proxy_send_timeout,omitempty"`
	ProxyReadTimeout    string `json:"proxy_read_timeout,omitempty"`
}

type Client struct {
	MaxBodySize    string `json:"max_body_size"`
	BodyBufferSize string `json:"body_buffer_size"`
}

type ServerJson struct {
	Listen      [][]string          `json:"listen"`
	ListenTag   []map[string]string `json:"listen_tag"`
	ListenIpv6  bool                `json:"listen_ipv6"`
	ServerName  []string            `json:"server_name"`
	Index       []string            `json:"index"`
	Root        string              `json:"root"`
	If          [][]string          `json:"if"`
	SSL         SSLConfig           `json:"ssl"`
	UserInclude string              `json:"user_include"`
	Upstream    UpstreamJson        `json:"upstream"`
	Gzip        GzipJson            `json:"gzip"`
	Location    LocationNew         `json:"location"`
	Log         LogG                `json:"log"`
	Other       string              `json:"other"`
}

type GzipJson struct {
	Gzip   [][]string `json:"gzip"`
	Status string     `json:"status"`
}

type LocationConfig struct {
	MatchPriority     string     `json:"match_priority"`
	MatchArguments    string     `json:"match_arguments,omitempty"`
	ProxyPass         string     `json:"proxy_pass,omitempty"`
	ProxySetHeader    [][]string `json:"proxy_set_header,omitempty"`
	ProxyNextUpstream []string   `json:"proxy_next_upstream,omitempty"`
	ProxyCache        string     `json:"proxy_cache,omitempty"`
	TryFiles          []string   `json:"try_files,omitempty"`
	Expires           string     `json:"expires,omitempty"`
	AccessLog         string     `json:"access_log,omitempty"`
	ErrorLog          string     `json:"error_log,omitempty"`
	Return            string     `json:"return,omitempty"`
}
type LogG struct {
	Format     FormatLog  `json:"format"`
	LogSetting LogSetting `json:"log_setting"`
}

type FormatLogJson struct {
	Name   string   `json:"name"`
	Status bool     `json:"status"`
	Format []string `json:"format"`
}

type FormatLog struct {
	AccessLog FormatLogJson `json:"access_log,omitempty"`
	ErrorLog  FormatLogJson `json:"error_log,omitempty"`
}

type Remote struct {
	AccessLog []string `json:"access_log,omitempty"`
	ErrorLog  []string `json:"error_log,omitempty"`
}

type LogSetting struct {
	Local      Remote `json:"local"`
	Remote     Remote `json:"remote"`
	Mode       string `json:"mode"`
	FormatMode bool   `json:"format_mode"`
}

type UpstreamSingleInfo struct {
	Server           string `json:"server"`
	MaxFails         string `json:"max_fails"`
	FailTimeout      string `json:"fail_timeout"`
	Weight           string `json:"weight"`
	Status           int    `json:"status"`
	TodayAccessNum   int64  `json:"today_access_num"`
	TodayErrorNum    int64  `json:"today_error_num"`
	Qps              int64  `json:"qps"`
	ReturnSourceTime int64  `json:"return_source_time"`
	Ps               string `json:"ps"`
	AddTime          int    `json:"add_time"`
	Id               string `json:"id"`
}

type UpstreamJson struct {
	Name             string               `json:"name"`
	PollingAlgorithm string               `json:"polling_algorithm"`
	Host             string               `json:"host"`
	Server           []string             `json:"server"`
	ServerNew        []UpstreamSingleInfo `json:"server_new"`
	EnableNote       int                  `json:"enable_note"`
	CheckDns         CheckDns             `json:"check_dns"`
}
type CheckDns struct {
	Status         int64                      `json:"status"`
	InspectionTime int64                      `json:"inspection_time"`
	DomainAddress  map[string]ReturnDomainDns `json:"domain_address"`
}

type ReturnDomainDns struct {
	Address map[string]string `json:"address"`
}

type SiteInfos struct {
	SiteInfos []SiteInfoJson `json:"siteinfos"`
}

type SiteInfoJson struct {
	SiteID                  string                 `json:"site_id"`
	SiteName                string                 `json:"site_name"`
	SslNotAfter             time.Time              `json:"ssl_not_after"`
	DomainNum               int                    `json:"domain_num"`
	AccessNum               int64                  `json:"access_num"`
	InterceptionNum         int64                  `json:"interception_num"`
	RealTimeSend            int64                  `json:"real_time_send"`
	RealTimeRecv            int64                  `json:"real_time_recv"`
	RunMode                 int                    `json:"run_mode"`
	IsIpv6                  bool                   `json:"is_ipv6"`
	IsSSL                   bool                   `json:"is_https"`
	Domain                  []string               `json:"domain"`
	DomainPorts             []interface{}          `json:"domain_ports"`
	IpList                  []string               `json:"ip_list"`
	Cdn                     bool                   `json:"cdn"`
	PollingAlgorithm        string                 `json:"polling_algorithm"`
	Cc                      bool                   `json:"cc"`
	RegionalRestrictions    []interface{}          `json:"regional_restrictions"`
	RegionalRestrictionsNum int                    `json:"regional_restrictions_num"`
	Ports                   []int                  `json:"ports"`
	DomainKey               string                 `json:"domain_key"`
	AddTime                 int                    `json:"add_time"`
	HostName                string                 `json:"host"`
	SmartCc                 map[string]interface{} `json:"smart_cc"`
	ForceHttps              bool                   `json:"force_https"`
	WafInfo                 map[string]interface{} `json:"waf_info"`
	UserNginxConfig         string                 `json:"user_nginx_config"`
	SslInfo                 SslInfo                `json:"ssl_info"`
	Upstream                UpstreamJson           `json:"upstream"`
	ProxyInfo               ProxyInfo              `json:"proxy_timeout"`
	Client                  Client                 `json:"client"`
	Overseas                Overseas               `json:"overseas"`
}

type Overseas struct {
	Status   bool   `json:"status"`
	RegionId string `json:"region_id"`
}

type SiteRealTimeInfo struct {
	SiteId          string `json:"site_id"`
	AccessNum       int64  `json:"access_num"`
	InterceptionNum int64  `json:"interception_num"`
	RealTimeSend    int64  `json:"real_time_send"`
	RealTimeRecv    int64  `json:"real_time_recv"`
}

type SslInfo struct {
	NotAfter     time.Time `json:"not_after"`
	Brand        string    `json:"brand"`
	Domains      []string  `json:"Domains"`
	Fullchain    string    `json:"fullchain"`
	Privkey      string    `json:"privkey"`
	SslName      string    `json:"ssl_name"`
	ForceHttps   bool      `json:"force_https"`
	IsHttps      bool      `json:"is_https"`
	SslCiphers   string    `json:"ssl_ciphers"`
	SslProtocols string    `json:"ssl_protocols"`
}

func init() {
	CheckWafConfig()
	CheckWafSiteConfig()
	ClearZipPath()
	MkdirPaths := []string{GlobalVhostPath, SslPath, SiteJsonPath, CertPath, BackupPath, ZipPath, HistoryBackupPath, HistoryBackupConfig, SliceSiteLogJson, NginxJsonPath, NginxStreamPath}
	for _, v := range MkdirPaths {
		if !FileExists(v) {
			os.MkdirAll(v, 0600)
		}
	}
	CheckWebWafConfig()
}

func ClearZipPath() {
	os.RemoveAll(ZipPath)
}

func UpdateWafConfig(types string, timeInt int) {
	HttpPostByToken("http://127.0.0.251/updateinfo?types="+types, timeInt)
}

func GetDomainInfo(siteId string) []interface{} {
	domains := make([]any, 0)
	jsonPath := SiteJsonPath + siteId + ".json"
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil
	}
	var data SiteJson
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return nil
	}

	serverNameLength := len(data.Server.ServerName)

	if serverNameLength < 1 {
		return domains
	}

	ListenTagIdx := len(data.Server.ListenTag) - 1
	portSet := make(map[string]struct{})
	addDomain := make(map[string]string, 0)
	defaultPort := "80"
	if len(data.Server.Listen) == 1 {
		defaultPort = strings.Split(data.Server.Listen[0][0], " ")[0]
	}
	for i := len(data.Server.Listen) - 1; i > -1; i-- {
		if ListenTagIdx > -1 {
			for k, v := range data.Server.ListenTag[ListenTagIdx] {
				if _, ok := portSet[v]; ok {
					continue
				}

				domains = append(domains, map[string]string{
					"domain": k,
					"port":   v,
				})
				addDomain[k] = "1"
				portSet[v] = struct{}{}
			}
			ListenTagIdx--
		}

	}
	for _, vv := range data.Server.ServerName {
		for _, v := range data.Server.Listen {
			vString := strings.Split(v[0], " ")[0]
			if _, ok := portSet[vString]; ok {
				continue
			}
			domains = append(domains, map[string]string{
				"domain": vv,
				"port":   vString,
			})
			addDomain[vv] = "1"
			portSet[vString] = struct{}{}
		}

	}
	for _, vvv := range data.Server.ServerName {
		if _, ok := addDomain[vvv]; !ok {
			domains = append(domains, map[string]string{
				"domain": vvv,
				"port":   defaultPort,
			})
		}

	}

	return domains
}

func CheckSslInfo(fullChain string, privateKey string, isHttps bool) (string, bool) {
	if !isHttps {
		return "", true
	}
	certFile := CertPath + "/test.fullchain.pem"
	keyFile := CertPath + "/test.privkey.pem"
	boolV, _ := WriteFile(certFile, fullChain)
	if !boolV {
		return "", false
	}
	boolV, _ = WriteFile(keyFile, privateKey)
	if !boolV {
		return "", false
	}
	var sslInfo SslInfo
	sslInfo = ReadSslInfo(certFile, keyFile, sslInfo)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)
	if sslInfo.Brand == "" && sslInfo.Domains == nil {
		return "", false
	}
	sslName := ""
	if len(sslInfo.Domains) > 0 {
		sslName = strings.ReplaceAll(sslInfo.Domains[0], "*.", "")
	}

	return sslName, true
}

func ReadSslInfo(certFile string, keyFile string, sslInfo SslInfo) SslInfo {
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

func DelSslInfo(sslName string) error {
	if _, err := os.Stat(SslPath); os.IsNotExist(err) {
		return err
	}
	files, err := os.ReadDir(SslPath)
	if err != nil {
		return err
	}
	var flag = false
	for _, f := range files {
		if f.Name() == sslName {
			flag = true
		}
	}
	if !flag {
		return errors.New("sslName不存在")
	}
	err = os.RemoveAll(SslPath + "/" + sslName)
	if err != nil {
		return err
	}
	return nil
}

func GetAllSslInfo() []SslInfo {
	var sslInfos []SslInfo
	files, _ := os.ReadDir(SslPath)
	for _, f := range files {
		var sslInfo SslInfo
		sslInfo.SslName = f.Name()
		fullFile := SslPath + "/" + f.Name() + "/fullchain.pem"
		privateFile := SslPath + "/" + f.Name() + "/privkey.pem"
		fullStr, err := ReadFile(fullFile)
		if err != nil {
			continue
		}
		privateStr, err := ReadFile(privateFile)
		if err != nil {
			continue
		}
		cert, err := tls.LoadX509KeyPair(SslPath+"/"+f.Name()+"/fullchain.pem", SslPath+"/"+f.Name()+"/privkey.pem")
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

func GetSslInfo(certFile string, keyFile string) SslInfo {
	var sslInfo SslInfo
	fullChain, err := ReadFile(certFile)
	if err != nil {
		return sslInfo
	}
	privateKey, err := ReadFile(keyFile)
	if err != nil {
		return sslInfo
	}
	sslInfo.Fullchain = fullChain
	sslInfo.Privkey = privateKey
	return ReadSslInfo(certFile, keyFile, sslInfo)
}

func GetAllDomain() ([]map[string]string, error) {
	domain := make([]map[string]string, 0)
	query := M("site_info").
		Field([]string{
			"site_id",
			"site_name",
			"create_time"}).
		Order("create_time", "desc")
	res, err := query.Select()

	if err != nil {
		return domain, err
	}

	for _, v := range res {
		domain = append(domain, map[string]string{
			"domain":      v["site_name"].(string),
			"name":        v["site_id"].(string),
			"create_time": InterfaceToString(v["create_time"]),
		})
	}
	sort.Slice(domain, func(i, j int) bool {
		return domain[i]["domain"] < domain[j]["domain"]
	})
	return domain, nil

}

func GetSslInfoBySiteId(siteId string) SslInfo {
	certFile := CertPath + "/" + siteId + "/fullchain.pem"
	keyFile := CertPath + "/" + siteId + "/privkey.pem"
	sslInfo := GetSslInfo(certFile, keyFile)
	data, err := GetSiteJson(siteId)
	if err != nil {
		sslInfo.ForceHttps = false
	}
	sslInfo.ForceHttps = data.ForceHttps
	sslInfo.IsHttps = data.IsSSL
	return sslInfo
}

func GetSiteJson(siteId string) (SiteJson, error) {
	jsonPath := SiteJsonPath + siteId + ".json"
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return SiteJson{}, err
	}
	var data SiteJson
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return SiteJson{}, err
	}
	return data, nil
}

func GetSiteNameBySiteId(siteId string) (string, error) {
	data, err := GetSiteJson(siteId)
	if err != nil {
		return "", err
	}
	return data.SiteName, nil
}

func GetSingleSiteSetting(siteId string) (SiteInfoJson, error) {
	var siteInfo SiteInfoJson
	data, err := GetSiteJson(siteId)
	if err != nil {
		return SiteInfoJson{}, err
	}

	siteInfo.DomainNum = len(strings.Split(data.Server.ServerName[0], " "))
	siteInfo.ForceHttps = data.ForceHttps
	siteInfo.SslInfo.ForceHttps = data.ForceHttps
	siteInfo.SiteName = data.SiteName
	certFile := CertPath + "/" + siteId + "/fullchain.pem"
	keyFile := CertPath + "/" + siteId + "/privkey.pem"
	siteInfo.SslInfo = GetSslInfo(certFile, keyFile)
	if len(data.Server.SSL.SSLCiphers) > 0 {
		siteInfo.SslInfo.SslCiphers = data.Server.SSL.SSLCiphers[0]
	} else {
		siteInfo.SslInfo.SslCiphers = ""
	}
	if len(data.Server.SSL.SSLProtocols) > 0 {
		siteInfo.SslInfo.SslProtocols = data.Server.SSL.SSLProtocols[0]
	} else {
		siteInfo.SslInfo.SslProtocols = ""
	}
	siteInfo.IsSSL = data.IsSSL
	siteInfo.DomainPorts = GetDomainInfo(siteId)
	siteInfo.IpList = data.Server.Upstream.Server
	siteInfo.PollingAlgorithm = data.Server.Upstream.PollingAlgorithm
	siteInfo.UserNginxConfig = GetUserConfigInfo(siteId)
	siteInfo.SiteID = siteId
	siteInfo.HostName = data.Server.Location.HostName
	siteInfo.Upstream, _ = GetReturnSourceInfo(siteId)
	siteInfo.WafInfo, _ = GetRulesBySiteId(siteId)
	siteInfo.IsIpv6 = data.Server.ListenIpv6
	siteInfo.ProxyInfo = data.ProxyInfo
	siteInfo.Client = data.Client
	siteInfo.Upstream.CheckDns.Status = 0
	siteInfo.Upstream.CheckDns.InspectionTime = 0
	res, err := M("site_return_domain_check").Where("site_id=?", siteId).Find()
	if err == nil {
		if res["status"] != nil {
			siteInfo.Upstream.CheckDns.Status = res["status"].(int64)
		}
		if res["inspection_time"] != nil {
			siteInfo.Upstream.CheckDns.InspectionTime = res["inspection_time"].(int64)
		}
	}

	return siteInfo, nil
}

func GetSingleSiteInfo(siteId string, siteInfo SiteInfoJson, searchStr string) (SiteInfoJson, error) {
	data, err := GetSiteJson(siteId)
	if err != nil {
		return SiteInfoJson{}, err
	}

	if len(data.Server.ServerName) > 0 {
		siteInfo.DomainNum = len(strings.Split(data.Server.ServerName[0], " "))
	}

	siteInfo.ForceHttps = data.ForceHttps
	siteInfo.SslInfo.ForceHttps = data.ForceHttps
	siteInfo.SiteName = data.SiteName
	if searchStr != "" && !strings.Contains(data.SiteName, searchStr) {
		return SiteInfoJson{}, errors.New("网站被过滤")

	}
	certFile := CertPath + "/" + siteId + "/fullchain.pem"
	keyFile := CertPath + "/" + siteId + "/privkey.pem"
	sslInfo := GetSslInfo(certFile, keyFile)
	siteInfo.SslNotAfter = sslInfo.NotAfter
	siteInfo.AccessNum = 1000
	siteInfo.InterceptionNum = 100
	siteInfo.RunMode = GetRunMode(siteId)
	siteInfo.IsSSL = data.IsSSL
	siteInfo.Domain = data.Server.ServerName
	siteInfo.IpList = data.Server.Upstream.Server
	siteInfo.Cdn = GetCdnRule(siteId)
	siteInfo.PollingAlgorithm = data.Server.Upstream.PollingAlgorithm
	siteInfo.RegionalRestrictions = GetSpecifySiteRegionRules(siteId)
	siteInfo.RegionalRestrictionsNum = len(siteInfo.RegionalRestrictions)
	siteInfo.Cc = GetCcOpen(siteId)
	siteInfo.HostName = data.Server.Location.HostName
	siteInfo.AddTime = data.AddTime
	siteInfo.DomainKey = siteId
	siteInfo.SiteID = siteId
	siteInfo.Overseas.Status, siteInfo.Overseas.RegionId = GetSpecifySiteRegionOverseasRules(siteId)
	siteInfo.Upstream.CheckDns.Status = 0
	siteInfo.Upstream.CheckDns.InspectionTime = 0
	res, err := M("site_return_domain_check").Where("site_id=?", siteId).Find()
	if err == nil {
		if res["status"] != nil {
			siteInfo.Upstream.CheckDns.Status = res["status"].(int64)
		}
		if res["inspection_time"] != nil {
			siteInfo.Upstream.CheckDns.InspectionTime = res["inspection_time"].(int64)
		}
	}
	Open, err := GetSmartCcOpen(siteId)
	getCcStatus := true
	if err != nil {
		getCcStatus = false
	}
	siteInfo.SmartCc = map[string]interface{}{"open": Open, "status": getCcStatus}

	return siteInfo, nil
}

func SetForceHttps(siteId string, forceHttps bool) error {

	jsonPath := SiteJsonPath + siteId + ".json"
	confPath := VhostPath + siteId + ".conf"
	if !FileExists(jsonPath) {
		return errors.New("配置文件不存在")
	}

	data, err := ReadMapStringInterfaceFile(jsonPath)
	if err != nil {
		return err
	}

	data["force_https"] = forceHttps
	err = BackupFile([]string{jsonPath, confPath}, "", "")
	if err != nil {
		return err
	}
	err = WriteMapStringInterfaceFile(jsonPath, data)
	if err != nil {
		return err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)

	err = ReloadNginx()
	if err != nil {
		RestoreFile([]string{jsonPath, confPath})
		return err
	}
	return nil
}

func GetSiteId() (map[string]string, error) {
	siteId := make(map[string]string, 0)
	jsonData, err := os.ReadFile(SiteIdPath)
	if err != nil {
		return siteId, err
	}
	err = json.Unmarshal(jsonData, &siteId)
	if err != nil {
		return siteId, err
	}
	return siteId, nil
}

func GetSiteIdByDatabase() (map[string]string, error) {
	siteIds := make(map[string]string, 0)
	siteInfo, err := M("site_info").Field([]string{"distinct site_id"}).Select()
	if err != nil {
		return siteIds, err
	}
	if len(siteInfo) > 0 {
		for _, v := range siteInfo {
			siteIds[v["site_id"].(string)] = "1"
		}
	}
	return siteIds, nil
}

/*
 * @brief 取所有网站信息 路由接口
 */
func GetSitesInfo(searchStr string) []interface{} {
	var lines []interface{}
	var siteInfoS SiteInfos
	var siteInfo SiteInfoJson
	siteId, err := GetSiteId()
	if err != nil {
		return lines
	}
	if len(siteId) == 0 {
		return lines
	}

	wg := sync.WaitGroup{}
	for i, _ := range siteId {
		wg.Add(1)
		go func(id string, siteInfo1 SiteInfoJson, siteInfoS1 *SiteInfos) {
			defer func() {
				if err := recover(); err != nil {
					logging.Error(PanicTrace(err))
				}
			}()

			defer wg.Done()
			siteInfo1, err = GetSingleSiteInfo(id, siteInfo1, searchStr)
			if err != nil {
				return
			}
			updateSiteInfoLock.Lock()
			siteInfoS.SiteInfos = append(siteInfoS.SiteInfos, siteInfo1)
			updateSiteInfoLock.Unlock()
		}(i, siteInfo, &siteInfoS)

	}
	wg.Wait()
	sort.Slice(siteInfoS.SiteInfos, func(i, j int) bool {
		return siteInfoS.SiteInfos[i].AddTime > siteInfoS.SiteInfos[j].AddTime
	})
	for i := 0; i < len(siteInfoS.SiteInfos); i++ {
		lines = append(lines, siteInfoS.SiteInfos[i])
	}
	return lines
}

func GetCcOpen(siteId string) bool {
	jsonData, err := ReadInterfaceFileBytes(WafSiteConfigPath)
	if err != nil {
		return false
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		return jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cc"].(map[string]interface{})["open"].(bool)
	}
	return false
}

func GetCdnRule(siteId string) bool {
	jsonData, err := ReadInterfaceFileBytes(WafSiteConfigPath)
	if err != nil {
		return false
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		return jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"].(bool)
	}
	return false
}

func ReadInterfaceFileBytes(filePath string) (interface{}, error) {
	var result interface{}
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

func GetSpecifySiteRegionOverseasRules(siteId string) (bool, string) {
	overseas := false
	jsonData, err := ReadListInterfaceFileBytes(CityConfig)
	if err != nil {
		return overseas, ""
	}
	for _, v := range jsonData {
		switch v.(map[string]interface{})["site"].(type) {
		case string:
			if v.(map[string]interface{})["site"].(string) == siteId {
				if _, ok := v.(map[string]interface{})["status"]; ok {
					overseas = v.(map[string]interface{})["status"].(bool)
				}
				return overseas, v.(map[string]interface{})["region_id"].(string)
			}
		case map[string]interface{}:
			if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})[siteId]; ok {
				if _, ok := v.(map[string]interface{})["status"]; ok {
					overseas = v.(map[string]interface{})["status"].(bool)
				}
				return overseas, v.(map[string]interface{})["region_id"].(string)

			}
		}
	}
	return overseas, ""
}

func GetSpecifySiteRegionRules(siteId string) []interface{} {
	var result []interface{}
	jsonData, err := ReadListInterfaceFileBytes(ProvinceConfig)
	if err != nil {
		return result
	}

	for _, v := range jsonData {
		switch v.(map[string]interface{})["site"].(type) {
		case string:
			if v.(map[string]interface{})["site"].(string) == siteId {
				result = append(result, v)
			} else {
				if v.(map[string]interface{})["site"].(string) == "allsite" {
					result = append(result, v)
				}
			}
		case map[string]interface{}:
			if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})[siteId]; ok {
				result = append(result, v.(map[string]interface{}))
			} else {
				if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})["allsite"]; ok {
					result = append(result, v.(map[string]interface{}))
				}
			}
		}

	}
	jsonDataA, err := ReadListInterfaceFileBytes(CityConfig)
	if err != nil {
		return result
	}

	for _, v := range jsonDataA {
		switch v.(map[string]interface{})["site"].(type) {
		case string:
			if v.(map[string]interface{})["site"].(string) == siteId {
				result = append(result, v)
			} else {
				if v.(map[string]interface{})["site"].(string) == "allsite" {
					result = append(result, v)
				}
			}
		case map[string]interface{}:
			if _, ok := v.(map[string]interface{})["site"].(map[string]interface{}); !ok {
				continue
			}
			if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})[siteId]; ok {

				result = append(result, v.(map[string]interface{}))
			} else {
				if _, ok := v.(map[string]interface{})["site"].(map[string]interface{})["allsite"]; ok {
					result = append(result, v.(map[string]interface{}))
				}
			}
		}
	}

	return result
}

func RemoveDuplicates(slice []int) []int {
	uniqueSet := make(map[int]bool)
	result := make([]int, 0)

	for _, item := range slice {
		uniqueSet[item] = true
	}
	for item := range uniqueSet {
		result = append(result, item)
	}
	return result
}

func BackupFile(FileList []string, dstPath string, isRename string) error {
	if dstPath == "" {
		dstPath = BackupPath
	}
	for _, v := range FileList {
		if !FileExists(v) {
			continue
		}
		ReadStr, err := ReadFile(v)
		fileName := filepath.Base(v)
		if err != nil {
			return err
		}
		writeFile := dstPath + fileName + ".bak"
		switch isRename {
		case "":
			writeFile = dstPath + fileName + ".bak"
		case "src":
			writeFile = dstPath + fileName
		default:
			writeFile = dstPath + fileName + isRename
		}
		if isRename != "" {
			fileName = dstPath + isRename
		}
		boolV, err := WriteFile(writeFile, ReadStr)
		if !boolV {
			return err
		}
	}
	return nil

}

func RemoveFile(FileList []string) error {
	if FileList != nil {
		for _, v := range FileList {
			if !FileExists(v) {
				continue
			}
			os.Remove(v)
		}
	}
	return nil
}

func RemoveBackupFile(FileList []string) error {
	if FileList != nil {
		for _, v := range FileList {

			fileName := filepath.Base(v)
			if !FileExists(BackupPath + fileName + ".bak") {
				continue
			}
			_ = os.Remove(BackupPath + fileName + ".bak")
		}
	}
	return nil
}

func RestoreFile(FileList []string) error {
	if FileList != nil {
		for _, v := range FileList {
			fileName := filepath.Base(v)
			if !FileExists(BackupPath + fileName + ".bak") {
				continue
			}
			_ = os.Rename(BackupPath+fileName+".bak", v)
			os.Remove(BackupPath + fileName + ".bak")
		}
	}
	return nil
}

func AddSiteJson(siteId string, domain []string, ipList []string, siteName string, isHttps bool, fullChain string, privateKey string, cdn bool, pollingAlgorithm string, hostStr string, addPort []string, addMap []map[string]string) error {
	SslName, boolV := CheckSslInfo(fullChain, privateKey, isHttps)
	if !boolV && isHttps {
		return errors.New("添加网站失败，检测到错误的证书或密钥格式，请检查！")
	}
	siteJson := SiteJson{}
	siteJson.AddTime = int(time.Now().Unix())
	siteJson.SiteID = siteId
	err := WriteSiteID(siteId, siteId)
	if err != nil {
		return err
	}

	siteJson.DomainFirstName = siteId
	err = os.MkdirAll("/www/cloud_waf/wwwroot/"+siteId, 0755)
	if err != nil {
		return err
	}
	err = WriteDomain(domain, siteId)
	if err != nil {
		return err
	}

	siteJson.IsSSL = isHttps
	siteJson.SiteName = siteName
	if isHttps {
		if fullChain == "" || privateKey == "" {
			return errors.New("证书内容为空")
		}
		AddCert(privateKey, fullChain, siteId, SslName)
		sslListen := make([]string, 0)
		for _, v := range addPort {
			if len(sslListen) > 0 {
				if v != "443" {
					siteJson.Server.Listen = append(siteJson.Server.Listen, []string{v})
				}
			} else {
				if v == "80" {
					sslListen = append(sslListen, "443 ssl")
				} else {
					sslListen = append(sslListen, v+" ssl")
				}
			}

		}
		if len(sslListen) > 0 {
			addHttpPort := true
			for _, v := range siteJson.Server.Listen {
				if v[0] == "80" {
					addHttpPort = false
				}
			}
			if addHttpPort {
				siteJson.Server.Listen = append(siteJson.Server.Listen, []string{"80"})
			}
			siteJson.Server.Listen = append(siteJson.Server.Listen, sslListen)
		} else {
			siteJson.Server.Listen = [][]string{{"80"}, {"443 ssl"}}
		}

		siteJson = AddSslJson(siteJson, siteId, SslCiphersDefault, SslProtocolsDefault)
	} else {
		for _, v := range addPort {
			siteJson.Server.Listen = append(siteJson.Server.Listen, []string{v})
		}
	}
	siteJson.Server.ListenTag = addMap
	siteJson.Server.ListenIpv6 = true
	siteJson.Server.ServerName = domain
	siteJson.Server.Index = []string{"index.html"}
	siteJson.Server.Root = "/www/wwwroot/" + siteId
	var httpToHttps []string
	httpToHttps = append(httpToHttps, "($server_port !~ 443)")
	httpToHttps = append(httpToHttps, "rewrite \"^(/.*)$\" https://$host$1 permanent")
	siteJson.Server.If = append(siteJson.Server.If, httpToHttps)
	var denyFile []string
	denyFile = append(denyFile, "( $uri ~ \"^/\\.well-known/.*\\.(php|jsp|py|js|css|lua|ts|go|zip|tar\\.gz|rar|7z|sql|bak)$\" )")
	denyFile = append(denyFile, "return 403")
	siteJson.Server.If = append(siteJson.Server.If, denyFile)

	useIncludeFile := UserPath + "/" + siteId + ".conf"
	if !FileExists(useIncludeFile) {
		_, err := os.Create(useIncludeFile)
		if err != nil {
			return err
		}
	}
	siteJson.Server.UserInclude = "include /etc/nginx/user/" + siteId + ".conf;\n"
	siteJson.SourceProtocol = "http://"
	if strings.Split(ipList[0], ":")[0] == "https" {
		siteJson.SourceProtocol = "https://"
	}
	proxyPass := siteJson.SourceProtocol + siteId
	var upstreamJson UpstreamJson
	siteJson.Server.Upstream = AddUpstreamJson(upstreamJson, pollingAlgorithm, ipList, siteId, "2", "600", "1", 1, "")
	siteJson.Server.Gzip.Gzip = [][]string{{"on"}, {"gzip_min_length 1k"}, {"gzip_buffers 4 16k"}, {"gzip_http_version 1.1"}, {"gzip_comp_level 3"}, {"gzip_types text/plain text/css text/xml  application/json application/javascript application/xml+rss application/atom+xml image/svg+xml"}, {"gzip_vary on"}, {"gzip_proxied expired no-cache no-store private auth"}, {"gzip_disable \"MSIE [1-6]\\.\""}}
	siteJson.Server.Gzip.Status = "on"
	siteJson.ProxyInfo = ProxyInfo{}
	siteJson.ProxyInfo.ProxyConnectTimeout = "600"
	siteJson.ProxyInfo.ProxySendTimeout = "600"
	siteJson.ProxyInfo.ProxyReadTimeout = "600"
	siteJson.Client.MaxBodySize = "500m"
	siteJson.Client.BodyBufferSize = "500m"

	siteJson.Server.Location.HostName = hostStr
	locationNot := AddLocationJson("", "/", proxyPass, "1.1", []string{"Host", "Upgrade $http_upgrade", "Connection \"upgrade\"", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, []string{"error timeout invalid_header http_500 http_502 http_503 http_504"}, "off", "", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationNot = append(siteJson.Server.Location.LocationNot, locationNot)
	locationAt := AddLocationJson("@", "static", proxyPass, "", []string{"Host", "X-Real-IP $remote_addr", "X-Forwarded-For $proxy_add_x_forwarded_for"}, nil, "off", "", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationAt = append(siteJson.Server.Location.LocationAt, locationAt)
	LocationRegex := AddLocationJson("~", "\\.*\\.(gif|jpg|jpeg|png|bmp|swf|js|css|woff|woff2)$", "", "", nil, nil, "", "", "", []string{"$uri", "@static"}, "1h", "", "", "")
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationRegex)
	LocationCert := AddLocationJson("~", "^/\\.well-known/", "", "", nil, nil, "", "all", "", nil, "", "", "", "")
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationCert)
	LocationDeny := AddLocationJson("~", "^/(\\.user\\.ini|\\.htaccess|\\.git|\\.env|\\.svn|\\.project)", "", "", nil, nil, "", "", "", nil, "", "", "", "404")
	siteJson.Server.Location.LocationRegex = append(siteJson.Server.Location.LocationRegex, LocationDeny)
	siteJson.Server.Log = AddLogJson(false, false, "access_log", []string{"'$remote_addr - $remote_user [$time_local] '", "'\"$request\" $status $body_bytes_sent '", "'\"$http_referer\" \"$http_user_agent\"'"}, false, "error_log", []string{"'$remote_addr - $remote_user [$time_local] '", "'\"$request\" $status $body_bytes_sent '", "'\"$http_referer\" \"$http_user_agent\"'"}, "local", []string{"/www/wwwlogs/" + siteId + ".log"}, []string{"/www/wwwlogs/" + siteId + ".error.log"}, []string{"syslog", "ip:port", "siteName"}, []string{"syslog", "ip:port", "siteName"})
	writeData, err := json.Marshal(siteJson)
	if err != nil {
		return err
	}
	err = os.WriteFile(SiteJsonPath+siteId+".json", writeData, 0644)
	if err != nil {
		return err
	}
	return nil

}

func CheckDomain(domains []string, appendPort string) (string, bool) {

	allDomain := make(map[string]string, 0)
	siteIds, err := GetSiteId()
	if err != nil {
		return "", true
	}
	checkDomain := make(map[string]string, 0)
	for _, siteId := range siteIds {
		if !FileExists(SiteJsonPath+siteId+".json") || !FileExists(VhostPath+siteId+".conf") {
			continue
		}
		data, err := GetSiteJson(siteId)
		if err != nil {
			continue
		}
		if len(data.Server.ServerName) < 1 {
			continue

		}
		publicPort := make(map[string]string)
		for _, v1 := range data.Server.Listen {
			port := v1[0]
			if strings.Contains(v1[0], " ") {
				port = strings.Split(v1[0], " ")[0]
			}
			publicPort[port] = "1"

		}

		for _, server := range data.Server.ServerName {
			allDomain[server] = "1"
			for key1, _ := range publicPort {
				checkDomain[server+":"+key1] = "1"
			}
		}

	}
	if len(checkDomain) == 0 {
		return "", true
	}

	addPort := make(map[string]string, 0)
	addDomain := make(map[string]string, 0)
	for _, v3 := range domains {
		if strings.HasPrefix(v3, "http://") || strings.HasPrefix(v3, "https://") {
			v3 = ReplaceHttp(v3)
		}
		v3 = strings.ToLower(v3)
		if !strings.Contains(v3, ":") {
			addPort[appendPort] = "1"
			addDomain[v3] = "1"

		} else {
			addPort[strings.Split(v3, ":")[1]] = "1"
			addDomain[strings.Split(v3, ":")[0]] = "1"

		}
	}
	for key, _ := range addDomain {
		for port, _ := range addPort {
			if _, ok := checkDomain[key+":"+port]; ok {
				return key + ":" + port, false
			}
		}

	}

	return "", true

}

func CreateWafConfigJson(siteId string, isCDN bool) error {
	siteConfig, err := Rconfigfile(WafSiteConfigJsonPath)
	if err != nil {
		return err
	}
	siteConfig["cdn"] = isCDN
	siteConfig["cc"].(map[string]interface{})["is_cc_url"] = true
	wafFiles := []string{WafSiteConfigPath, SiteWafConfigJson}
	wafConfig := make(map[string]interface{})
	if FileExists(WafSiteConfigPath) {
		wafConfig, err := Rconfigfile(WafSiteConfigPath)
		if err != nil {
			return err
		}
		GlobalRules, err := GetGlobalConfigRules()
		if err == nil {
			if GlobalRules.(map[string]interface{})["cc"] != nil {
				siteConfig["cc"] = GlobalRules.(map[string]interface{})["cc"]
			}
			if GlobalRules.(map[string]interface{})["number_attacks"] != nil {
				siteConfig["number_attacks"] = GlobalRules.(map[string]interface{})["number_attacks"]
			}
			if GlobalRules.(map[string]interface{})["sql"] != nil {
				siteConfig["sql"] = GlobalRules.(map[string]interface{})["sql"]
			}
			if GlobalRules.(map[string]interface{})["xss"] != nil {
				siteConfig["xss"] = GlobalRules.(map[string]interface{})["xss"]
			}
			if GlobalRules.(map[string]interface{})["ssrf"] != nil {
				siteConfig["ssrf"] = GlobalRules.(map[string]interface{})["ssrf"]
			}
			if GlobalRules.(map[string]interface{})["cookie"] != nil {
				siteConfig["cookie"] = GlobalRules.(map[string]interface{})["cookie"]
			}
			if GlobalRules.(map[string]interface{})["rce"] != nil {
				siteConfig["rce"] = GlobalRules.(map[string]interface{})["rce"]
			}
			if GlobalRules.(map[string]interface{})["file_upload"] != nil {
				siteConfig["file_upload"] = GlobalRules.(map[string]interface{})["file_upload"]
			}
			if GlobalRules.(map[string]interface{})["from_data"] != nil {
				siteConfig["from_data"] = GlobalRules.(map[string]interface{})["from_data"]
			}
			if GlobalRules.(map[string]interface{})["download"] != nil {
				siteConfig["download"] = GlobalRules.(map[string]interface{})["download"]
			}
			if GlobalRules.(map[string]interface{})["file_import"] != nil {
				siteConfig["file_import"] = GlobalRules.(map[string]interface{})["file_import"]
			}
			if GlobalRules.(map[string]interface{})["php_eval"] != nil {
				siteConfig["php_eval"] = GlobalRules.(map[string]interface{})["php_eval"]
			}
			if GlobalRules.(map[string]interface{})["scan"] != nil {
				siteConfig["scan"] = GlobalRules.(map[string]interface{})["scan"]
			}
			if GlobalRules.(map[string]interface{})["user_agent"] != nil {
				siteConfig["user_agent"] = GlobalRules.(map[string]interface{})["user_agent"]
			}

		}
		wafConfig[siteId] = siteConfig

		for _, v := range wafFiles {
			err = Wconfigfile(v, wafConfig)
			if err != nil {
				return err
			}
		}

	} else {
		wafConfig[siteId] = siteConfig
		for _, v := range wafFiles {
			err = Wconfigfile(v, wafConfig)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func CheckSiteDomainJson() error {
	if FileExists(DomainsJsonPath) {
		JsonData, err := ReadListInterfaceFileBytes(DomainsJsonPath)
		if err != nil || JsonData == nil {
			os.RemoveAll(DomainsJsonPath)
			return errors.New("读取DomainsJsonPath文件失败")
		}
	}
	if !FileExists(SiteDomainConfigJson) && FileExists(DomainsJsonPath) {
		writeData, err := ReadFile(DomainsJsonPath)
		if err == nil {
			if writeData == "[]" {
				return nil
			}
			_, err = WriteFile(SiteDomainConfigJson, writeData)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

func WriteDomain(domain []string, siteId string) error {

	domains := make([]interface{}, 0)
	domainMap := map[string]interface{}{"name": siteId, "domains": domain}
	if !FileExists(SiteDomainConfigJson) && FileExists(DomainsJsonPath) {
		oldData, err := ReadListInterfaceFileBytes(DomainsJsonPath)
		if err == nil {
			domains = oldData
		}
	}
	if FileExists(SiteDomainConfigJson) {
		oldData, err := ReadListInterfaceFileBytes(SiteDomainConfigJson)
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
	domaiFiles := []string{SiteDomainConfigJson, DomainsJsonPath}
	for _, v := range domaiFiles {
		err = os.WriteFile(v, writeData, 0644)
		if err != nil {
			return err
		}
	}
	return nil

}

func AddCert(privateKey string, fullChain string, siteId string, sslName string) error {
	siteSslPath := SslPath + "/" + sslName
	SiteSslPrivateKey := siteSslPath + "/privkey.pem"
	SiteSslFullChain := siteSslPath + "/fullchain.pem"
	siteCertPath := CertPath + "/" + siteId
	sitePrivateKey := siteCertPath + "/privkey.pem"
	siteFullChain := siteCertPath + "/fullchain.pem"
	MkdirPathS := []string{siteSslPath, siteCertPath}
	for _, v := range MkdirPathS {
		if !FileExists(v) {
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
		if !FileExists(v) {
			return errors.New(v + "文件不存在")
		}
	}
	return nil
}

func AddSslJson(siteJson SiteJson, siteId string, ssLCiphers string, ssLProtocols []string) SiteJson {
	siteJson.Server.SSL.SSLCertificate = "/etc/nginx/cert/" + siteId + "/fullchain.pem"
	siteJson.Server.SSL.SSLCertificateKey = "/etc/nginx/cert/" + siteId + "/privkey.pem"
	if len(ssLProtocols) == 0 {
		ssLProtocols = SslProtocolsDefault
	}
	siteJson.Server.SSL.SSLProtocols = []string{strings.Join(ssLProtocols, " ")}
	if ssLCiphers == "" {
		ssLCiphers = SslCiphersDefault
	}
	siteJson.Server.SSL.SSLCiphers = []string{ssLCiphers}
	siteJson.Server.SSL.SSLPreferServerCiphers = "on"
	siteJson.Server.SSL.SSLSessionCache = []string{"shared:SSL:10m"}
	siteJson.Server.SSL.SSLSessionTimeout = "10m"
	siteJson.Server.SSL.AddHeader = []string{"Strict-Transport-Security \"max-age=31536000\""}
	siteJson.Server.SSL.ErrorPage = []string{"497  https://$host$request_uri"}
	return siteJson
}

func ModifyUpstreamJson(upstreamJson UpstreamJson, id string, sourceIp string, maxFails string, failTimeout string, weight string, status int, ps string) UpstreamJson {
	isAdd := true
	for i, v := range upstreamJson.ServerNew {
		if v.Id == id {
			v.Ps = ps
			v.Server = sourceIp
			v.MaxFails = maxFails
			v.FailTimeout = failTimeout
			v.Weight = weight
			v.Status = status
			upstreamJson.ServerNew[i] = v
			isAdd = false

		}
	}

	if isAdd {
		if len(upstreamJson.Server) > 0 && len(upstreamJson.ServerNew) < 1 {
			addData := UpstreamSingleInfo{}
			addData.Server = sourceIp
			addData.MaxFails = maxFails
			addData.FailTimeout = failTimeout
			addData.Weight = weight
			addData.Status = status
			addData.Id = RandomStr(20)
			addData.AddTime = int(time.Now().Unix())
			addData.Ps = ps
			upstreamJson.ServerNew = append(upstreamJson.ServerNew, addData)
			upstreamJson.Server = nil

		}
	}
	return upstreamJson
}

func DelUpstreamJson(upstreamJson UpstreamJson, id string) UpstreamJson {
	for i, v := range upstreamJson.ServerNew {
		if v.Id == id {
			upstreamJson.ServerNew = append(upstreamJson.ServerNew[:i], upstreamJson.ServerNew[i+1:]...)
		}
	}
	return upstreamJson
}

func AddUpstreamJson(upstreamJson UpstreamJson, pollingAlgorithm string, ipList []string, siteId string, maxFails string, failTimeout string, weight string, status int, ps string) UpstreamJson {
	addData := UpstreamSingleInfo{}
	for _, v := range ipList {
		v = strings.ToLower(v)
		addData.Server = v
		addData.MaxFails = maxFails
		addData.FailTimeout = failTimeout + "s"
		addData.Weight = weight
		addData.Id = RandomStr(20)
		addData.Status = status
		addData.AddTime = int(time.Now().Unix())
		addData.Ps = ps
		upstreamJson.ServerNew = append(upstreamJson.ServerNew, addData)
	}
	upstreamJson.Name = siteId
	upstreamJson.PollingAlgorithm = pollingAlgorithm
	return upstreamJson
}

func AddLocationJson(matchPriority string, matchArguments string, proxyPass string, proxyHttpVersion string, proxySetHeader []string, proxyNextUpstream []string, proxyCache string, allow string, deny string, tryFiles []string, expires string, accessLog string, errorLog string, Return string) []map[string]interface{} {
	var location []map[string]interface{}
	location = append(location, map[string]interface{}{"match_priority": matchPriority})
	location = append(location, map[string]interface{}{"match_arguments": matchArguments})
	location = append(location, map[string]interface{}{"proxy_pass": proxyPass})
	location = append(location, map[string]interface{}{"proxy_set_header": proxySetHeader})
	location = append(location, map[string]interface{}{"proxy_next_upstream": proxyNextUpstream})
	location = append(location, map[string]interface{}{"proxy_cache": proxyCache})
	location = append(location, map[string]interface{}{"allow": allow})
	location = append(location, map[string]interface{}{"deny": deny})
	location = append(location, map[string]interface{}{"try_files": tryFiles})
	location = append(location, map[string]interface{}{"expires": expires})
	location = append(location, map[string]interface{}{"access_log": accessLog})
	location = append(location, map[string]interface{}{"error_log": errorLog})
	location = append(location, map[string]interface{}{"return": Return})
	return location
}

func AddLogJson(formatMode bool, formatAccessStatus bool, formatAccessNname string, formatAccess []string, formatErrorStatus bool, formatErrorName string, formatError []string, logMode string, localAccess []string, localError []string, remoteAccess []string, remoteError []string) LogG {
	var log LogG
	log.LogSetting.FormatMode = false //是否启用自定义日志格式
	log.Format.AccessLog.Status = formatAccessStatus
	log.Format.AccessLog.Name = formatAccessNname
	log.Format.AccessLog.Format = formatAccess
	log.Format.ErrorLog.Status = formatErrorStatus
	log.Format.ErrorLog.Name = formatErrorName
	log.Format.ErrorLog.Format = formatError
	log.LogSetting.Mode = logMode
	log.LogSetting.Local.AccessLog = localAccess
	log.LogSetting.Local.ErrorLog = localError
	log.LogSetting.Remote.AccessLog = remoteAccess
	log.LogSetting.Remote.ErrorLog = remoteError
	return log
}

func WriteSiteID(siteId string, DomainFirstName string) error {
	siteIdMap := make(map[string]string, 0)
	siteOldIdMap, err := GetSiteId()
	if err == nil {
		siteIdMap = siteOldIdMap
	}
	siteIdMap[siteId] = DomainFirstName
	siteIdJson, err := json.Marshal(siteIdMap)
	if err != nil {
		return err
	}

	err = os.WriteFile(SiteIdPath, siteIdJson, 0644)
	if err != nil {
		return err
	}
	return nil
}

func AddNignxJsonToConf(siteId string, upsteamConf string) {
	jsonPath := SiteJsonPath + siteId + ".json"
	confPath := VhostPath + siteId + ".conf"
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return
	}
	var jsonMap SiteJson
	err = json.Unmarshal(jsonData, &jsonMap)
	if err != nil {
		return
	}
	var conf string
	conf = "server {\n"
	listenMap := make(map[string]string, 0)
	for _, v := range jsonMap.Server.Listen {
		if _, ok := listenMap[v[0]]; ok {
			continue
		}
		defaultServer := " default_server"
		if siteId != "default_wildcard_domain_server" {
			defaultServer = ""
		}
		conf = conf + "\tlisten " + v[0] + defaultServer + ";\n"
		if jsonMap.Server.ListenIpv6 {
			conf = conf + "\tlisten [::]:" + v[0] + defaultServer + ";\n"

		}
		listenMap[v[0]] = "1"
	}
	conf = conf + "\tserver_name " + siteId + " " + strings.Join(jsonMap.Server.ServerName, " ") + ";\n"
	conf = conf + "\tindex " + strings.Join(jsonMap.Server.Index, " ") + ";\n"
	conf = conf + "\troot " + jsonMap.Server.Root + ";\n\n"
	if jsonMap.ForceHttps {
		conf = ParseIfJson(conf, jsonMap.Server.If, "https")
	}
	conf = ParseSSLJson(conf, jsonMap.Server.SSL, jsonMap.IsSSL)
	conf = conf + "\t" + jsonMap.Server.UserInclude + "\n"
	conf = conf + "\terror_page 502 /502.html;\n\tlocation = /502.html {\n\t\troot /etc/nginx/waf/html;\n\t}\n\n"
	for idx, item := range jsonMap.Server.Gzip.Gzip {
		if idx == 0 {
			conf = conf + "\tgzip " + strings.Join(item, " ") + ";\n"
		} else {
			conf = conf + "\t" + strings.Join(item, " ") + ";\n"
		}

	}
	hostFixed := "\n\tset $host_optimize $http_host;\n\tif ($http_host = \"\") {\n\t\tset $host_optimize \"default\";\n\t}\n"

	conf = conf + hostFixed
	HostStr := jsonMap.Server.Location.HostName
	for _, item := range jsonMap.Server.Location.LocationNot {
		conf = ParseLocationJson(HostStr, conf, item, jsonMap.ProxyInfo, jsonMap.Client)
	}
	emptyProxyInfo := ProxyInfo{}
	for _, item := range jsonMap.Server.Location.LocationAt {
		conf = ParseLocationJson(HostStr, conf, item, emptyProxyInfo, jsonMap.Client)
	}
	for i, item := range jsonMap.Server.Location.LocationRegex {
		conf = ParseLocationJson(HostStr, conf, item, emptyProxyInfo, jsonMap.Client)
		if i == 1 {
			conf = ParseIfJson(conf, jsonMap.Server.If, "apply_ssl")
		}
	}
	for _, item := range jsonMap.Server.Location.LocationTilde {
		conf = ParseLocationJson(HostStr, conf, item, emptyProxyInfo, jsonMap.Client)
	}

	for _, item := range jsonMap.Server.Location.LocationStar {
		conf = ParseLocationJson(HostStr, conf, item, emptyProxyInfo, jsonMap.Client)
	}
	logFormatAccess := ""
	if GetCdnRule(siteId) {
		logFormatAccess = " access_log"
	}
	conf = conf + "\n\taccess_log " + strings.Join(jsonMap.Server.Log.LogSetting.Local.AccessLog, " ") + logFormatAccess + ";\n"
	conf = conf + "\terror_log " + strings.Join(jsonMap.Server.Log.LogSetting.Local.ErrorLog, " ") + ";\n"
	conf = conf + "}\n"

	if upsteamConf != "" {
		conf = upsteamConf + conf
	}

	err = os.WriteFile(confPath, []byte(conf), 0644)
	if err != nil {
		return
	}
}

func ParseSSLJson(conf string, jsonMap SSLConfig, isHttps bool) string {
	if isHttps {
		conf = conf + "\tssl_certificate " + jsonMap.SSLCertificate + ";\n"
		conf = conf + "\tssl_certificate_key " + jsonMap.SSLCertificateKey + ";\n"
		conf = conf + "\tssl_protocols " + strings.Join(jsonMap.SSLProtocols, " ") + ";\n"
		conf = conf + "\tssl_ciphers " + strings.Join(jsonMap.SSLCiphers, " ") + ";\n"
		conf = conf + "\tssl_prefer_server_ciphers " + jsonMap.SSLPreferServerCiphers + ";\n"
		conf = conf + "\tssl_session_cache " + strings.Join(jsonMap.SSLSessionCache, " ") + ";\n"
		conf = conf + "\tssl_session_timeout " + jsonMap.SSLSessionTimeout + ";\n"
		conf = conf + "\tadd_header " + strings.Join(jsonMap.AddHeader, " ") + ";\n"
		conf = conf + "\terror_page " + strings.Join(jsonMap.ErrorPage, " ") + ";\n\n"
	}
	return conf
}

func ParseIfJson(conf string, ifContent [][]string, types string) string {
	for _, item := range ifContent {
		isContinue := false
		for idx, item2 := range item {
			if idx == 0 && !strings.Contains(item2, "$server_port") && types == "https" {
				isContinue = true
				continue
			}
			if idx == 0 && !strings.Contains(item2, "well-known") && types == "apply_ssl" {
				isContinue = true
				continue
			}
			if isContinue {
				continue
			}
			switch idx {
			case 0:
				conf = conf + "\n\tif " + item2 + " {\n"
			default:
				conf = conf + "\t\t" + item2 + ";\n"
			}

		}
		if !isContinue {
			conf = conf + "\t}\n\n"
		}
	}
	return conf
}

func ParseLocationJson(HostStr string, conf string, item []map[string]interface{}, proxyInfo ProxyInfo, clientInfo Client) string {
	emptyString := true
	locationConf := ""
	isClear := false
	for _, item2 := range item {
		for k, item3 := range item2 {
			if item3 == nil || item3 == "" && k != "match_priority" && k != "return" {
				continue
			}
			switch k {
			case "match_priority":
				locationConf = locationConf + "\n\tlocation " + item3.(string)
				if item3.(string) == "@" {
					emptyString = false
				}
			case "match_arguments":
				if item3.(string) == "^/\\.well-known/" {
					isClear = true
				}
				if emptyString {
					locationConf = locationConf + " " + item3.(string) + " {\n"
				} else {
					locationConf = locationConf + item3.(string) + " {\n"
				}
			case "proxy_pass":

				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "proxy_set_header":
				for _, item4 := range item3.([]interface{}) {
					if item4.(string) == "Host" {
						locationConf = locationConf + "\t\t" + k + " " + item4.(string) + " " + HostStr + ";\n"
					} else {
						locationConf = locationConf + "\t\t" + k + " " + item4.(string) + ";\n"
					}

				}
			case "proxy_cache":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
				if proxyInfo.ProxySendTimeout != "" && proxyInfo.ProxyReadTimeout != "" && proxyInfo.ProxyConnectTimeout != "" {
					locationConf = locationConf + "\t\tproxy_connect_timeout " + proxyInfo.ProxyConnectTimeout + ";\n"
					locationConf = locationConf + "\t\tproxy_send_timeout " + proxyInfo.ProxySendTimeout + ";\n"
					locationConf = locationConf + "\t\tproxy_read_timeout " + proxyInfo.ProxyReadTimeout + ";\n"
					locationConf = locationConf + "\t\tclient_max_body_size " + clientInfo.MaxBodySize + ";\n"
				}
			case "allow":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "deny":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "try_files":
				for idx, item4 := range item3.([]interface{}) {
					switch idx {
					case 0:
						locationConf = locationConf + "\t\t" + k + " " + item4.(string)
					case len(item3.([]interface{})) - 1:
						locationConf = locationConf + " " + item4.(string) + ";\n"
					default:
						locationConf = locationConf + " " + item4.(string)
					}

				}
			case "expires":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "access_log":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "error_log":
				locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n"
			case "return":
				if item3.(string) == "" {
					locationConf = locationConf + "\n\t}\n"
				} else {
					locationConf = locationConf + "\t\t" + k + " " + item3.(string) + ";\n\t}\n"
				}
			}
		}
	}
	if isClear {
		locationConf = ""
	}
	return conf + locationConf
}

func ParseUpstreamConf(siteId string) (string, error) {
	config, err := os.ReadFile(SiteJsonPath + siteId + ".json")
	if err != nil {
		return "", err
	}
	var jsonData SiteJson
	err = json.Unmarshal([]byte(config), &jsonData)
	if err != nil {
		return "", err
	}
	upstream := jsonData.Server.Upstream
	var UpstreamConf string
	UpstreamConf = "upstream " + siteId + " {\n"
	if upstream.PollingAlgorithm != "round_robin" && upstream.PollingAlgorithm != "sticky" {
		UpstreamConf = UpstreamConf + "\t" + upstream.PollingAlgorithm + ";\n"
	}
	if upstream.PollingAlgorithm == "sticky" {
		UpstreamConf = UpstreamConf + "\tsticky name=bt_waf_route expires=12h httponly secure;\n"
	}
	addData := ""
	if len(upstream.Server) > 0 {
		domainName := strings.ReplaceAll(upstream.Server[0], "https://", "")
		domainName = strings.ReplaceAll(domainName, "http://", "")
		if !strings.Contains(domainName, ":") && strings.Contains(upstream.Server[0], "https://") {
			domainName = domainName + ":443"
		}
		UpstreamConf = UpstreamConf + "\tserver " + domainName + "  max_fails=2 fail_timeout=600s weight=1;\n"
	}
	if len(upstream.ServerNew) > 0 {
		for _, item := range upstream.ServerNew {
			if item.Status < 1 {
				continue
			}
			addData = " max_fails=" + item.MaxFails + " fail_timeout=" + strings.ReplaceAll(item.FailTimeout, "s", "") + "s"
			if upstream.PollingAlgorithm == "round_robin" {
				addData = addData + " weight=" + item.Weight
			}
			if item.Status == 2 {
				addData = addData + " backup"
			}
			sourceItem := item.Server
			domainName := strings.TrimSpace(item.Server)
			domainName = strings.ReplaceAll(domainName, "https://", "")
			domainName = strings.ReplaceAll(domainName, "http://", "")
			if !strings.Contains(domainName, ":") && strings.Contains(sourceItem, "https://") {
				domainName = domainName + ":443"
			}
			UpstreamConf = UpstreamConf + "\tserver " + domainName + addData + ";\n"
		}
	}
	UpstreamConf = UpstreamConf + "}\n"
	return UpstreamConf, nil
}
func AddNginxUpstreamConf(siteIdStr string) (string, error) {
	jsonData, err := os.ReadFile(SiteIdPath)
	if err != nil {
		return "", err
	}
	var siteId map[string]string
	err = json.Unmarshal([]byte(jsonData), &siteId)
	if err != nil {
		return "", err
	}
	upstreamConfS := ""
	for id, _ := range siteId {
		if siteIdStr != id {
			continue
		}
		upstreamConf, err := ParseUpstreamConf(id)
		if err == nil {
			upstreamConfS += upstreamConf
		}
	}

	return upstreamConfS, err

}

func DeleteSiteId(siteId string) error {
	var siteIdMap map[string]string
	readByte, err := os.ReadFile(SiteIdPath)
	if err == nil {
		err = json.Unmarshal([]byte(readByte), &siteIdMap)
		if err != nil {
			return err
		}
	}
	_, ok := siteIdMap[siteId]
	if !ok {
		return nil
	} else {
		delete(siteIdMap, siteId)
	}
	siteIdJson, err := json.Marshal(siteIdMap)
	if err != nil {
		return err
	}
	err = os.WriteFile(SiteIdPath, siteIdJson, 0644)
	if err != nil {
		return err
	}
	return nil
}

func GetRunMode(siteId string) int {
	jsonData, err := ReadFile(WafSiteConfigPath)
	if err != nil {
		return 0
	}
	var data interface{}
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return 0
	}
	if data.(map[string]interface{})[siteId] == nil {
		return 0
	}
	runMode := data.(map[string]interface{})[siteId].(map[string]interface{})["mode"]
	return InterfaceToInt(runMode)

}

func ModifySiteName(siteId string, siteName string) error {
	jsonPath := SiteJsonPath + siteId + ".json"
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}

	var data SiteJson
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		return err
	}
	data.SiteName = siteName
	jsonStr, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return err
	}
	defer os.Remove(BackupPath + siteId + ".json.bak")
	boolV, err := WriteFile(jsonPath, string(jsonStr))
	if !boolV {
		err = RestoreFile([]string{jsonPath})
		if err != nil {
			return err
		}
		return errors.New("写入json配置文件失败")
	}
	return nil
}

func DownloadSsl(siteId string) (core.Response, error) {
	err := compress.Zip(ZipPath+siteId+".zip", CertPath+"/"+siteId)
	if err != nil {
		return nil, err
	}
	response, err := core.DownloadFile(ZipPath+siteId+".zip", siteId+".zip")
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DelDomain(domain []string, siteId string) error {
	jsonPath := SiteJsonPath + siteId + ".json"
	jsonConf := VhostPath + siteId + ".conf"
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	var data SiteJson
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return err
	}
	for i := 0; i < len(domain); i++ {
		if len(data.Server.ServerName) == 1 && len(data.Server.Listen) > 1 {
			if !strings.Contains(domain[i], ":") {
				return errors.New("删除失败，网站只有一个域名，且监听端口大于1时，域名必须带端口")
			} else {
				for k, v := range data.Server.Listen {
					if strings.Split(v[0], ":")[0] == strings.Split(domain[i], ":")[1] {
						data.Server.Listen = append(data.Server.Listen[:k], data.Server.Listen[k+1:]...)
					}
				}
				for k, v := range data.Server.ListenTag {
					for key, value := range v {
						if value == strings.Split(domain[i], ":")[1] && key == strings.Split(domain[i], ":")[0] {
							if len(data.Server.ListenTag) > 1 {
								data.Server.ListenTag = append(data.Server.ListenTag[:k], data.Server.ListenTag[k+1:]...)
							} else {
								data.Server.ListenTag = make([]map[string]string, 0)
							}

						}
					}
				}
			}
		}
		if len(data.Server.ServerName) > 1 {
			for k, v := range data.Server.ListenTag {
				for key, value := range v {
					if value == strings.Split(domain[i], ":")[1] && key == strings.Split(domain[i], ":")[0] {
						if len(data.Server.ListenTag) > 1 {
							data.Server.ListenTag = append(data.Server.ListenTag[:k], data.Server.ListenTag[k+1:]...)
						} else {
							data.Server.ListenTag = make([]map[string]string, 0)
						}
					}
				}
			}
			delServerName := true
			delPort := true
			for _, v := range data.Server.ListenTag {
				for key, value := range v {
					if key == strings.Split(domain[i], ":")[0] {
						delServerName = false
					}
					if value == strings.Split(domain[i], ":")[1] {
						delPort = false
					}

				}
			}
			if delServerName {
				for j := 0; j < len(data.Server.ServerName); j++ {
					if strings.Split(domain[i], ":")[0] == data.Server.ServerName[j] {
						data.Server.ServerName = append(data.Server.ServerName[:j], data.Server.ServerName[j+1:]...)
					}
				}
			}
			if delPort {
				for kk, vv := range data.Server.Listen {
					if strings.Split(vv[0], ":")[0] == strings.Split(domain[i], ":")[1] {
						data.Server.Listen = append(data.Server.Listen[:kk], data.Server.Listen[kk+1:]...)
					}
				}

			}
		}
	}
	err = BackupFile([]string{jsonPath, DomainConfig, jsonConf}, "", "")
	if err != nil {
		return err
	}
	err = WriteDomain(data.Server.ServerName, siteId)
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, DomainConfig, jsonConf})
		defer RestoreFile([]string{jsonPath, DomainConfig, jsonConf})
		return err
	}
	jsonStr, err := json.Marshal(data)
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, DomainConfig, jsonConf})
		defer RestoreFile([]string{jsonPath, DomainConfig, jsonConf})
		return err
	}
	boolV, err := WriteFile(jsonPath, string(jsonStr))
	if !boolV {
		defer RemoveBackupFile([]string{jsonPath, DomainConfig, jsonConf})
		defer RestoreFile([]string{jsonPath, DomainConfig, jsonConf})
		return errors.New("写入json配置文件失败")
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, DomainConfig, jsonConf})
		defer RestoreFile([]string{jsonPath, DomainConfig, jsonConf})
		return err
	}
	return nil

}

func ModifyUserConfigInfo(siteId string, content string) error {
	userIncludeFile := UserPath + "/" + siteId + ".conf"
	err := BackupFile([]string{userIncludeFile}, "", "")
	if err != nil {
		return err
	}
	boolV, _ := WriteFile(userIncludeFile, content)
	if !boolV {
		return errors.New("写入user_include文件失败")
	}
	err = ReloadNginx()
	if err != nil {
		return err
	}
	return nil
}

func GetTcpLoadBalanceListenPortAndProtocol() []map[string]string {
	result := make([]map[string]string, 0)
	if !FileExists(NginxJsonPath + "/nginx.json") {
		return result
	}
	loadBalanceContent, err := ReadMapStringInterfaceFile(NginxJsonPath + "/nginx.json")
	if err != nil {
		return result
	}

	for _, v := range loadBalanceContent["tcp_load_balance"].(map[string]interface{}) {
		if v.(map[string]interface{})["listen_port"] != nil && v.(map[string]interface{})["protocol"] != nil && v.(map[string]interface{})["protocol"].(string) != "udp" {
			listenPort := v.(map[string]interface{})["listen_port"].(string)
			protocol := v.(map[string]interface{})["protocol"].(string)
			result = append(result, map[string]string{"listen_port": listenPort, "protocol": protocol})

		}

	}
	return result
}

func ReloadNginx() error {
	_, stdErr, err := ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-t")
	if err != nil {
		return err
	}
	if stdErr != "" && !strings.Contains(stdErr, "test is successful") {
		return errors.New(stdErr)
	}
	_, steErr, err := ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-s", "reload")
	if err != nil {
		return err
	}

	if steErr != "" {
		ExecNginxCommand("docker", "exec", "cloudwaf_nginx", "nginx", "-s", "reload")
		return errors.New(steErr)
	}
	return nil
}

func GetUserConfigInfo(siteId string) string {
	userIncludeFile := UserPath + "/" + siteId + ".conf"
	userInclude, err := ReadFile(userIncludeFile)
	if err != nil {
		return ""
	}
	return userInclude
}

func GetSiteLogInfo(siteId string, types string) string {
	if types != "error" && types != "access" && types != "slow" {
		types = "access"
	}
	logPath := LogRootPath + siteId + ".log"
	if types == "error" {
		logPath = LogRootPath + siteId + ".error.log"
	}
	logStr, err := Tail(logPath, 1000)
	if err != nil {
		return ""
	}
	return logStr

}

func ClearSiteLog(siteId string, types string) (bool, error) {
	if types != "error" && types != "access" && types != "slow" {
		types = "access"
	}
	logPath := LogRootPath + siteId + ".log"
	if types == "error" {
		logPath = LogRootPath + siteId + ".error.log"
	}
	ok, err := WriteFile(logPath, "")
	if err != nil {
		return false, err
	}
	return ok, nil

}

func AddDomain(domain []string, siteId string) error {
	_, addPort, _, err := CheckDomainIp(domain, false)
	if err != nil && err.Error() != "3" {
		switch err.Error() {
		case "0":
			return errors.New("端口不正确,端口范围为1-65535")
		case "1", "2":
			return errors.New("域名地址不正确" + ErrIpWithNotHttp)
		}
		return err
	}

	tcpPortMap := GetTcpAllPorts()
	for _, portSting := range addPort {
		if _, ok := tcpPortMap[portSting]; ok {
			return errors.New(portSting + "端口已经被占用！请更换端口")
		}
	}
	rDomain, boolV := CheckDomain(domain, "80")
	if !boolV {
		return errors.New(" 此域名已经在配置文件中监听该端口，请勿重复添加！</br>" + rDomain)
	}

	jsonPath := SiteJsonPath + siteId + ".json"
	jsonConf := VhostPath + siteId + ".conf"

	data, err := GetSiteJson(siteId)
	if err != nil {
		return err
	}
	addedDomain, addDomain, checkDomainPorts, inCurrent := DomainIsAdd(domain, "80", siteId)
	if len(addedDomain) > 0 {
		if inCurrent {
			if len(addDomain) > 1 {
				return errors.New("暂不支持此添加方式！你可以用此域名创建一个新的网站！")
			}
			if len(data.Server.ServerName) > 1 {
				return errors.New("暂不支持此添加方式！你可以用此域名创建一个新的网站！")
			}

		} else {
			for k, v := range checkDomainPorts {
				if len(v) > 1 {
					return errors.New(k + "暂不支持此添加方式！你可以用此域名创建一个新的网站！")
				}
			}
		}
	} else {
		for k, v := range checkDomainPorts {
			if len(v) > 1 {
				return errors.New(k + "暂不支持此添加方式！你可以用此域名创建一个新的网站！")
			}
		}
		if len(data.Server.ServerName) == 1 && len(data.Server.Listen) > 1 {
			return errors.New("暂不支持此添加方式！你可以用此域名创建一个新的网站！")
		}
	}

	serverNameSet := make(map[string]struct{})
	for _, v := range data.Server.ServerName {
		serverNameSet[v] = struct{}{}
	}
	for i := 0; i < len(domain); i++ {
		sName := ""
		if domain[i] == "" {
			continue
		}
		domain[i] = ReplaceHttp(domain[i])
		domain[i] = strings.ToLower(domain[i])
		if strings.Contains(domain[i], ":") {
			domainSplit := strings.Split(domain[i], ":")
			port := domainSplit[1]
			addPort := true
			for _, item := range data.Server.Listen {
				if item[0] == port {
					addPort = false
				}
			}
			if port != "" {
				if addPort {
					data.Server.Listen = append(data.Server.Listen, []string{port})
				}
				data.Server.ListenTag = append(data.Server.ListenTag, map[string]string{domainSplit[0]: domainSplit[1]})
			}
			sName = domainSplit[0]
		} else {
			data.Server.ListenTag = append(data.Server.ListenTag, map[string]string{domain[i]: "80"})
			sName = domain[i]
		}
		sName = strings.ToLower(sName)
		if _, ok := serverNameSet[sName]; !ok {
			data.Server.ServerName = append(data.Server.ServerName, sName)
		}
	}
	err = BackupFile([]string{jsonPath, jsonConf, DomainConfig}, "", "")
	if err != nil {
		return err
	}
	err = WriteDomain(data.Server.ServerName, siteId)
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, jsonConf, DomainConfig})
		defer RestoreFile([]string{jsonPath, jsonConf, DomainConfig})
		return err
	}
	jsonStr, err := json.Marshal(data)
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, jsonConf, DomainConfig})
		defer RestoreFile([]string{jsonPath, jsonConf, DomainConfig})
		return err
	}
	err = BackupFile([]string{jsonPath}, "", "")
	boolV, err = WriteFile(jsonPath, string(jsonStr))
	if !boolV {
		defer RemoveBackupFile([]string{jsonPath, jsonConf, DomainConfig})
		defer RestoreFile([]string{jsonPath, jsonConf, DomainConfig})
		return errors.New("写入json配置文件失败")
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		defer RemoveBackupFile([]string{jsonPath, jsonConf, DomainConfig})
		defer RestoreFile([]string{jsonPath, jsonConf, DomainConfig})
		return err
	}
	return nil

}

func SetCdn(siteId string, cdn bool) error {
	jsonData, err := ReadInterfaceFileBytes(WafSiteConfigPath)
	if err != nil {
		return err
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		jsonData.(map[string]interface{})[siteId].(map[string]interface{})["cdn"] = cdn
	}
	err = BackupFile([]string{WafSiteConfigPath}, "", "")
	if err != nil {
		return err
	}
	jsonString, err := json.Marshal(jsonData)
	if err != nil {
		err = RemoveBackupFile([]string{WafSiteConfigPath})
		if err != nil {
			return err
		}
		return err
	}
	boolV, err := WriteFile(WafSiteConfigPath, string(jsonString))
	if !boolV {
		err = RestoreFile([]string{WafSiteConfigPath})
		if err != nil {
			return err
		}
		err = RemoveBackupFile([]string{WafSiteConfigPath})
		if err != nil {
			return err
		}
		return err
	}
	return nil
}

func RestoreSite(siteId string) error {

	jsonPath := SiteJsonPath + siteId + ".json"
	jsonBackupPath := BackupPath + siteId + ".json.bak"
	defer func() {
		if FileExists(jsonBackupPath) {
			os.Remove(jsonBackupPath)
		}
	}()
	if FileExists(jsonBackupPath) {
		err := os.Rename(jsonBackupPath, jsonPath)
		if err != nil {
			return err
		}
		if FileExists(jsonPath) {
			upsteamConf, _ := AddNginxUpstreamConf(siteId)
			AddNignxJsonToConf(siteId, upsteamConf)
			err = ReloadNginx()
			if err != nil {
				return err
			}
			return nil
		}
	}
	return errors.New("站点恢复失败")
}

func IsStringValid(input string) bool {
	pattern := `^\d+(\.\d+){3}$`
	matched, err := regexp.MatchString(pattern, input)
	if err != nil {
		return false
	}
	return matched
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

func CheckIp(ip string) bool {
	ip = ReplaceHttp(ip)
	if net.ParseIP(ip) == nil {
		return false
	}
	return true
}

func SetSingleLocationProxyPass(proxyPass string, item [][]map[string]interface{}) ([][]map[string]interface{}, error) {
	for _, item1 := range item {
		for _, item2 := range item1 {
			for k, _ := range item2 {
				if k == "proxy_pass" {
					item2[k] = proxyPass
				}
			}
		}
	}
	return item, nil
}

func SetLocationProxyPass(jsonMap SiteJson, proxyPass string) (SiteJson, error) {
	item, err := SetSingleLocationProxyPass(proxyPass, jsonMap.Server.Location.LocationNot)
	if err != nil {
		jsonMap.Server.Location.LocationNot = item
	}
	item, err = SetSingleLocationProxyPass(proxyPass, jsonMap.Server.Location.LocationAt)
	if err != nil {
		jsonMap.Server.Location.LocationNot = item
	}
	return jsonMap, nil
}

func GetReturnSourceInfo(siteId string) (UpstreamJson, error) {
	upstreamInfo := UpstreamJson{}
	upstreamInfo.EnableNote = 0
	jsonData, err := GetSiteJson(siteId)
	if err != nil {
		return upstreamInfo, err
	}
	upstreamInfo.PollingAlgorithm = jsonData.Server.Upstream.PollingAlgorithm
	upstreamInfo.Host = jsonData.Server.Location.HostName
	upstreamInfo.Name = jsonData.Server.Upstream.Name
	if jsonData.Server.Upstream.ServerNew != nil {
		upstreamInfo.ServerNew = jsonData.Server.Upstream.ServerNew
	}
	if jsonData.Server.Upstream.Server != nil {
		addData := UpstreamSingleInfo{}
		addData.Server = jsonData.Server.Upstream.Server[0]
		addData.AddTime = jsonData.AddTime
		addData.FailTimeout = "600s"
		addData.Id = RandomStr(20)
		addData.MaxFails = "2"
		addData.Status = 1
		addData.Weight = "1"
		addData.Ps = ""
		upstreamInfo.ServerNew = append(upstreamInfo.ServerNew, addData)
		jsonStr, err := json.Marshal(jsonData)
		if err != nil {
			logging.Debug("GetReturnSourceInfo json转换失败：", err)
		}
		err = BackupFile([]string{SiteJsonPath + siteId + ".json"}, "", "")
		boolV, err := WriteFile(SiteJsonPath+siteId+".json", string(jsonStr))
		if !boolV {
			err = RestoreFile([]string{SiteJsonPath + siteId + ".json"})
			if err != nil {
				logging.Debug("恢复"+siteId+"配置文件失败：", err)
			}
		}
	}
	for _, item := range upstreamInfo.ServerNew {
		if item.Status == 1 {
			upstreamInfo.EnableNote++
		}
	}
	return upstreamInfo, nil

}

func DelReturnSourceIp(siteId string, id string) error {
	jsonPath := SiteJsonPath + siteId + ".json"
	data, err := GetSiteJson(siteId)
	if err != nil {
		return err
	}
	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return err
	}
	notCurentNoteHttps := make(map[string]string, 0)
	for _, item := range data.Server.Upstream.ServerNew {
		if item.Status == 1 {
			if strings.Contains(item.Server, "https://") {
				if id != item.Id {
					notCurentNoteHttps["https"] = "1"
				}
			} else {
				if id != item.Id {
					notCurentNoteHttps["http"] = "1"
				}
			}
		}
	}
	if len(notCurentNoteHttps) == 1 {
		for k, _ := range notCurentNoteHttps {
			proxyHeader := k + "://" + siteId
			tmpData, err := SetLocationProxyPass(data, proxyHeader)
			if err != nil {
				data = tmpData
			}
		}

	}
	data.Server.Upstream = DelUpstreamJson(data.Server.Upstream, id)
	writeJson, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		return err
	}
	return nil
}

func ModifyReturnSourceIp(siteId string, id string, pollingAlgorithm string, sourceIp string, hostStr string, maxFails string, failTimeout string, weight string, status int, oldStatus int, ps string) error {
	jsonPath := SiteJsonPath + siteId + ".json"
	data, err := GetSiteJson(siteId)
	if err != nil {
		return err
	}
	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return err
	}
	enableNote := 0
	totalNode := 0
	noteHttps := make(map[string]string, 0)
	notCurentNoteHttps := make(map[string]string, 0)
	curenthttps := "https://"
	for _, item := range data.Server.Upstream.ServerNew {
		if item.Status == 1 {
			enableNote++
			if strings.Contains(item.Server, "https://") {
				noteHttps["https"] = "1"
				if id != item.Id {
					notCurentNoteHttps["https"] = "1"
				}
			} else {
				noteHttps["http"] = "1"
				if id != item.Id {
					notCurentNoteHttps["http"] = "1"
				}
			}
			if id == item.Id && strings.Contains(item.Server, "http://") {
				curenthttps = "http://"
			}
		}
		totalNode++
	}
	if data.Server.Upstream.Server != nil {
		enableNote++
	}
	if enableNote <= 1 && status == 0 && oldStatus != status {
		return errors.New("至少启用一个节点")
	}
	proxyHeader := "http://" + siteId
	isModifyProxyHeader := false
	if len(data.Server.Upstream.ServerNew) == 1 {
		isModifyProxyHeader = true
		if strings.Contains(sourceIp, "https://") {
			proxyHeader = "https://" + siteId
		}
	}
	if enableNote == 2 && status == 0 {
		if len(noteHttps) == 2 {
			if curenthttps == "http://" {
				proxyHeader = "https://" + siteId
			}
		} else {
			proxyHeader = curenthttps + siteId
		}
		isModifyProxyHeader = true

	}

	if (status == 0 && len(notCurentNoteHttps) == 1) || (len(noteHttps) == 2 && status == 1 && len(notCurentNoteHttps) == 1) {
		for k, _ := range notCurentNoteHttps {
			proxyHeader = k + "://" + siteId
		}
		isModifyProxyHeader = true
	}
	if isModifyProxyHeader {
		tmpData, err := SetLocationProxyPass(data, proxyHeader)
		if err != nil {
			data = tmpData
		}
	}
	data.Server.Upstream = ModifyUpstreamJson(data.Server.Upstream, id, sourceIp, maxFails, failTimeout, weight, status, ps)
	writeJson, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		return err
	}

	return nil
}

func AddReturnSourceIp(siteId string, pollingAlgorithm string, sourceIp string, HostStr string, maxFails string, failTimeout string, weight string, status int, ps string) (bool, error) {
	ipList := []string{sourceIp}
	_, _, _, err := CheckDomainIp(ipList, false)
	if err != nil {
		switch err.Error() {
		case "0":
			return true, errors.New("端口不正确,端口范围为1-65535")
		case "1", "2":
			return true, errors.New("源站地址不正确" + ErrIpWithHttp)
		case "4":
			return true, errors.New("源站地址检测到不支持的域名后缀！支持的域名后缀如下(包括中英文后缀)：</br>" + strings.Join(DomainList, " "))

		}
	}
	jsonPath := SiteJsonPath + siteId + ".json"
	data, err := GetSiteJson(siteId)
	if err != nil {
		return false, err
	}
	for _, item := range data.Server.Upstream.ServerNew {
		item.Server = ReplaceHttp(item.Server)
		item.Server = strings.ToLower(item.Server)
		for _, ip := range ipList {
			ip = ReplaceHttp(ip)
			ip = strings.ToLower(ip)
			if item.Server == ip {
				return true, errors.New("此节点已经添加过，请勿重复添加！")
			}
		}
	}
	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return false, err
	}
	data.Server.Upstream = AddUpstreamJson(data.Server.Upstream, pollingAlgorithm, ipList, siteId, maxFails, failTimeout, weight, status, ps)
	data.Server.Upstream.PollingAlgorithm = pollingAlgorithm
	data.Server.Location.HostName = HostStr
	writeJson, err := json.Marshal(data)
	if err != nil {
		return true, err
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return true, err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		return true, err
	}
	return false, nil

}

func SetReturnSource(siteId string, pollingAlgorithm string, HostStr string) (bool, error) {
	jsonPath := SiteJsonPath + siteId + ".json"
	data, err := GetSiteJson(siteId)
	if err != nil {
		return false, err
	}

	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return false, err
	}

	data.Server.Upstream.Host = HostStr
	proxyHeader := "http://" + siteId
	proxyHeader = data.SourceProtocol + siteId
	data.Server.Upstream.PollingAlgorithm = pollingAlgorithm
	data.Server.Location.HostName = HostStr
	tmpData, err := SetLocationProxyPass(data, proxyHeader)
	if err != nil {
		data = tmpData
	}
	writeJson, err := json.Marshal(data)
	if err != nil {
		return true, err
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return true, err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		return true, err
	}
	return false, nil
}

/* 编辑网站 路由接口*/
func ModifySiteJson(siteId string, domain []string, ipList []string, siteName string, isHttps bool, fullChain string, privateKey string, cdn bool, pollingAlgorithm string, sslName string) (bool, error) {

	data, err := GetSiteJson(siteId)
	if err != nil {
		return false, err
	}
	rDomain, boolV := CheckDomain(domain, "443")
	sslPort := ""
	if !boolV && !data.IsSSL {
		for index, v := range data.Server.Listen {
			if v == nil {
				continue
			}
			splitV := strings.Split(v[0], " ")[0]
			if splitV != "443" && splitV != "80" {
				if len(data.Server.Listen) == 1 {
					data.Server.Listen = make([][]string, 0)
				} else {
					data.Server.Listen = append(data.Server.Listen[:index], data.Server.Listen[index+1:]...)
				}
				sslPort = splitV
				break
			}
		}
		if sslPort == "" {
			return false, errors.New(" 此域名已经在配置文件中监听443端口并且未指定其他端口，无法开启证书！</br>" + rDomain)
		}
	}

	jsonPath := SiteJsonPath + siteId + ".json"
	data.SiteName = siteName
	if isHttps {
		data.IsSSL = isHttps
	}
	data.IsCDN = cdn
	addPort := true
	if len(data.Server.ListenTag) > 0 {
		addPort = false
	}
	if isHttps {
		if fullChain == "" || privateKey == "" {
			return false, err
		}
		err := AddCert(privateKey, fullChain, siteId, sslName)
		if err != nil {
			return false, err
		}
		is_add_ssl := true
		for _, item := range data.Server.Listen {
			if strings.Contains(item[0], "ssl") {
				is_add_ssl = false
			}
		}
		if sslPort == "" {
			sslPort = "443"
		}
		if is_add_ssl {
			data.Server.Listen = append(data.Server.Listen, []string{sslPort + " ssl"})
		}
		data = AddSslJson(data, siteId, SslCiphersDefault, SslProtocolsDefault)
	} else {
		if addPort {
			data.Server.Listen = append(data.Server.Listen, []string{"80"})
		}
	}
	data.Server.ServerName = domain
	data.Server.Upstream.PollingAlgorithm = pollingAlgorithm
	data.Server.Upstream.Server = ipList
	err = BackupFile([]string{jsonPath}, "", "")
	if err != nil {
		return false, err
	}
	writeJson, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	err = os.WriteFile(jsonPath, writeJson, 0644)
	if err != nil {
		return true, err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		return true, err
	}
	return false, nil
}

func DelSiteAuth(siteId string) error {
	_, err := MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		err := DelSpecificSiteAllAuthInfo(db, siteId)
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

func DelSiteIdDomainFile(siteId string) error {
	domainFile := DomainConfig
	if FileExists(SiteDomainConfigJson) {
		domainFile = SiteDomainConfigJson
	}
	jsonData, err := ReadListInterfaceFileBytes(domainFile)
	if err != nil {
		return err
	}
	for i, v := range jsonData {
		if v.(map[string]interface{})["name"].(string) == siteId {
			jsonData = append(jsonData[:i], jsonData[i+1:]...)

		}
	}
	domainFiles := []string{SiteDomainConfigJson, DomainConfig}
	for _, v := range domainFiles {
		err = WriteListInterfaceFile(v, jsonData)
		if err != nil {
			continue
		}
	}
	return nil
}

func DeleteSite(siteId string) error {
	siteIds, err := GetSiteId()
	if err != nil {
		return err
	}
	if len(siteIds) == 0 {
		return errors.New("没有网站")
	}
	err = DelSiteAuth(siteId)
	if err != nil {
		return err
	}
	err = DeleteSiteId(siteId)
	if err != nil {
		return err
	}

	siteIdJson := SiteJsonPath + siteId + ".json"
	rootPath := "/www/cloud_waf/wwwroot/" + siteId
	includeUserPath := "/www/cloud_waf/nginx/conf.d/user/" + siteId + ".conf"
	siteIdConf := VhostPath + siteId + ".conf"
	certPath := CertPath + "/" + siteId
	accessLog := LogRootPath + siteId + ".log"
	errorLog := LogRootPath + siteId + ".error.log"
	removeFileList := []string{siteIdJson, siteIdConf, certPath, accessLog, errorLog, rootPath, includeUserPath}
	for _, file := range removeFileList {
		if !FileExists(file) {
			continue
		}
		fi, err := os.Stat(file)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			err := os.RemoveAll(file)
			if err != nil {
				continue
			}
		} else {
			err := os.Remove(file)
			if err != nil {
				continue
			}
		}
	}
	DelSiteIdDomainFile(siteId)
	jsonStr, err := ReadFileBytes(WafSiteConfigPath)
	if err != nil {
		return err
	}
	var jsonData interface{}
	if err = json.Unmarshal(jsonStr, &jsonData); err != nil {
		return err
	}
	if _, ok := jsonData.(map[string]interface{})[siteId]; ok {
		delete(jsonData.(map[string]interface{}), siteId)
	}
	jsonStr, err = json.Marshal(jsonData)
	if err != nil {
		return err
	}
	boolV, err := WriteFile(WafSiteConfigPath, string(jsonStr))
	if !boolV {
		return err
	}
	delSiteId := []string{siteId}
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
	err = ReloadNginx()
	if err != nil {
		return err
	}
	return nil
}

func DeployCert(siteId string, sslName string) (bool, error) {
	SslPath := SslPath + sslName
	CheckFile := []string{SslPath, SslPath + "/fullchain.pem", SslPath + "/privkey.pem"}
	for _, v := range CheckFile {
		if !FileExists(v) {
			return false, errors.New(v + "不存在")
		}
	}
	fullString, err := ReadFile(SslPath + "/fullchain.pem")
	if err != nil {
		return false, err
	}
	privateString, err := ReadFile(SslPath + "/privkey.pem")
	if err != nil {
		return false, err

	}
	boolV, err := InstallCert(privateString, fullString, siteId)
	if err != nil {
		return boolV, err
	}
	return false, nil

}

/*外部调用方法，用以安装证书，安装证书后会自动重载nginx，无需手动重载nginx*/
func InstallCert(privateKey string, fullChain string, siteId string) (bool, error) {
	SslName, boolV := CheckSslInfo(fullChain, privateKey, true)
	if !boolV {
		return false, errors.New("启用失败，检测到错误的证书或密钥格式，请检查！")
	}
	data, err := GetSiteJson(siteId)
	if err != nil {
		return false, err
	}
	domain := data.Server.ServerName
	ipList := data.Server.Upstream.Server
	siteName := data.SiteName
	cdn := data.IsCDN
	pollingAlgorithm := data.Server.Upstream.PollingAlgorithm
	boolV, err = ModifySiteJson(siteId, domain, ipList, siteName, true, fullChain, privateKey, cdn, pollingAlgorithm, SslName)
	if err != nil {
		return boolV, err
	}
	return false, nil
}

func GetTcpAllPorts() map[string]string {
	result := make(map[string]string, 0)
	loadBalanceContent, err := ReadMapStringInterfaceFile(NginxJsonPath + "/nginx.json")
	if err != nil {
		return result
	}
	if _, ok := loadBalanceContent["tcp_load_balance"]; ok {
		for _, v := range loadBalanceContent["tcp_load_balance"].(map[string]interface{}) {
			if v.(map[string]interface{})["listen_port"] != nil {
				listenPort := v.(map[string]interface{})["listen_port"].(string)
				result[listenPort] = "1"
			}
		}

	}
	return result
}

func DelAddSiteInfo(siteId string) {
	os.RemoveAll(SiteRootPath + siteId)
	os.RemoveAll(CertPath + "/" + siteId)
	os.RemoveAll(SiteJsonPath + siteId + ".json")
	os.RemoveAll(VhostPath + siteId + ".conf")
	os.RemoveAll(UserPath + "/" + siteId + ".conf")
	os.RemoveAll(DomainConfig)
	os.RemoveAll(SiteIdPath)
	DeleteSiteId(siteId)
	DelSiteIdDomainFile(siteId)
	RestoreFile([]string{DomainConfig, SiteIdPath})

}

func CheckDomainIp(domain []string, isHttps bool) ([]string, []string, []map[string]string, error) {
	var err error
	addDomain := []string{}
	addDomainMap := make(map[string]string)
	addPort := []string{}
	addPortMap := make(map[string]string, 0)
	addMapList := make([]map[string]string, 0)
	ErrorList := make([]string, 0)
	for _, ip := range domain {
		ip = strings.ToLower(ip)
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
				ErrorList = append(ErrorList, "1")
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

func DomainIsAdd(domains []string, appendPort string, currentSiteId string) (map[string]string, map[string]string, map[string]map[string]string, bool) {
	allDomain := make(map[string]string, 0)
	addDomain := make(map[string]string, 0)
	addedDomain := make(map[string]string, 0)
	checkDomainPorts := make(map[string]map[string]string, 0)
	currentSiteServerName := make([]string, 0)
	inCurrent := false
	siteIds, err := GetSiteId()
	if err != nil {
		return addedDomain, addDomain, checkDomainPorts, inCurrent
	}

	for _, siteId := range siteIds {

		if !FileExists(SiteJsonPath+siteId+".json") || !FileExists(VhostPath+siteId+".conf") {
			continue
		}
		data, err := GetSiteJson(siteId)
		if err != nil {
			continue
		}
		if len(data.Server.ServerName) < 1 {
			continue

		}
		if currentSiteId == siteId {
			currentSiteServerName = data.Server.ServerName
		}
		for _, server := range data.Server.ServerName {
			allDomain[server] = "1"
		}
	}
	for _, v := range domains {
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			v = ReplaceHttp(v)
		}
		v = strings.ToLower(v)
		if !strings.Contains(v, ":") {
			addDomain[v] = "1"
			if _, ok := allDomain[v]; ok {
				addedDomain[v] = "1"
				if _, ok := checkDomainPorts[v]; !ok {
					checkDomainPorts[v] = map[string]string{appendPort: "1"}
				} else {
					checkDomainPorts[v][appendPort] = "1"
				}
			}
		} else {
			domain := strings.Split(v, ":")[0]
			addDomain[domain] = "1"
			if _, ok := checkDomainPorts[domain]; !ok {
				checkDomainPorts[strings.Split(v, ":")[0]] = map[string]string{strings.Split(v, ":")[1]: "1"}
			} else {
				checkDomainPorts[strings.Split(v, ":")[0]][strings.Split(v, ":")[1]] = "1"
			}

			if _, ok := allDomain[domain]; ok {
				addedDomain[domain] = "1"
			}
		}
	}
	for _, v := range currentSiteServerName {
		if _, ok := addedDomain[v]; ok {
			inCurrent = true
		}
	}
	return addedDomain, addDomain, checkDomainPorts, inCurrent

}

func AddSite(domain []string, ipList []string, siteName string, isHttps bool, fullChain string, privateKey string, cdn bool, pollingAlgorithm string, hostStr string) error {
	wildcardDomain := false
	if len(domain) == 1 {
		domain[0] = ReplaceHttp(domain[0])
		domain[0] = strings.TrimSpace(domain[0])
		if domain[0] == "" {
			return errors.New("域名不能为空")
		}
		if domain[0] == "*" || domain[0] == "*.*" {
			wildcardDomain = true
		}
	}
	if wildcardDomain {
		siteIds, err := GetSiteId()
		if err != nil {
			return err
		}
		for _, siteId := range siteIds {
			if !FileExists(SiteJsonPath+siteId+".json") || !FileExists(VhostPath+siteId+".conf") {
				continue
			}
			if siteId == "default_wildcard_domain_server" {
				return errors.New("通配所有域名网站已经添加过")
			}
		}
	}
	addDomain, addPort, addMap, err := CheckDomainIp(domain, isHttps)
	if !wildcardDomain && err != nil && err.Error() != "3" {
		switch err.Error() {
		case "0":
			return errors.New("防护域名端口不正确,端口范围为1-65535")
		case "1", "2":
			return errors.New("防护域名地址不正确" + ErrIpWithNotHttp)
		case "4":
			return errors.New("防护域名检测到不支持的域名后缀！支持的域名后缀如下(包括中英文后缀)：</br>" + strings.Join(DomainList, " "))

		}
		return err
	}
	if !wildcardDomain {
		tcpPortMap := GetTcpAllPorts()
		for _, portSting := range addPort {
			if _, ok := tcpPortMap[portSting]; ok {
				return errors.New(portSting + "端口已经被占用！请更换端口")
			}
		}
	}
	appendPort := "80"
	if isHttps {
		appendPort = "443"
	}
	if !wildcardDomain {
		rDomain, boolV := CheckDomain(domain, appendPort)
		if !boolV {
			return errors.New("此域名已经在配置文件中监听该端口，请勿重复添加！</br>" + rDomain)
		}
		_, addDomains, checkDomainPorts, _ := DomainIsAdd(domain, appendPort, "")
		if len(addDomains) > 1 {
			for _, v := range checkDomainPorts {
				if len(v) > 1 {
					return errors.New("暂不支持此添加方式！你可以用此域名创建一个新的网站！")
				}
			}
		}
	}
	_, _, _, err = CheckDomainIp(ipList, isHttps)
	if err != nil && err.Error() != "3" {
		switch err.Error() {
		case "0":
			return errors.New("源站端口不正确,端口范围为1-65535")
		case "1", "2":
			return errors.New("源站地址不正确" + ErrIpWithHttp)
		case "4":
			return errors.New("源站地址检测到不支持的域名后缀！支持的域名后缀如下(包括中英文后缀)：</br>" + strings.Join(DomainList, " "))
		}
		return err
	}
	if hostStr == "" || hostStr == "$host" {
		hostStr = "$host_optimize"
	}
	err = BackupFile([]string{DomainConfig, SiteIdPath}, "", "")
	if err != nil {
		return err
	}
	siteId := "default_wildcard_domain_server"
	if !wildcardDomain {
		siteId = strings.ReplaceAll(domain[0], `*.`, "__")
		siteId = strings.ReplaceAll(siteId, ".", "_")
		siteId = strings.ReplaceAll(siteId, "https://", "")
		siteId = strings.ReplaceAll(siteId, "http://", "")
		siteId = strings.ReplaceAll(siteId, "：", "_")
		siteId = strings.ReplaceAll(siteId, ":", "_")
		siteId = strings.ToLower(siteId)
	} else {
		addDomain = []string{"_"}
		addPort = []string{"_"}
		siteName = "通配所有域名"
		addPort = []string{appendPort}
	}
	err = AddSiteJson(siteId, addDomain, ipList, siteName, isHttps, fullChain, privateKey, cdn, pollingAlgorithm, hostStr, addPort, addMap)
	if err != nil {
		DelAddSiteInfo(siteId)
		return err
	}
	err = CreateWafConfigJson(siteId, cdn)
	if err != nil {
		DelAddSiteInfo(siteId)
		return err
	}
	err = SetCdn(siteId, cdn)
	if err != nil {
		DelAddSiteInfo(siteId)
		return err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		DelAddSiteInfo(siteId)
		return err
	}
	return nil
}

func RemoveSiteSslInfo(siteId string) error {
	err := BackupFile([]string{SiteJsonPath + siteId + ".json", VhostPath + siteId + ".conf"}, "", "")
	if err != nil {
		return err
	}
	data, err := GetSiteJson(siteId)
	if err != nil {
		return err
	}

	if err != nil {
		defer RestoreFile([]string{SiteJsonPath + siteId + ".json", VhostPath + siteId + ".conf"})
		return err
	}
	data.IsSSL = false
	data.ForceHttps = false
	delInt := make([]int, 0)
	for i, v := range data.Server.Listen {
		if strings.Contains(v[0], "ssl") {
			if len(data.Server.Listen) == 1 {
				addPort := "80"
				currentPort := strings.Split(v[0], " ")[0]
				if currentPort != "" && currentPort != "443" {
					addPort = currentPort
				}
				data.Server.Listen = make([][]string, 0)
				data.Server.Listen = append(data.Server.Listen, []string{addPort})
			} else {
				delInt = append(delInt, i)
			}

		}
	}
	if len(delInt) > 0 {
		sort.Slice(delInt, func(i, j int) bool {
			return delInt[i] > delInt[j]
		})
		for _, v := range delInt {
			data.Server.Listen = append(data.Server.Listen[:v], data.Server.Listen[v+1:]...)

		}
	}
	jsonStr, err := json.Marshal(data)
	if err != nil {
		defer RestoreFile([]string{SiteJsonPath + siteId + ".json", VhostPath + siteId + ".conf"})
		return err
	}
	boolV, err := WriteFile(SiteJsonPath+siteId+".json", string(jsonStr))
	if !boolV {
		return errors.New("写入json配置文件失败")
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		defer RestoreFile([]string{SiteJsonPath + siteId + ".json", VhostPath + siteId + ".conf"})
		return err
	}
	return nil
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
	return ConvertByte2String(stdoutBuf.Bytes(), "GB18030"), ConvertByte2String(stderrBuf.Bytes(), "GB18030"), nil
}

func dayRange() (string, int) {
	currentTime := time.Now()
	startDate := currentTime.Format("2006-01-02")
	startHour := currentTime.Hour()
	return startDate, startHour
}

func GetDataWithDatabase(res interface{}, startDate string, siteId string, result map[string]int64) (map[string]int64, error) {
	_, err := MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		queryRequest := conn.NewQuery()
		queryRequest.Table("request_total").
			Where("date = ?", []any{startDate}).
			Where("server_name = ?", []any{siteId}).
			Field([]string{
				"ifnull(SUM(request), 0) as `request_total`",
			})
		result1, err := queryRequest.Find()

		if err != nil {
			return nil, err
		}
		resT1 := struct {
			RequestTotal int64 `json:"request_total"`
		}{}
		result["request"] = resT1.RequestTotal

		res2, err := conn.NewQuery().
			Table("request_total").
			Where("server_name = ?", []any{siteId}).
			Field([]string{"sec_send_bytes", "sec_receive_bytes"}).
			Order("id", "desc").
			Limit([]int64{1}).
			Find()

		if err != nil {
			return nil, err
		}

		resT2 := struct {
			SecSendBytes int64 `json:"sec_send_bytes"`
			SecRecvBytes int64 `json:"sec_receive_bytes"`
		}{}

		if err := MapToStruct(res2, &resT2); err != nil {
			return nil, err
		}
		result["send"] = resT2.SecSendBytes
		result["recv"] = resT2.SecRecvBytes
		return result1, err
	})

	if err != nil {
		return nil, err
	}
	return result, err
}

func GetSingleSiteAccess(siteId string) map[string]int64 {
	result := map[string]int64{
		"request":   0,
		"intercept": 0,
		"send":      0,
		"recv":      0,
	}
	startDate, _ := dayRange()
	res, err := HttpPostByToken(URL_HTTP_REQUEST+"/get_site_status?server_name="+siteId, 3)
	if err != nil {
		result, err = GetDataWithDatabase(res, startDate, siteId, result)
		if err != nil {
			return result
		}
	}

	jsonData := struct {
		Msg struct {
			Today struct {
				Req int64 `json:"req"`
			}
			SendBytes int64 `json:"send_bytes"`
			RecvBytes int64 `json:"recv_bytes"`
		} `json:"msg"`
		Status bool `json:"status"`
	}{}

	err = json.Unmarshal([]byte(res), &jsonData)
	if err != nil || jsonData.Status == false {
		result, err = GetDataWithDatabase(res, startDate, siteId, result)
		if err != nil {
			return result
		}
	} else {
		result["request"] = jsonData.Msg.Today.Req
		result["send"] = jsonData.Msg.SendBytes
		result["recv"] = jsonData.Msg.RecvBytes
	}
	resA, err := MySqlWithClose(func(conn *db.MySql) (interface{}, error) {
		cacheKey := "IP_INTERCEPT__" + siteId

		if cache.Has(cacheKey) {
			return cache.Get(cacheKey), nil
		}
		query := conn.NewQuery()
		query.Table("ip_intercept").
			Where("server_name = ?", []any{siteId}).
			Where("date > ?", []any{time.Unix(ZeroTimestamp()-1, 0).Format("2006-01-02")}).
			Field([]string{
				"sum(request) as intercept",
			})

		result23, err := query.Find()
		if err != nil {
			return nil, err
		}
		cache.Set(cacheKey, result23, 10)
		return result23, err
	})

	resT := struct {
		Intercept int64 `json:"intercept"`
	}{}
	if err = MapToStruct(resA, &resT); err != nil {
		return nil
	}
	if err != nil {
		return nil
	}
	result["intercept"] = resT.Intercept
	return result

}

func ReplaceDate(nowStr string) string {
	nowStr = strings.Replace(nowStr, " ", "_", -1)
	nowStr = strings.Replace(nowStr, ":", "", -1)
	return nowStr
}

func ReadSliceLog() string {
	readStr, err := ReadFile(SliceSiteLogPath)
	if err != nil {
		return ""
	}
	return readStr
}

func SliceSiteLog() {
	WriteFile(SliceSiteLogPath, "\n\n\n"+ReadSliceLog()+"\n"+GetNowTimeStr()+"开始切割网站日志...")
	siteIdS := make(map[string]string, 0)
	err := error(nil)
	if clusterCommon.ClusterState() != clusterCommon.CLUSTER_LOWER {
		siteIdS, err = GetSiteIdByDatabase()
		if err != nil {
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"读取网站列表失败:"+"\n退出日志切割任务"+err.Error())
			return
		}
	} else {
		jsonData, err := os.ReadFile(types.SiteIdPath)
		if err != nil {
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"读取文件失败:"+types.SiteIdPath+"\n退出日志切割任务"+err.Error())
			return
		}
		err = json.Unmarshal(jsonData, &siteIdS)
		if err != nil {
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"反序列化数据失败:"+types.SiteIdPath+"\n退出日志切割任务"+err.Error())
			return
		}
	}

	for id, _ := range siteIdS {
		isAddJson := false
		siteslicejson := SliceSiteLogJson + id + ".json"
		data := make([]map[string]string, 0)
		if FileExists(siteslicejson) {
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
		nowStr := ReplaceDate(GetNowTimeStr())
		backupPath := HistoryBackupPath + "logs/" + id + "/"
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
			if !FileExists(backupPath) {
				err := os.MkdirAll(v, 0755)
				if err != nil {
					WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 创建目录失败:"+filepath.Dir(v)+"\n"+err.Error())
					continue
				}
			}
		}
		backupLogFile := []string{LogRootPath + id + ".log", LogRootPath + id + ".error.log", LogRootPath + id + ".slow.log"}
		for _, v := range backupLogFile {
			logPaths := []string{backupPathAccess, backupPathError, backupPathSlow}
			for _, v1 := range logPaths {
				if !FileExists(v1) {
					err := os.MkdirAll(v1, 0755)
					if err != nil {
						WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 创建目录失败:"+filepath.Dir(v)+"\n"+err.Error())
						continue
					}
				}
			}
			zipName := backupFileAccess
			if FileExists(v) {
				switch {
				case strings.HasSuffix(v, ".error.log"):
					zipName = backupFileError
				case strings.HasSuffix(v, ".slow.log"):
					zipName = backupFileSlow
				}
				logLock.Lock()
				err := compress.Zip(zipName+".zip", v)
				if err != nil {
					WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 压缩日志文件失败:"+v+"\n"+err.Error())
				}
				if FileExists(zipName + ".zip") {
					err = os.Truncate(v, 0)

					if err != nil {
						os.Remove(v)
						boolV, err := WriteFile(v, "")
						if !boolV {
							WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"清理过期日志文件失败:"+err.Error())
						}
						WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"清理过期日志文件成功:"+v)
					}
					isAddJson = true
					WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 压缩日志文件成功:"+v+"\n压缩后文件名为："+zipName+".zip")
				} else {
					WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 压缩日志文件失败:"+v)
				}
				logLock.Unlock()

			} else {
				WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 日志文件不存在:"+v+",跳过此日志文件日志切割")
			}

		}
		err = ReloadNginx()
		if err != nil {
			ReloadNginx()
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+" 重载nginx失败:"+err.Error())
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
					if FileExists(v1) {
						err = os.Remove(v1)
						if err != nil {
							WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"清理过期日志文件失败:"+err.Error())
							continue
						}
						WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"清理过期日志文件成功:"+v1)
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
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"转换json失败:"+err.Error())
			continue
		}
		boolV, err := WriteFile(siteslicejson, string(jsonStr))
		if !boolV {
			WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"写入json配置文件失败:"+err.Error())
			continue
		}

	}
	WriteFile(SliceSiteLogPath, ReadSliceLog()+"\n"+GetNowTimeStr()+"切割网站日志任务已执行\n")
}

func GetSslCiphers() []string {
	return []string{"EECDH+AESGC", "EECDH+AES256+SHA384", "EECDH+AES256+SHA", "EECDH+AES128+SHA256", "EECDH+AES128+SHA", "AES256+SHA256", "AES256+SHA", "AES128+SHA", "DES-CBC3-SHA", "EECDH+CHACHA20", "EECDH+CHACHA20-draft", "EECDH+AES128", "RSA+AES128", "EECDH+AES256", "RSA+AES256", "EECDH+3DES", "RSA+3DES", "!MD5"}
}

func GetCurrentSslCiphers(siteId string) string {
	defaultSslCiphers := "EECDH+AESGC:EECDH+AES256+SHA384:EECDH+AES256+SHA:EECDH+AES128+SHA256:EECDH+AES128+SHA:AES256+SHA256:AES256+SHA:AES128+SHA:DES-CBC3-SHA:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5"
	data, err := GetSiteJson(siteId)
	if err != nil {
		return defaultSslCiphers
	}
	if len(data.Server.SSL.SSLCiphers) > 0 {
		return data.Server.SSL.SSLCiphers[0]
	}
	return defaultSslCiphers
}

func GetSslProtocols() []string {
	return []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
}

func GetCurrentSslProtocols(siteId string) string {
	data, err := GetSiteJson(siteId)
	if err != nil {
		return "TLSv1, TLSv1.1, TLSv1.2, TLSv1.3"
	}
	if len(data.Server.SSL.SSLProtocols) > 0 {
		return data.Server.SSL.SSLProtocols[0]
	}
	return "TLSv1, TLSv1.1, TLSv1.2, TLSv1.3"
}

func SetSslSecureConfig(siteId string, sslCiphers string, sslProtocols []string) error {

	if siteId == "" {
		return errors.New("网站ID不能为空")
	}
	if len(sslCiphers) == 0 || len(sslProtocols) == 0 {
		return errors.New("sslCiphers或sslProtocols不能为空")
	}
	data, err := GetSiteJson(siteId)
	if err != nil {
		return err
	}
	data = AddSslJson(data, siteId, sslCiphers, sslProtocols)
	writeData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonPath := SiteJsonPath + siteId + ".json"
	confPath := VhostPath + siteId + ".conf"
	err = BackupFile([]string{jsonPath, confPath}, "", "")
	if err != nil {
		return err
	}
	err = os.WriteFile(SiteJsonPath+siteId+".json", writeData, 0644)
	if err != nil {
		return err
	}
	upsteamConf, _ := AddNginxUpstreamConf(siteId)
	AddNignxJsonToConf(siteId, upsteamConf)
	err = ReloadNginx()
	if err != nil {
		RestoreFile([]string{jsonPath, confPath})
		ReloadNginx()
		return err
	}
	return nil
}

func GetAddDomainInfo(domain []string) AddDomainInfo {
	addDomainInfo := AddDomainInfo{}
	addDomainInfo.Status = true
	addDomainInfo.SourceIpList.IntranetIpList = []string{"192.168.10.26", "192.168.10.27"}
	addDomainInfo.SourceIpList.ExtranetIpList = []string{"42.65.54.64", "98.65.23.12"}
	addDomainInfo.IsHttps = true
	addDomainInfo.IsCdn = true
	return addDomainInfo

}

func AddTcpJsonToTcpUpstream(tcpLoadBalanceInfo map[string]types.SingleTcpLoadBalance) string {
	tcpUpstremConf := ""
	for k, v := range tcpLoadBalanceInfo {
		tcpUpstremConf += "upstream " + k + " {\n"
		for _, v1 := range v.NodeAddressMap {
			tcpUpstremConf += "\tserver " + v1.NodeAddress + ":" + v1.NodePort + " weight=" + v1.Weight + " max_fails=" + v1.MaxFails + " fail_timeout=" + v1.FailTimeout + "s;\n"
		}
		tcpUpstremConf += "}\n"
	}
	return tcpUpstremConf

}

func AddTcpJsonToTcpServer(tcpLoadBalanceInfo map[string]types.SingleTcpLoadBalance) string {
	tcpServerConf := ""
	for k, v := range tcpLoadBalanceInfo {
		tcpServerConf += "server {\n"
		switch v.Protocol {
		case "tcp":
			tcpServerConf += "\tlisten " + v.ListenAddress + ":" + v.ListenPort + ";\n"
		case "udp":
			tcpServerConf += "\tlisten " + v.ListenAddress + ":" + v.ListenPort + " udp;\n"
		case "tcp/udp":
			tcpServerConf += "\tlisten " + v.ListenAddress + ":" + v.ListenPort + ";\n"
			tcpServerConf += "\tlisten " + v.ListenAddress + ":" + v.ListenPort + " udp;\n"
		}
		tcpServerConf += "\tproxy_connect_timeout " + v.MaxTimeout + "s;\n"
		tcpServerConf += "\tproxy_timeout " + v.NotTimeout + "s;\n"
		tcpServerConf += "\tproxy_pass " + k + ";\n"
		tcpServerConf += "\taccess_log /www/wwwlogs/tcp_udp_" + k + ".log tcp_udp_format;\n"
		tcpServerConf += "\terror_log /www/wwwlogs/tcp_udp_" + k + ".error.log;\n"
		tcpServerConf += "}\n"

	}
	return tcpServerConf

}

func AddTcpLoadBalance(protocol string, listenAddress string, port string, maxTimeout string, notTimeout string, ps string, nodeInfo []types.LoadNodeInfo) (string, error) {
	if !validate.IsPort(port) {
		return "", errors.New("端口不正确")
	}
	loadBalanceName := strings.ReplaceAll(listenAddress, ".", "_") + "__" + port
	nginxJsonContent, err := ReadFile(NginxJsonPath + "/nginx.json")
	if err != nil {
		nginxJsonContent = "{}"
	}
	nginxJson := types.TcpLoadBalance{}
	err = json.Unmarshal([]byte(nginxJsonContent), &nginxJson)
	if err != nil {
		return "", err
	}
	loadBalanceNameCheck := make([]string, 0)
	loadBalanceNameCheck = append(loadBalanceNameCheck, "127_0_0_1__"+port)
	loadBalanceNameCheck = append(loadBalanceNameCheck, "0_0_0_0__"+port)
	for _, v := range loadBalanceNameCheck {
		if _, ok := nginxJson.TcpLoadBalance[v]; ok {
			return "", errors.New("此端口的端口转发已存在")
		}
	}
	if _, ok := nginxJson.TcpLoadBalance[loadBalanceName]; ok {
		loadBalanceNameData := nginxJson.TcpLoadBalance[loadBalanceName]
		if loadBalanceNameData.ListenAddress == listenAddress && loadBalanceNameData.ListenPort == port {
			return "", errors.New("监听地址和端口已存在,请勿重复添加")
		}
		return "", errors.New("此端口的端口转发已存在")
	}
	addData := types.SingleTcpLoadBalance{}
	addData.Protocol = protocol
	addData.ListenAddress = listenAddress
	addData.ListenPort = port
	addData.MaxTimeout = maxTimeout
	addData.NotTimeout = notTimeout
	addData.Count = 0
	addData.CountTime = float64(time.Now().Unix())
	addData.AddTime = time.Now().Unix()
	addData.Ps = ""
	addNodeData := types.LoadNodeInfo{}
	for _, v := range nodeInfo {
		if _, ok := addData.NodeAddressMap[v.NodeAddress+":"+v.NodePort]; ok {
			return "", errors.New("节点地址和端口已存在,请勿重复添加")
		}
		logName := "/www/cloud_waf/nginx/logs/tcp_" + loadBalanceName + ".log"
		if !FileExists(logName) {
			WriteFile(logName, "")
		}
		addNodeData.NodeAddress = v.NodeAddress
		addNodeData.NodePort = v.NodePort
		addNodeData.Status = v.Status
		addNodeData.Weight = v.Weight
		addNodeData.MaxFails = v.MaxFails
		addNodeData.FailTimeout = v.FailTimeout
		addNodeData.NodeAddressFollow = v.NodeAddressFollow
		addNodeData.Ps = v.Ps
		id := RandomStr(20)
		if len(addData.NodeAddressMap) == 0 {
			addData.NodeAddressMap = make(map[string]types.LoadNodeInfo)
		}
		addData.NodeAddressMap[id] = addNodeData
	}
	if len(nginxJson.TcpLoadBalance) == 0 {
		nginxJson.TcpLoadBalance = make(map[string]types.SingleTcpLoadBalance)
	}
	nginxJson.TcpLoadBalance[loadBalanceName] = addData
	nginxJsonStr, err := json.Marshal(nginxJson)
	if err != nil {
		return "", err
	}
	boolV, err := WriteFile(NginxJsonPath+"/nginx.json", string(nginxJsonStr))
	if !boolV {
		return "", errors.New("写入json配置文件失败")
	}
	tcpUpstreamContent := AddTcpJsonToTcpUpstream(nginxJson.TcpLoadBalance)
	tcpServerContent := AddTcpJsonToTcpServer(nginxJson.TcpLoadBalance)
	tcpContent := tcpUpstreamContent + tcpServerContent
	boolV, err = WriteFile(NginxStreamPath+"/tcp.conf", tcpContent)
	if !boolV {
		return "", errors.New("写入tcp.conf配置文件失败")
	}
	err = ReloadNginx()
	if err != nil {
		return "", err
	}
	if listenAddress != "127.0.0.1" && listenAddress != "localhost" {
		err := AllowPortByProtocol(port, protocol, true)
		if err != nil {
			logging.Debug("放行端口失败:", err)
		}
	}

	return "", nil

}

func ReadFileLine(fileName string, match_string string, match_line int, countTime float64, lineCount int) (int, float64, error) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var countTimeNum float64 = 0
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "|")
		if len(fields) >= match_line+1 && fields[match_line] == match_string {
			countTimeTmp, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				countTimeNum = countTimeTmp
				if countTimeTmp > countTime {
					lineCount++
				}

			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return lineCount, countTimeNum, err
	}
	return lineCount, countTimeNum, nil
}

func ReadTcpLoadJsonFile(filePath string) (types.TcpLoadBalance, error) {
	tcpLoadBalance := types.TcpLoadBalance{}
	jsonStr, err := ReadFileBytes(filePath)
	if err != nil {
		return tcpLoadBalance, err
	}
	if err = json.Unmarshal(jsonStr, &tcpLoadBalance); err != nil {
		return tcpLoadBalance, err
	}
	return tcpLoadBalance, nil
}

func PortForwardingCount() (map[string]int, error) {
	countMap := make(map[string]int, 0)
	sourceLoadStr, err := ReadTcpLoadJsonFile(NginxJsonPath + "/nginx.json")
	if err != nil {
		return countMap, err
	}
	if len(sourceLoadStr.TcpLoadBalance) > 0 {
		for k, v := range sourceLoadStr.TcpLoadBalance {
			logName := "/www/cloud_waf/nginx/logs/tcp_udp_" + k + ".log"
			if FileExists(logName) {
				tmpCount, countTime, err := ReadFileLine(logName, v.ListenPort, 3, v.CountTime, v.Count)
				if err != nil {
					continue
				}
				countMap[k] = tmpCount
				if tmpCount > 0 {
					v.Count = tmpCount
				}
				if countTime > 0 {
					v.CountTime = countTime
				}
			} else {
				countMap[k] = v.Count
				continue
			}
			sourceLoadStr.TcpLoadBalance[k] = v
		}
	}
	writeData, err := json.Marshal(sourceLoadStr)
	if err != nil {
		return countMap, err
	}
	boolV, err := WriteFile(NginxJsonPath+"/nginx.json", string(writeData))
	if !boolV {
		return countMap, err
	}
	return countMap, nil
}

func GetFirstServerNameBySiteId(siteId string) (string, error) {
	serverName := ""
	data, err := GetSiteJson(siteId)
	if err != nil {
		return serverName, err
	}
	if len(data.Server.ServerName) > 0 {
		serverName = data.Server.ServerName[0]

	}
	return serverName, nil
}

func SiteJsonToBack(siteJson map[string]interface{}) (types.SiteJson, error) {
	server := types.ServerJson{}
	err := json.Unmarshal([]byte(siteJson["server"].(string)), &server)
	if err != nil {
		return types.SiteJson{}, err
	}
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

func GetSiteReturnDomain(siteId string) (map[string]string, error) {
	sourceSlice := make(map[string]string, 0)
	if !M("site_info").Where("site_id = ?", []any{siteId}).Exists() {
		return sourceSlice, errors.New("网站配置不存在")
	}
	query := M("site_info").
		Field([]string{"id", "site_id", "site_name", "server", "is_cdn", "load_group_id", "status", "create_time", "update_time"}).
		Where("site_id = ?", []any{siteId})
	result, err := query.Find()
	if err != nil {
		return sourceSlice, err
	}
	data, err := SiteJsonToBack(result)
	if err != nil {
		return sourceSlice, err
	}
	if len(data.Server.Upstream.Server) > 0 {
		for _, v1 := range data.Server.Upstream.Server {
			address := strings.TrimSpace(v1.Address)
			address = ReplaceHttp(address)
			if strings.Contains(address, ":") {
				address = strings.Split(address, ":")[0]
			}
			if IsIpv4(address) || IsIpv6(address) {
				continue
			}
			if _, ok := sourceSlice[address]; !ok {
				sourceSlice[address] = "1"
			}
		}
	}
	return sourceSlice, nil
}

func GetDomainParse(sourceSlice map[string]string) (map[string]map[string]string, error) {
	newDomainParse := make(map[string]map[string]string, 0)
	for k, _ := range sourceSlice {
		addresses, err := net.LookupHost(k)
		if err != nil {
			return newDomainParse, err
		}
		domainParse := make(map[string]string, 0)
		for _, address := range addresses {
			domainParse[address] = "1"
		}
		newDomainParse[k] = domainParse
	}
	return newDomainParse, nil
}

func SiteSourceAddressAutoCheck() {
	res, err := M("site_return_domain_check").Select()
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
		newDomainParse, err := GetDomainParse(sourceSlice)
		if err != nil {
			continue
		}
		if len(newDomainParse) < 1 {
			continue
		}
		isUpdate := false
		newParseSame := true
		for i := 0; i < 4; i++ {
			newDomainParseTmp, err := GetDomainParse(sourceSlice)
			if err != nil {
				continue
			}
			if len(newDomainParse) != len(newDomainParseTmp) {
				newParseSame = false
				break
			}
			if len(newDomainParseTmp) != len(newDomainParse) {
				newParseSame = false
				break
			}
			for kk, valuev := range newDomainParseTmp {
				if _, ok := newDomainParse[kk]; !ok {
					newParseSame = false
					break
				}
				if len(newDomainParse[kk]) != len(newDomainParse[kk]) {
					newParseSame = false
				}
				for k2, _ := range valuev {
					if _, ok := newDomainParse[kk][k2]; !ok {
						newParseSame = false
						break
					}
				}
			}

		}
		if !newParseSame {
			continue

		}
		if len(oldDomainParse) != len(newDomainParse) {
			isUpdate = true
		}
		for k, value := range newDomainParse {
			if _, ok := oldDomainParse[k]; !ok {
				isUpdate = true
				break
			}
			if len(oldDomainParse[k]) != len(newDomainParse[k]) {
				isUpdate = true
			}
			for k1, _ := range value {
				if _, ok := oldDomainParse[k][k1]; !ok {
					isUpdate = true
					break
				}
			}
		}
		if isUpdate {
			isReload = true
			newDomainParseJson, err := json.Marshal(newDomainParse)
			if err != nil {
				continue
			}
			_, err = M("site_return_domain_check").Where("site_id=?", siteId).Update(map[string]any{"parse_info": string(newDomainParseJson), "last_exec_time": time.Now().Unix()})
			if err != nil {
				logging.Error("更新回源域名解析信息失败:", err)
			}
		}
	}
	if isReload {
		err = ReloadNginx()
		if err != nil {
			logging.Error("回源域名解析ip变化---重载nginx失败:", err)
		}
	}
}
