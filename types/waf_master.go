package types

import (
	"sync"
	"time"
)

var (
	SsLHttpDebug      = "/www/cloud_waf/console/data/ssl_debug"
	NginxPath         = "/www/cloud_waf/nginx/"
	WwwLogs           = "/www/wwwlogs/"
	VhostPath         = NginxPath + "conf.d/vhost/"
	NginxStreamPath   = NginxPath + "conf.d/stream/"
	UserPath          = NginxPath + "conf.d/user/"
	WafSiteConfigPath = NginxPath + "conf.d/waf/config/site.json"
	SiteIdPath        = NginxPath + "conf.d/other/siteid.json"
	DomainConfig      = NginxPath + "conf.d/waf/config/domains.json"
	NginxJsonPath     = GlobalVhostPath + "nginx_json"
	SliceSiteLogJson  = GlobalVhostPath + "slice_log_json/"
	DomainsJsonPath   = NginxPath + "conf.d/waf/config/domains.json"
	SiteRootPath      = "/www/cloud_waf/wwwroot/"

	LogRootPath = NginxPath + "logs/"

	CertPath           = NginxPath + "conf.d/cert/"
	DockerCertPath     = "/etc/nginx/cert/"
	GlobalVhostPath    = "/www/cloud_waf/vhost/"
	SslPath            = GlobalVhostPath + "ssl/"
	SiteJsonPath       = GlobalVhostPath + "site_json/"
	BackupPath         = NginxPath + "conf.d/backup/"
	ZipPath            = NginxPath + "conf.d/zip/"
	HistoryBackupPath  = GlobalVhostPath + "history_backups/"
	WafRuleHistoryPath = HistoryBackupPath + "waf_rule/"

	SiteDomainConfigJson  = SiteJsonPath + "domains.json"
	SiteWafConfigJson     = SiteJsonPath + "site.json"
	SiteGlobalConfig      = SiteJsonPath + "config.json"
	WafPath               = NginxPath + "conf.d/waf"
	RulePath              = WafPath + "/rule/"
	WafRuleLogPath        = "/www/cloud_waf/console/logs/waf_rule_backup.log"
	WafRuleRestoreLogPath = "/www/cloud_waf/console/logs/waf_rule_restore.log"

	HistoryBackupConfig = HistoryBackupPath + "config/"

	ErrIpWithHttp    = "，请参考如下正确填写：<br />http://192.168.10.10:8080"
	ErrIpWithNotHttp = "，请参考如下正确填写：<br />192.168.10.10:8080"

	SslCiphersDefault   = "EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5"
	SslProtocolsDefault = []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}

	DockerNginx      = "/etc/nginx/cert/"
	englistToChinese = map[string]string{"aliyun": "阿里云DNS", "tencent": "腾讯云DNS"}
	LogLock          = sync.RWMutex{}
	ReturnInfo       = "暂不支持此添加方式！你可以用此域名%s创建一个新的网站！"

	DomainList = []string{"tk", "com", "cn", "top", "xyz", "net", "work", "vip", "email", "club", "site", "live", "wang", "online", "tech", "cc", "fans", "group", "host", "cloud", "shop", "team", "beer", "ren", "technology", "fashion", "luxe", "yoga", "red", "love", "ltd", "chat", "pub", "run", "city", "kim", "pet", "space", "fun", "store", "pink", "ski", "design", "ink", "wiki", "video", "company", "plus", "center", "cool", "fund", "gold", "guru", "life", "show", "today", "world", "zone", "social", "bio", "black", "blue", "green", "lotto", "organic", "poker", "promo", "vote", "archi", "voto", "fit", "website", "press", "icu", "art", "law", "band", "media", "cab", "cash", "cafe", "games", "link", "fan", "info", "pro", "mobi", "asia", "studio", "biz", "vin", "news", "fyi", "tax", "tv", "market", "shopping", "mba", "sale", "co", "中国", "企业", "我爱你", "移动", "中文网", "集团", "在线", "游戏", "网店", "网址", "网站", "商店", "娱乐"}

	DomainSuffix = map[string]int{"archi": 1, "art": 1, "asia": 1, "band": 1, "beer": 1, "bio": 1, "biz": 1, "black": 1, "blue": 1, "cab": 1, "cafe": 1, "cash": 1, "cc": 1, "center": 1, "chat": 1, "city": 1, "cloud": 1, "club": 1, "cn": 1, "co": 1, "com": 1, "company": 1, "cool": 1, "design": 1, "email": 1, "fan": 1, "fans": 1, "fashion": 1, "fit": 1, "fun": 1, "fund": 1, "fyi": 1, "games": 1, "gold": 1, "green": 1, "group": 1, "guru": 1, "host": 1, "icu": 1, "info": 1, "ink": 1, "kim": 1, "law": 1, "life": 1, "link": 1, "live": 1, "lotto": 1, "love": 1, "ltd": 1, "luxe": 1, "market": 1, "mba": 1, "media": 1, "mobi": 1, "net": 1, "news": 1, "online": 1, "organic": 1, "pet": 1, "pink": 1, "plus": 1, "poker": 1, "press": 1, "pro": 1, "promo": 1, "pub": 1, "red": 1, "ren": 1, "run": 1, "sale": 1, "shop": 1, "shopping": 1, "show": 1, "site": 1, "ski": 1, "social": 1, "space": 1, "store": 1, "studio": 1, "tax": 1, "team": 1, "tech": 1, "technology": 1, "tk": 1, "today": 1, "top": 1, "tv": 1, "video": 1, "vin": 1, "vip": 1, "vote": 1, "voto": 1, "wang": 1, "website": 1, "wiki": 1, "work": 1, "world": 1, "xyz": 1, "yoga": 1, "zone": 1, "中国": 1, "中文网": 1, "企业": 1, "商店": 1, "在线": 1, "娱乐": 1, "我爱你": 1, "游戏": 1, "移动": 1, "网址": 1, "网店": 1, "网站": 1, "集团": 1}
)

type SiteListParams struct {
	P        int    `json:"p"`
	PSize    int    `json:"p_size"`
	SiteName string `json:"site_name"`
	SiteId   string `json:"site_id"`
}

type WafRegion struct {
	RegionId string            `json:"region_id"`
	Count    int64             `json:"count"`
	Region   map[string]string `json:"region"`
	Status   bool              `json:"status"`
	SiteId   map[string]string `json:"site"`
	Time     int64             `json:"time"`
	Types    string            `json:"types"`
	Uri      string            `json:"uri"`
}

type SslJson struct {
	SiteIDs    []string `json:"site_ids"`
	SslName    string   `json:"ssl_name"`
	Fullchain  string   `json:"full_chain"`
	PrivateKey string   `json:"private_key"`
	SslType    string   `json:"ssl_type"`
	SslPath    string   `json:"ssl_path"`
	CreateTime int64    `json:"create_time"`
	Domains    []string `json:"domains"`
	ApplyType  string   `json:"apply_type"`
}

type SslEntryJson struct {
	SiteID     string `json:"site_id"`
	SslName    string `json:"ssl_name"`
	SslType    string `json:"ssl_type"`
	SslPath    string `json:"ssl_path"`
	CreateTime int64  `json:"create_time"`
	Domains    string `json:"domains"`
	ApplyType  string `json:"apply_type"`
}

type ApplySslInfo struct {
	SiteID     string `json:"site_ids"`
	SslName    string `json:"ssl_name"`
	Fullchain  string `json:"full_chain"`
	PrivateKey string `json:"private_key"`
	SslType    string `json:"ssl_type"`
	SslPath    string `json:"ssl_path"`
	CreateTime int64  `json:"create_time"`
}

type SiteIdAndName struct {
	SiteId     string `json:"site_id"`
	SiteName   string `json:"site_name"`
	CreateTime int    `json:"create_time"`
}

type Domains struct {
	DomainString string `json:"domain_string"`
}

type SiteJson struct {
	Types                string                 `json:"types"`
	DomainList           []string               `json:"domain_list"`
	SiteName             string                 `json:"site_name"`
	SiteID               string                 `json:"site_id"`
	Server               ServerJson             `json:"server"`
	IsCDN                int64                  `json:"is_cdn"`
	CreateTime           int64                  `json:"create_time"`
	UpdateTime           int64                  `json:"update_time"`
	LoadGroupId          int64                  `json:"load_group_id"`
	Status               int64                  `json:"status"`
	WafInfo              map[string]interface{} `json:"waf_info"`
	RegionalRestrictions []interface{}          `json:"regional_restrictions"`
	Overseas             Overseas               `json:"overseas"`
}

type ProxyInfo struct {
	ProxyConnectTimeout string `json:"proxy_connect_timeout,omitempty"`
	ProxySendTimeout    string `json:"proxy_send_timeout,omitempty"`
	ProxyReadTimeout    string `json:"proxy_read_timeout,omitempty"`
}

type Overseas struct {
	Status   bool   `json:"status"`
	RegionId string `json:"region_id"`
}

type EntrySiteJson struct {
	SiteName    string `json:"site_name"`
	SiteID      string `json:"site_id"`
	Server      string `json:"server"`
	IsCDN       int64  `json:"is_cdn"`
	CreateTime  int64  `json:"create_time"`
	LoadGroupId int64  `json:"load_group_id"`
	Status      int64  `json:"status"`
	UpdateTime  int64  `json:"update_time"`
}

type SiteInfo struct {
	ListenPort    []string `json:"listen_port"`
	ListenSslPort string   `json:"listen_ssl_port"`

	ServerName []string `json:"server_name"`
	IsSsl      int      `json:"is_ssl"`
}

type EntrySiteCheck struct {
	SiteId       string `json:"site_id"`
	DomainString string `json:"domain_string"`
	Port         string `json:"port"`
	CreateTime   int64  `json:"create_time"`
}

type ServerJson struct {
	ListenPort      []string      `json:"listen_port"`
	ListenSslPort   []string      `json:"listen_ssl_port"`
	ListenTag       []string      `json:"listen_tag"`
	ListenIpv6      int           `json:"listen_ipv6"`
	ServerName      []string      `json:"server_name"`
	Index           []string      `json:"index"`
	Root            string        `json:"root"`
	If              IfConfig      `json:"if"`
	Ssl             *SiteSsl      `json:"ssl"`
	UserInclude     string        `json:"user_include"`
	UserIncludeText string        `json:"user_include_text"`
	Upstream        *UpstreamJson `json:"upstream"`
	Gzip            GzipJson      `json:"gzip"`
	Location        *LocationList `json:"location_list"`
	Log             LogInfo       `json:"log"`
	ProxyInfo       ProxyInfo     `json:"proxy_info"`
	Client          Client        `json:"client"`
}

type Client struct {
	MaxBodySize    string `json:"max_body_size"`
	BodyBufferSize string `json:"body_buffer_size"`
}
type IfConfig struct {
	Uri If `json:"uri"`
}

type If struct {
	Name   string `json:"name"`
	Match  string `json:"match"`
	Value  string `json:"value"`
	Return string `json:"return"`
}

type GzipJson struct {
	Status          bool     `json:"status"`
	GzipMinLength   string   `json:"gzip_min_length"`
	GzipBuffers     []string `json:"gzip_buffers"`
	GzipHttpVersion string   `json:"gzip_http_version"`
	GzipCompLevel   string   `json:"gzip_comp_level"`
	GzipTypes       []string `json:"gzip_types"`
	GzipVary        bool     `json:"gzip_vary"`
	GzipProxied     []string `json:"gzip_proxied"`
	GzipDisable     []string `json:"gzip_disable"`
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

type SiteSsl struct {
	IsSsl                  int       `json:"is_ssl"`
	FullChain              string    `json:"full_chain"`
	PrivateKey             string    `json:"private_key"`
	SSLCertificate         string    `json:"ssl_certificate"`
	SSLCertificateKey      string    `json:"ssl_certificate_key"`
	SSLProtocols           []string  `json:"ssl_protocols"`
	SSLCiphers             []string  `json:"ssl_ciphers"`
	SSLPreferServerCiphers string    `json:"ssl_prefer_server_ciphers"`
	SSLSessionCache        []string  `json:"ssl_session_cache"`
	SSLSessionTimeout      string    `json:"ssl_session_timeout"`
	AddHeader              []string  `json:"add_header"`
	ErrorPage              []string  `json:"error_page"`
	ForceHttps             int       `json:"force_https"`
	NotAfter               time.Time `json:"not_after"`
	Brand                  string    `json:"brand"`
	Domains                []string  `json:"Domains"`
	SslName                string    `json:"ssl_name"`
	SslType                string    `json:"ssl_type"`
	ApplyType              string    `json:"apply_type"`
}

type SiteUpstream struct {
	Address     string `json:"address"`
	MaxFails    string `json:"max_fails"`
	FailTimeout string `json:"fail_timeout"`
	Weight      string `json:"weight"`
	Status      string `json:"status"`
	Ps          string `json:"ps"`
	AddTime     int64  `json:"add_time"`
	Id          string `json:"id"`
}

type UpstreamJson struct {
	Name             string          `json:"name"`
	PollingAlgorithm string          `json:"polling_algorithm"`
	Host             string          `json:"host"`
	Server           []*SiteUpstream `json:"server"`
	EnableNote       int             `json:"enable_note"`
	SourceProtocol   string          `json:"source_protocol"`
	CheckDns         CheckDns        `json:"check_dns"`
}

type CheckDns struct {
	Status         int64                      `json:"status"`
	InspectionTime int64                      `json:"inspection_time"`
	DomainAddress  map[string]ReturnDomainDns `json:"domain_address"`
}

type ReturnDomainDns struct {
	Address map[string]string `json:"address"`
}

type LocationList struct {
	LocationEqual []LocationJson `json:"location =,omitempty"`
	LocationNot   []LocationJson `json:"location ,omitempty"`
	LocationTilde []LocationJson `json:"location ^~,omitempty"`
	LocationStar  []LocationJson `json:"location ~*,omitempty"`
	LocationRegex []LocationJson `json:"location ~,omitempty"`
	LocationAt    []LocationJson `json:"location @,omitempty"`
}

type LocationJson struct {
	MatchPriority     string   `json:"match_priority,omitempty"`
	MatchArguments    string   `json:"match_arguments,omitempty"`
	ProxyPass         string   `json:"proxy_pass,omitempty"`
	ProxySetHeader    []string `json:"proxy_set_header,omitempty"`
	ProxyNextUpstream []string `json:"proxy_next_upstream,omitempty"`
	ProxyCache        string   `json:"proxy_cache,omitempty"`
	Allow             string   `json:"allow,omitempty"`
	Deny              string   `json:"deny,omitempty"`
	TryFiles          []string `json:"try_files,omitempty"`
	Expires           string   `json:"expires,omitempty"`
	AccessLog         string   `json:"access_log,omitempty"`
	ErrorLog          string   `json:"error_log,omitempty"`
	Return            string   `json:"return,omitempty"`
}

type LogInfo struct {
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
	Local Remote `json:"local"`

	Mode string `json:"mode"`
}

type DnsRecord struct {
	PageNumber   uint64 `json:"page_number"`
	PageSize     uint64 `json:"page_size"`
	Domain       string `json:"domain"`
	DomainId     uint64 `json:"domain_id"`
	DomainGrade  string `json:"domain_grade"`
	SubDomain    string `json:"sub_domain"`
	RecordId     uint64 `json:"record_id"`
	RecordType   string `json:"record_type"`
	RecordLine   string `json:"record_line"`
	RecordLineId string `json:"record_line_id"`
	Value        string `json:"value"`
	MX           string `json:"mx"`
	TTL          string `json:"ttl"`
	Weight       string `json:"weight"`
	Status       string `json:"status"`
	Remark       string `json:"remark"`
	Region       string `json:"region"`
	Endpoint     string `json:"endpoint"`
}

type ApiKey struct {
	SecretId     string   `json:"secret_id" form:"secret_id"`
	SecretKey    string   `json:"secret_key" form:"secret_key"`
	DomainList   []string `json:"domains" form:"domains"`
	DomainString string   `json:"domain_string" form:"domain_string"`
	Types        string   `json:"types" form:"types"`
	Ps           string   `json:"ps" form:"ps"`
	Status       int64    `json:"status" form:"status"`
}

type DnsData struct {
	Key        ApiKey   `json:"api_key"`
	Name       string   `json:"dns_name"`
	DomainList []string `json:"domains"`
	Ps         string   `json:"ps"`
	Time       int64    `json:"create_time"`
}

type SyncSite struct {
	SiteId        string   `json:"site_id"`
	Types         string   `json:"types"`
	Domains       []string `json:"domains"`
	UserInclude   string   `json:"user_include"`
	MasterConf    string   `json:"master_conf"`
	Fullchain     string   `json:"full_chain"`
	PrivateKey    string   `json:"private_key"`
	SiteIdContent string   `json:"site_id_content"`
	Itself        int      `json:"itself"`
	LoadGroupId   int64    `json:"load_group_id"`
	NodeId        string   `json:"node_id"`
	FileName      string   `json:"file_name"`
}

type EntryDnsData struct {
	Key        string `json:"api_key"`
	Name       string `json:"dns_name"`
	DomainList string `json:"domains"`
	Ps         string `json:"ps"`
	Time       int64  `json:"create_time"`
	Status     int64  `json:"status"`
}

type ListDnsData struct {
	Key         string `json:"api_key"`
	Name        string `json:"dns_name"`
	NameChinese string `json:"name_chinese"`
	DomainList  string `json:"domains"`
	Ps          string `json:"ps"`
	Time        int64  `json:"create_time"`
	Status      int64  `json:"status"`
	DomainTotal int    `json:"domain_total"`
}

type EntryMasterLoadBalance struct {
	Name         string `json:"load_name"`
	CorruptCheck int    `json:"corrupt_check"`
	DnsName      string `json:"dns_name"`
	Method       string `json:"load_method"`
	Nodes        string `json:"nodes"`
	Ps           string `json:"ps"`
	CreateTime   int64  `json:"create_time"`
}
type EntryMasterLoadBalanceAll struct {
	Id           int64  `json:"id"`
	Name         string `json:"load_name"`
	CorruptCheck int    `json:"corrupt_check"`
	DnsName      string `json:"dns_name"`
	Method       string `json:"load_method"`
	Nodes        string `json:"nodes"`
	Ps           string `json:"ps"`
	CreateTime   int64  `json:"create_time"`
}

type MasterLoadBalanceAll struct {
	Id           int64        `json:"id"`
	Name         string       `json:"load_name"`
	CorruptCheck int          `json:"corrupt_check"`
	DnsName      string       `json:"dns_name"`
	ChineseName  string       `json:"chinese_name"`
	Method       string       `json:"load_method"`
	Nodes        []*LoadNodes `json:"nodes"`
	Ps           string       `json:"ps"`
	CreateTime   int64        `json:"create_time"`
}

type MasterLoadBalance struct {
	Name         string       `json:"load_name"`
	CorruptCheck int          `json:"corrupt_check"`
	DnsName      string       `json:"dns_name"`
	ChineseName  string       `json:"chinese_name"`
	Method       string       `json:"load_method"`
	Nodes        []*LoadNodes `json:"nodes"`
	Ps           string       `json:"ps"`
	CreateTime   int64        `json:"create_time"`
}

type LoadNodes struct {
	Ip         string `json:"ip"`
	Weight     int    `json:"weight"`
	Region     string `json:"region"`
	Status     int    `json:"status"`
	Id         string `json:"id"`
	Ps         string `json:"ps"`
	IsParse    bool   `json:"is_parse"`
	CreateTime int64  `json:"create_time"`
}

type Tencent struct {
	DomainId  uint64 `json:"DomainId"`
	Name      string `json:"Name"`
	Status    string `json:"Status"`
	DNSStatus string `json:"DNSStatus"`
	Grade     string `json:"Grade"`
}

type Aliyun struct {
	DomainId    string `json:"DomainId"`
	Name        string `json:"Name"`
	AliDomain   bool   `json:"AliDomain"`
	RecordCount int64  `json:"RecordCount"`
	VersionCode string `json:"VersionCode"`
}

type NodeList struct {
	Ip               string `json:"ip"`
	Remark           string `json:"remark"`
	Id               string `json:"id"`
	ServerIpLocation string `json:"server_ip_location"`
	Status           int    `json:"status"`
	InGroup          int    `json:"in_group"`
	SortId           int    `json:"sort_id"`
}

type DnsDomainInfo struct {
	RootDomain  string            `json:"root_domain"`
	Subdomain   map[string]string `json:"subdomain"`
	DnsName     string            `json:"dns_name"`
	ChineseName string            `json:"chinese_name"`
	Status      int               `json:"status"`
	ParseList   []interface{}     `json:"parse_list"`
	Version     string            `json:"version"`
	DnsServer   bool              `json:"dns_server"`
}

type TencentParse struct {
	Host   string `json:"host"`
	Ip     string `json:"address"`
	TTL    uint64 `json:"ttl"`
	Line   string `json:"line"`
	Weight uint64 `json:"weight"`
	Type   string `json:"type"`
	Status int    `json:"status"`
}

type AliyunParse struct {
	Host string `json:"host"`
	Ip   string `json:"address"`
	TTL  int64  `json:"ttl"`
	Line string `json:"line"`

	Type   string `json:"type"`
	Status int    `json:"status"`
}

type DomainInfo struct {
	Name      *string `json:"name"`
	DNSStatus bool    `json:"dns_status"`
}

type SiteDomainParse struct {
	SiteId      string `json:"site_id"`
	Subdomain   string `json:"subdomain"`
	RootDomain  string `json:"root_domain"`
	Ip          string `json:"ip"`
	ParseStatus int64  `json:"parse_status"`
	ParseTime   int64  `json:"parse_time"`
}

type AcmeInfo struct {
	Domain []string `json:"domain"`
	Server string   `json:"server"`
	Types  string   `json:"types"`
	SiteId string   `json:"site_id"`
}

type AcmeIn struct {
	SiteId string `json:"site_id"`
}

type SyncSiteJson struct {
	SiteID      string `json:"site_id"`
	Types       string `json:"types"`
	LoadGroupId int64  `json:"load_group_id"`
	NodeId      int64  `json:"node_id"`
}
