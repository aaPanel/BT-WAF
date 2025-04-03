package types

type Example struct{}

type ExportData1 struct {
	Time        int64  `json:"time"`
	Action      int64  `json:"action"`
	Server_name string `json:"server_name"`
	Uri         string `json:"uri"`
	Ip          string `json:"ip"`
	Ip_country  string `json:"ip_country"`
	Risk_type   string `json:"risk_type"`
}

type ExportData2 struct {
	Time          int64  `json:"time"`
	Block_status  int64  `json:"block_status"`
	Blocking_time int64  `json:"blocking_time"`
	Ip            string `json:"ip"`
	Ip_country    string `json:"ip_country"`
	Server_name   string `json:"server_name"`
	Uri           string `json:"uri"`
	Risk_type     string `json:"risk_type"`
}

type ManData struct {
	Open      float64       `json:"open"`
	Sort_     int           `json:"sort"`
	Timestamp int64         `json:"timestamp"`
	AuthType  string        `json:"auth_type"`
	Rules     []interface{} `json:"rules"`
	PS        string        `json:"ps"`
	Count     int           `json:"count"`
	RuleLog   string        `json:"rule_log"`
	Key       string        `json:"key"`
}

type URLRule struct {
	URL   string  `json:"url"`
	Type  string  `json:"type"`
	Param string  `json:"param,omitempty"`
	Open  float64 `json:"open"`
	Time  int64   `json:"time"`
	Notes string  `json:"notes"`
	Count int     `json:"count"`
	Index string  `json:"index"`
}

type UARule struct {
	Ua    string  `json:"ua"`
	Open  float64 `json:"open"`
	Time  int64   `json:"time"`
	Notes string  `json:"notes"`
	Count int     `json:"count"`
	Index string  `json:"index"`
}

type OverViewRequest struct {
	Id        int64  `json:"id"`
	Date      string `json:"date"`
	Err499    int64  `json:"err_499"`
	Err502    int64  `json:"err_502"`
	Err504    int64  `json:"err_504"`
	Hour      int64  `json:"hour"`
	Minute    int64  `json:"minute"`
	Request   int64  `json:"request"`
	Datam     int64  `json:"datam"`
	Timestamp int64  `json:"timestamp"`
}

type SpiderRequest struct {
	Hour      int `json:"hour"`
	Baidu     int `json:"baidu"`
	Google    int `json:"google"`
	Bing      int `json:"bing"`
	Sogou     int `json:"sogou"`
	Spider360 int `json:"spider_360"`
}

type Exclusive struct {
	SiteName  string  `json:"site_name"`
	RuleName  string  `json:"rule_name"`
	Count     float64 `json:"count"`
	Timestamp int64   `json:"timestamp"`
	Status    float64 `json:"status"`
	PS        string  `json:"ps"`
	SiteId    float64 `json:"site_id"`
}

type CClog struct {
	ServerName string     `json:"server_name"`
	BlockType  string     `json:"block_type"`
	Host       string     `json:"host"`
	Uri        string     `json:"uri"`
	IpInfo     []CCIpInfo `json:"ip_info"`
}

type CCIpInfo struct {
	Ip       string `json:"ip"`
	Request  int64  `json:"request"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	IpType   int    `json:"ip_type"`
}

type DomainCheck struct {
	SiteName     string `json:"sitename"`
	Status       bool   `json:"status"`
	SourceIPList struct {
		IntranetIPList []string `json:"intranet_ip_list"`
		ExtranetIPList []string `json:"extranet_ip_list"`
	} `json:"source_ip_list"`
	IsCDN        bool `json:"is_cdn"`
	IsHTTPS      bool `json:"is_https"`
	IsForceHTTPS bool `json:"is_force_https"`
}

type Speed struct {
	SiteName    string      `json:"site_name"`
	SiteId      string      `json:"site_id"`
	Open        bool        `json:"open"`
	EmptyCookie bool        `json:"empty_cookie"`
	Expire      int64       `json:"expire"`
	SingleSize  int64       `json:"size"`
	Force       []SpeedRule `json:"force"`
	White       []SpeedRule `json:"white"`
	Timestamp   int64       `json:"timestamp"`
}

type SpeedRule struct {
	Obj       string `json:"obj"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Key       string `json:"key"`
	Timestamp int64  `json:"timestamp"`
}

type Group struct {
	IP      string `json:"ip"`
	Network bool   `json:"Network"`
	Type    string `json:"type"`
	Time    int64  `json:"time"`
}

type Replace struct {
	SiteName string                   `json:"site_name"`
	SiteId   string                   `json:"site_id"`
	Open     bool                     `json:"open"`
	Rules    map[string][]ReplaceRule `json:"rules"`
}

type ReplaceRule struct {
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
	Keyword    string `json:"keyward"`
	ReValue    string `json:"re_value"`
	Key        string `json:"key"`
	Timestamp  int64  `json:"timestamp"`
}

type RuleHitType struct {
	IPw         bool `json:"IP白名单"`
	IPb         bool `json:"IP黑名单"`
	URIw        bool `json:"URI白名单"`
	URIb        bool `json:"URI黑名单"`
	UAw         bool `json:"UA白名单"`
	UAb         bool `json:"UA黑名单"`
	Customize   bool `json:"自定义拦截"`
	CustomizeCC bool `json:"自定义CC防御"`
	Area        bool `json:"地区限制"`
	CloudIP     bool `json:"云端恶意IP库"`
	Man         bool `json:"人机验证"`
	Replace     bool `json:"内容替换"`
}
