package types

type ConfigOrdinaryInfo struct {
	Mode float64 `json:"mode"`
	Ps   string  `json:"ps"`
}

type NumberAttacks struct {
	RetryCycle int    `json:"retry_cycle"`
	Retry      int    `json:"retry"`
	RetryTime  int    `json:"retry_time"`
	Ps         string `json:"ps"`
}

type Cc struct {
	CcTypeStatus int    `json:"cc_type_status"`
	Cycle        int    `json:"cycle"`
	Endtime      int    `json:"endtime"`
	Limit        int    `json:"limit"`
	Open         bool   `json:"open"`
	Ps           string `json:"ps"`
	Status       int    `json:"status"`
}

type FileUpload struct {
	Mode   int    `json:"mode"`
	Ps     string `json:"ps"`
	Status int    `json:"status"`
}

type ReadOnly struct {
	Open bool   `json:"open"`
	Ps   string `json:"ps"`
}

type SmartCc struct {
	Expire          float64 `json:"expire"`
	IpDropTime      float64 `json:"ip_drop_time"`
	MaxAvgProxyTime float64 `json:"max_avg_proxy_time"`
	MaxErrCount     float64 `json:"max_err_count"`
	MaxQps          float64 `json:"max_qps"`
	Open            bool    `json:"open"`
	Ps              string  `json:"ps"`
	Status          float64 `json:"status"`
}

type FileScan struct {
	Mode  int    `json:"mode"`
	Ps    string `json:"ps"`
	Limit int    `json:"limit"`
	Cycle int    `json:"cycle"`
}

type GlobalConfigRules struct {
	BlackStatus       int                    `json:"black_status"`
	Database          map[string]interface{} `json:"database"`
	NumberAttacks     NumberAttacks          `json:"number_attacks"`
	Cc                Cc                     `json:"cc"`
	FileUpload        FileUpload             `json:"file_upload"`
	FileScan          FileScan               `json:"file_scan"`
	MethodType        map[string]bool        `json:"method_type"`
	HeaderLen         map[string]int         `json:"header_len"`
	Sql               ConfigOrdinaryInfo     `json:"sql"`
	Xss               ConfigOrdinaryInfo     `json:"xss"`
	FromData          ConfigOrdinaryInfo     `json:"from_data"`
	PhpEval           ConfigOrdinaryInfo     `json:"php_eval"`
	Ssrf              ConfigOrdinaryInfo     `json:"ssrf"`
	Nday              ConfigOrdinaryInfo     `json:"nday"`
	Download          ConfigOrdinaryInfo     `json:"download"`
	UserAgent         ConfigOrdinaryInfo     `json:"user_agent"`
	Scan              ConfigOrdinaryInfo     `json:"scan"`
	FileImport        ConfigOrdinaryInfo     `json:"file_import"`
	NoBrowser         ConfigOrdinaryInfo     `json:"no_browser"`
	Host              ConfigOrdinaryInfo     `json:"host"`
	Cookie            ConfigOrdinaryInfo     `json:"cookie"`
	Rce               ConfigOrdinaryInfo     `json:"rce"`
	Idc               ConfigOrdinaryInfo     `json:"idc"`
	MachineVerifyType string                 `json:"machine_verify_type"`
	HttpOpen          bool                   `json:"http_open"`
}

type SiteConfigRules struct {
	Mode             int                `json:"mode"`
	AdminProtect     []interface{}      `json:"admin_protect"`
	Cc               Cc                 `json:"cc"`
	NumberAttacks    NumberAttacks      `json:"number_attacks"`
	FileUpload       FileUpload         `json:"file_upload"`
	ReadOnly         ReadOnly           `json:"readonly"`
	SmartCc          SmartCc            `json:"smart_cc"`
	DisableExt       []string           `json:"disable_ext"`
	DisablePhpPath   []string           `json:"disable_php_path"`
	DisableUploadExt []string           `json:"disable_upload_ext"`
	Cdn              bool               `json:"cdn"`
	CdnBaidu         bool               `json:"cdn_baidu"`
	CdnHeader        []string           `json:"cdn_header"`
	Cookie           ConfigOrdinaryInfo `json:"cookie"`
	Download         ConfigOrdinaryInfo `json:"download"`
	FileImport       ConfigOrdinaryInfo `json:"file_import"`
	FromData         ConfigOrdinaryInfo `json:"from_data"`
	PhpEval          ConfigOrdinaryInfo `json:"php_eval"`
	Scan             ConfigOrdinaryInfo `json:"scan"`
	Sql              ConfigOrdinaryInfo `json:"sql"`
	Ssrf             ConfigOrdinaryInfo `json:"ssrf"`
	UserAgent        ConfigOrdinaryInfo `json:"user_agent"`
	Xss              ConfigOrdinaryInfo `json:"xss"`
	Idc              ConfigOrdinaryInfo `json:"idc"`
	Rce              ConfigOrdinaryInfo `json:"rce"`
}

type TcpLoadBalance struct {
	TcpLoadBalance map[string]SingleTcpLoadBalance `json:"tcp_load_balance"`
}

type SingleTcpLoadBalance struct {
	Protocol string `json:"protocol"`

	ListenAddress  string                  `json:"listen_address"`
	ListenPort     string                  `json:"listen_port"`
	MaxTimeout     string                  `json:"max_timeout"`
	NotTimeout     string                  `json:"not_timeout"`
	Ps             string                  `json:"ps"`
	Count          int                     `json:"count"`
	CountTime      float64                 `json:"count_time"`
	AddTime        int64                   `json:"add_time"`
	NodeAddressMap map[string]LoadNodeInfo `json:"node_address_map"`
}

type LoadNodeInfo struct {
	NodeAddress string `json:"node_address"`
	NodePort    string `json:"node_port"`
	Weight      string `json:"weight"`
	MaxFails    string `json:"max_fails"`
	FailTimeout string `json:"fail_timeout"`
	Status      string `json:"status"`
	Ps          string `json:"ps"`

	NodeAddressFollow bool    `json:"node_address_follow"`
	AddTime           int64   `json:"add_time"`
	Count             int     `json:"count"`
	CountTime         float64 `json:"count_time"`
}
