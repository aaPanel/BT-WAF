package public

import (
	"CloudWaf/core"
)

type Charset string

const (
	UTF8                     = Charset("UTF-8")
	GB18030                  = Charset("GB18030")
	URL_BT_API               = "https://api.bt.cn"
	URL_BT_AUTH              = "https://api.bt.cn/authorization"
	URL_BT_BRANDNEW          = "https://www.bt.cn/api/v2"
	URL_BT_SUBMIT_BLOCK_LOGS = URL_BT_API + "/bt_waf/submit_waf_block_logs"

	URL_BT_GET_MALICIOUS_IP                  = URL_BT_API + "/bt_waf/get_malicious_ip"
	URL_BT_GET_MALICIOUS_IP_SHARE_PLAIN_TEXT = URL_BT_API + "/bt_waf/get_malicious_ip_share_plain_text"
	NPS_TYPE                                 = 5
	P_NAME                                   = "cloud_waf"
	URL_HTTP_REQUEST                         = "http://127.0.0.251"

	OPT_LOG_TYPE_SYSTEM                 = 0
	OPT_LOG_TYPE_LOGIN_SUCCESS          = 1
	OPT_LOG_TYPE_LOGIN_FAIL             = 2
	OPT_LOG_TYPE_UPDATE_PROFILE_SUCCESS = 3
	OPT_LOG_TYPE_UPDATE_PROFILE_FAIL    = 4
	OPT_LOG_TYPE_LOGOUT                 = 5
	OPT_LOG_TYPE_USER_OPERATION         = 6
	OPT_LOG_TYPE_MAN_MACHINE            = 7
	OPT_LOG_TYPE_SITE_LIST              = 8
	OPT_LOG_TYPE_SITE_AREA              = 9
	OPT_LOG_TYPE_SITE_GLOBAL_RULE       = 10
	OPT_LOG_TYPE_SITE_RULE              = 11
	OPT_LOG_TYPE_IP_WHITE               = 12
	OPT_LOG_TYPE_IP_BLACK               = 13
	OPT_LOG_TYPE_UA_WHITE               = 14
	OPT_LOG_TYPE_UA_BLACK               = 15
	OPT_LOG_TYPE_URL_WHITE              = 16
	OPT_LOG_TYPE_URL_BLACK              = 17
	OPT_LOG_TYPE_ATTACK_REPORT          = 18
	OPT_LOG_TYPE_SITE_SPEED             = 19
	OPT_LOG_TYPE_SITE_IPGROUP           = 20
	OPT_LOG_TYPE_PORT_FORWARD           = 21
	OPT_LOG_TYPE_REPLACEMENT            = 22
)

var (
	BT_USERINFO_FILE                        = core.AbsPath("./data/.userinfo")
	MYSQL_CONFIG_FILE                       = core.AbsPath("./config/mysql.json")
	SQLITE_CONFIG_FILE                      = core.AbsPath("./config/sqlite.json")
	WAF_RECAPTCHA_RULE_FILE                 = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/cc.json")
	WAF_LOCATION_CN_RULE_FILE               = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/city.json")
	WAF_LOCATION_WITHOUT_CN_RULE_FILE       = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/province.json")
	WAF_IP_BLACK_RULE_FILE                  = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/ip_black.json")
	WAF_IP_WHITE_RULE_FILE                  = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/ip_white.json")
	WAF_URI_BLACK_RULE_FILE                 = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/url_black.json")
	WAF_URI_WHITE_RULE_FILE                 = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/url_white.json")
	WAF_UA_BLACK_RULE_FILE                  = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/ua_black.json")
	WAF_UA_WHITE_RULE_FILE                  = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/ua_white.json")
	MALICIOUS_IP_FILE                       = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/malicious_ip.json")
	IP_GROUP_FILE                           = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/ip_group.json")
	MALICIOUS_IP_SHARE_PLAIN_FLAG_FILE      = core.AbsPath("./data/.malicious_ip_share_plain_flag")
	MALICIOUS_IP_SHARE_PLAIN_STATUS         = core.AbsPath("./data/.malicious_ip_share_plain_status")
	CUSTOMIZE_RULE_FILE                     = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/customize.json")
	CUSTOMIZE_RULE_HIT_FILE                 = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/customize_count.json")
	SITE_SPEED_RULE_FILE                    = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/speed.json")
	SITE_RESPONSE_CONTENT_REPLACE_RULE_FILE = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/rule/replacement.json")
	WAF_GLOBAL_RULE_FILE                    = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/config/config.json")
	WAF_SITE_RULE_FILE                      = core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/config/site.json")
)
