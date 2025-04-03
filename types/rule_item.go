package types

type RecaptchaRuleItem struct {
	Open      int    `json:"open"`
	Sort      int    `json:"sort"`
	Timestamp int64  `json:"timestamp"`
	AuthType  string `json:"auth_type"`
	Rules     any    `json:"rules"`
	Ps        string `json:"ps"`
	Count     int    `json:"count"`
	RuleLog   string `json:"rule_log"`
	Key       string `json:"key"`
}

type RegionRuleItem struct {
	Count    int    `json:"count"`
	Region   any    `json:"region"`
	RegionId string `json:"region_id"`
	Site     any    `json:"site"`
	Status   bool   `json:"status"`
	Time     int64  `json:"time"`
	Types    string `json:"types"`
	Uri      string `json:"uri"`
}

type URIBWRuleItem struct {
	Url   string `json:"url"`
	Type  string `json:"type"`
	Open  int    `json:"open"`
	Time  int64  `json:"time"`
	Notes string `json:"notes"`
	Count int    `json:"count"`
	Index string `json:"index"`
}

type UABWRuleItem struct {
	UA    string `json:"ua"`
	Open  int    `json:"open"`
	Time  int64  `json:"time"`
	Notes string `json:"notes"`
	Count int    `json:"count"`
	Index string `json:"index"`
}
