package providers

import (
	"CloudWaf/core/common"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/types"
	"encoding/json"
	"os"
	"path/filepath"
)

func init() {
	p := &patcher{
		rootPath: common.AbsPath("./data/.tags"),
	}
	registerProviderAlways(p.Run)
}

type patcher struct {
	rootPath string
}

func (p *patcher) Run() {
	if err := os.MkdirAll(p.rootPath, 0644); err != nil {
		return
	}

	if !p.isPatched("clear_webcache_v1") {
		p.DeleteSpeedOldData()
		p.DeleteRulesHitOldData()
		p.patch("clear_webcache_v1")
	}

	if !p.isPatched("clear_webcache_v2") {
		p.AddHitRuleTypeJson()
		p.patch("clear_webcache_v2")
	}
}

func (p *patcher) isPatched(filename string) bool {
	if _, err := os.Stat(p.path(filename)); err != nil {
		return false
	}

	return true
}

func (p *patcher) patch(filename string) error {
	return os.WriteFile(p.path(filename), []byte{}, 0644)
}

func (p *patcher) unpatch(filename string) error {
	return os.Remove(p.path(filename))
}

func (p *patcher) path(filename string) string {
	return filepath.Join(p.rootPath, filename)
}

func (p *patcher) DeleteSpeedOldData() {
	path1 := "/www/cloud_waf/nginx/conf.d/waf/data/speed_total/"
	path2 := "/www/cloud_waf/nginx/conf.d/waf/data/speed_cache/"
	err := os.RemoveAll(path1)
	if err != nil {
		logging.Error("清空网站统计失败：", err)
	}
	err = os.RemoveAll(path2)
	if err != nil {
		logging.Error("清空网站缓存失败：", err)
	}
}

func (p *patcher) DeleteRulesHitOldData() {
	public.HttpPostByToken(public.URL_HTTP_REQUEST+"/clean_btwaf_logs", 15)
	path := "/www/cloud_waf/nginx/conf.d/waf/data/btwaf_rule_hit.json"
	if !public.FileExists(path) {
		return
	}
	err := os.Remove(path)
	if err != nil {
		return
	}
}

func (p *patcher) AddHitRuleTypeJson() {
	hit_type_path := "/www/cloud_waf/nginx/conf.d/waf/rule/rule_hit_list.json"

	file_data := types.RuleHitType{
		IPw:         true,
		IPb:         true,
		URIw:        true,
		URIb:        true,
		UAw:         true,
		UAb:         true,
		Customize:   true,
		CustomizeCC: true,
		Area:        true,
		CloudIP:     true,
		Man:         false,
		Replace:     false,
	}
	rules_js, err := json.Marshal(file_data)
	if err != nil {
		logging.Error("转json失败：", err)
	}
	_, err = public.WriteFile(hit_type_path, string(rules_js))

	public.HttpPostByToken("http://127.0.0.251/updateinfo?types=rule", 2)

}
