package providers

import (
	"CloudWaf/core"
	"os"
)

func init() {
	dp := &directoryProvider{
		directories: []string{
			core.AbsPath("./config"),
			core.AbsPath("./data"),
			core.AbsPath("./logs"),
			core.AbsPath("./ssl"),
			core.AbsPath("./data/sessions"),
			core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/data"),
			core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/data/speed_cache"),
			core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/data/speed_total"),
			core.AbsPath("/www/cloud_waf/nginx/conf.d/waf/data/replace_total"),
		},
	}
	registerProviderAlways(dp.Run)
}

type directoryProvider struct {
	directories []string
}

func (dp *directoryProvider) Run() {
	dp.createDirectories()
}

func (dp *directoryProvider) createDirectories() {
	for _, dir := range dp.directories {
		_ = os.MkdirAll(dir, 0644)
	}
}
