package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"net/http"
)

func init() {
	core.RegisterModule(&Sys{})
}

type Sys struct{}

func (sys *Sys) GetSystemInfo(request *http.Request) core.Response {
	return core.Success(public.GetSystemInfo())
}
