/*
Copyright (C)  www.bt.cn CloudWAF Team
Licensed under the AGPL-3.0 license. See LICENSE file in the project root for license information.
*/
package main

import (
	"CloudWaf/cli"
	"CloudWaf/core"
	"CloudWaf/core/authorization"
	"CloudWaf/core/cache"
	"CloudWaf/core/common"
	"CloudWaf/core/flock"
	"CloudWaf/core/language"
	"CloudWaf/core/logging"
	_ "CloudWaf/modules"
	"CloudWaf/providers"
	"CloudWaf/public"
	"CloudWaf/public/access"
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

//go:embed static
var staticFs embed.FS

// 注册中间件
func registerMiddlewares(srv *core.Server) {
	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		// API暂时不开放,等前端对接后开放
		if true {
			return true
		}

		if len(r.URL.Path) < 5 || !strings.EqualFold(r.URL.Path[:5], "/api/") {
			return true
		}

		if r.Header.Get("waf_request_time") != "" || r.Header.Get("waf_request_token") != "" {
			if len(r.Header.Get("waf_request_time")) < 10 || len(r.Header.Get("waf_request_token")) != 32 {
				return true
			}
			requestTime := r.Header.Get("waf_request_time")
			timestamp, err := strconv.ParseInt(requestTime, 10, 64)
			if err != nil {
				return true
			}
			if time.Now().Unix()-timestamp > 120 {
				return true
			}
			apiFilePath := "/www/cloud_waf/console/data/btwaf_api.json"
			if !public.FileExists(apiFilePath) {
				return true
			}
			api, err := public.GetWAFApi()
			if err != nil {
				return true
			}
			if api.Open == false {
				return true
			}
			clientIP := r.RemoteAddr
			if !api.CheckWafApiAccess(clientIP) {
				return true
			}
			requestToken := r.Header.Get("waf_request_token")
			if api.WafAuthorization(requestTime, requestToken) {
				ctx := context.WithValue(r.Context(), "waf_authorized", true)
				*r = *r.WithContext(ctx)
				return true
			}
			return true
		}
		return true
	})

	// API限流中间件
	limit := 60 // 限制每秒连接次数
	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
			return true
		}
		if len(r.URL.Path) < 5 || !strings.EqualFold(r.URL.Path[:5], "/api/") {
			return true
		}
		cacheKey := "RATELIMIT__" + core.SnakeCase(r.URL.Path) + "__" + core.GetClientIpFromRequest(r)
		if cache.IncOrSet(cacheKey, 60) >= limit {
			w.WriteHeader(http.StatusTooManyRequests)
			return false
		}

		return true
	})

	// 安全入口中间件 如果请求没有经过安全入口则直接返回404、API除外
	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
			return true
		}
		uri := r.URL.Path
		for i := 0; i < 1; i++ {
			if len(uri) > 256 || strings.Contains(uri, "../") {
				break
			}
			ck, err := r.Cookie(authorization.SID())
			if err != nil {
				ck = &http.Cookie{
					Name:     authorization.SID(),
					Value:    public.RandomStr(32),
					Expires:  time.Now().Add(86400 * 30 * time.Second),
					HttpOnly: true,
					Secure:   true,
					Path:     "/",
					SameSite: http.SameSiteNoneMode,
				}
				http.SetCookie(w, ck)
			}

			cacheKey := cache.SessionPrefix + ck.Value
			if cache.Has(cacheKey) {
				return true
			}
			adminPath := public.AdminPath()
			if uri == adminPath || adminPath == "" {
				if !cache.Has(cacheKey) {
					core.SetSessionWithKey(ck.Value, "IsLogin", false)
				}
				return true
			}

			break
		}

		err := core.Html(`<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`).WriteResponse(w, http.StatusNotFound)

		if err != nil {
			logging.Info("响应失败：", err)
		}

		return false
	})

	ipErrorHtmlCN := `<!doctype html>
<html lang="zh">
    <head>
        <meta charset="utf-8">
        <title>访问被拒绝</title>
    </head>
    <body>
        <h1>你的请求已经被拒绝</h1>
        <p>拒绝原因：</p>
        <p>没有使用正确的IP访问</p>
    </body>
</html>`

	ipErrorHtmlEN := `<!doctype html>
<html lang="zh">
    <head>
        <meta charset="utf-8">
        <title>Access Denied</title>
    </head>
    <body>
        <h1>Your request has been denied</h1>
        <p>Reason:</p>
        <p>Access is not being done using the correct IP</p>
    </body>
</html>`

	//	授权IP中间件
	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
			return true
		}
		data, err := public.Rconfigfile("./config/sysconfig.json")
		if err != nil {
			return true
		}
		clientIp := core.GetClientIpFromRequest(r)
		if allowIps, ok := data["accept_ip"].([]interface{}); ok {
			if len(allowIps) == 0 {
				return true
			}
			for _, ip := range public.InterfaceArray_To_StringArray(allowIps) {
				if clientIp == ip {
					return true
				}
			}
		}
		errHtml := ipErrorHtmlCN
		if core.Language() == language.EN {
			errHtml = ipErrorHtmlEN
		}

		err = core.Html(errHtml).WriteResponse(w, 403)
		if err != nil {
			logging.Info("响应失败：", err)
		}
		return false
	})

	hostErrorHtmlCN := `<!doctype html>
<html lang="zh">
    <head>
        <meta charset="utf-8">
        <title>访问被拒绝</title>
    </head>
    <body>
        <h1>你的请求已经被拒绝</h1>
        <p>拒绝原因：</p>
        <p>没有使用正确的域名进行访问</p>
    </body>
</html>`

	hostErrorHtmlEN := `<!doctype html>
<html lang="zh">
    <head>
        <meta charset="utf-8">
        <title>Access Denied</title>
    </head>
    <body>
        <h1>Your request has been denied</h1>
        <p>Reason:</p>
        <p>Access is not being done using the correct HOST</p>
    </body>
</html>`

	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
			return true
		}
		data, err := public.Rconfigfile("./config/sysconfig.json")

		if err != nil {
			return true
		}
		allow_domain := strings.TrimSpace(public.InterfaceToString(data["accept_domain"]))
		if allow_domain == "" || core.GetHostFromRequest(r) == allow_domain {
			return true
		}
		errHtml := hostErrorHtmlCN
		if core.Language() == language.EN {
			errHtml = hostErrorHtmlEN
		}
		err = core.Html(errHtml).WriteResponse(w, 403)

		if err != nil {
			logging.Info("响应失败：", err)
		}
		return false
	})

	srv.Before(srv.AuthMiddleware)

	srv.Before(func(w http.ResponseWriter, r *http.Request) bool {
		if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
			return true
		}
		return access.RbacManager.IsAllowed(public.GetUid(r), r.URL.Path)
	})
}

func main() {
	if len(os.Args) > 1 {
		cli.Exec(os.Args[1:])
		return
	}
	defer func() {
		if err := recover(); err != nil {
			logging.Error(common.PanicTrace(err))
			logging.Error("服务启动时检测到PANIC错误，正在尝试重启...")
			time.Sleep(100 * time.Millisecond)

			main()
		}
	}()
	public.StartSchedulerAsync()
	providers.Provide()
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)
	fl := flock.New(core.AbsPath("./data/.lock"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked, err := fl.TryLockContext(ctx, 678*time.Millisecond)

	if err != nil {
		fmt.Println("Web服务启动失败：", err)
		return
	}

	if !locked {
		fmt.Println("Web服务启动失败：获取文件锁失败")
		return
	}
	defer fl.Unlock()

	pidFile := core.AbsPath("./data/.pid")

	core.RecoveryGo(func() {
		<-ch
		_ = fl.Unlock()
		_ = os.Remove(pidFile)

		os.Exit(0)
	}).Run(nil)

	core.RecoveryGo(func() {
		time.Sleep(1 * time.Second)
		if err == nil {
			_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
			log.Println("Web服务启动成功，监听端口: ", core.GetServerPort())
		}
		_ = fl.Unlock()
	}).Run(nil)

	func() {
		if _, err := os.Stat(pidFile); err != nil {
			return
		}
		bs, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(string(bs))
		if err != nil {
			return
		}
		proc, err := process.NewProcess(int32(pid))
		if err != nil {
			return
		}
		var killAll func(p *process.Process)
		killAll = func(p *process.Process) {
			childs, err := p.Children()
			if err != nil && !strings.Contains(err.Error(), "exit status") {
				return
			}
			for _, v := range childs {
				killAll(v)
			}
			_ = p.Kill()
		}
		killAll(proc)
		time.Sleep(100 * time.Millisecond)
	}()

	srv := core.Server{
		StaticFs:           staticFs,                              // 静态文件
		CertificatePemFile: core.AbsPath("./ssl/certificate.pem"), // SSL证书(文件路径)
		PrivateKeyPemFile:  core.AbsPath("./ssl/privateKey.pem"),  // 证书密钥(文件路径)
	}
	registerMiddlewares(&srv)
	err = nil
	err = srv.Run()
	if err != nil {
		log.Println("Web服务启动失败：", err)
	}
}
