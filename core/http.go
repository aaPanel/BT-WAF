package core

import (
	"CloudWaf/core/jwt"
	"CloudWaf/core/logging"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var (
	staticFileSuffixList        = GetSupportedStaticFileSuffix()
	fullPathMiddlewareMap       = make(map[string][]func(w http.ResponseWriter, r *http.Request) bool)
	suffixWildcardMiddlewareMap = make(map[string][]func(w http.ResponseWriter, r *http.Request) bool)
	middlewareMapMutex          = sync.RWMutex{}
	specialPageFileTrans        = map[string]string{
		AbsPath("./static/index.html"): "static/index.html",
		AbsPath("./static/login.html"): "static/login.html",
	}
	apiWhiteSet = map[string]struct{}{}
)

type middleWare struct {
	handlers []func(w http.ResponseWriter, r *http.Request) bool
}

func (m *middleWare) Add(handler func(w http.ResponseWriter, r *http.Request) bool) {
	m.handlers = append(m.handlers, handler)
}

func (m *middleWare) Pipeline() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, f := range m.handlers {
			if !f(w, r) {
				break
			}
		}
	}
}

func (m *middleWare) Clear() {
	m.handlers = make([]func(w http.ResponseWriter, r *http.Request) bool, 0)
}

type errorLogWriter struct{}

func (w *errorLogWriter) Write(data []byte) (int, error) {
	ignoreSuffix := []string{
		"remote error: tls: unknown certificate",
		"first record does not look like a TLS handshake",
		"EOF",
	}
	for _, s := range ignoreSuffix {
		if strings.HasSuffix(strings.TrimSpace(string(data)), s) {
			return 0, nil
		}
	}
	return fmt.Printf("%s\n", data)
}

type fileSystems []http.FileSystem

func (fs fileSystems) Open(name string) (file http.File, err error) {
	for _, f := range fs {
		if file, err = f.Open(name); err == nil {
			return mutReaddirFile{file}, err
		}
	}
	return mutReaddirFile{file}, err
}

type mutReaddirFile struct {
	http.File
}

func (m mutReaddirFile) Stat() (fi os.FileInfo, err error) {
	fi, err = m.File.Stat()
	if err != nil {
		return fi, err
	}

	if fi.IsDir() {
	LOOP:
		for {
			fl, err := m.Readdir(2)
			switch err {
			case io.EOF:
				break LOOP
			case nil:
				for _, f := range fl {
					if f.Name() == "index.html" {
						return fi, err
					}
				}
			default:
				return fi, err
			}
		}
	}

	return fi, err
}

type Server struct {
	Addr                  string
	StaticFs              embed.FS
	CertificatePemFile    string
	PrivateKeyPemFile     string
	beforeRequestHandlers []func(w http.ResponseWriter, r *http.Request) bool
	afterRequestHandlers  []func(w http.ResponseWriter, r *http.Request) bool
	handlers              map[string]func(w http.ResponseWriter, r *http.Request)
	wsHandlers            map[string]websocket.Handler
	mutex                 sync.Mutex
}

func (s *Server) AuthMiddleware(w http.ResponseWriter, r *http.Request) bool {
	if authorized, ok := r.Context().Value("waf_authorized").(bool); ok && authorized {
		return true
	}
	uri := SnakeCase(r.URL.Path)

	if !strings.HasPrefix(uri, "/api/") {
		return true
	}

	if IgnoredApi(uri) {
		return true
	}

	_, err := jwt.ParseTokenWithRequest(r)
	if err != nil {
		err = Fail(err).WriteResponse(w, 401)
		if err != nil {
			logging.Info(uri, "响应失败：", err)
		}
		return false
	}

	return true
}

func (s *Server) afterRequest(w http.ResponseWriter, r *http.Request) bool {
	switch v := w.(type) {
	case *LoggingResponseWriter:
		clientIp := GetClientIpFromRequest(r)
		clientPort := GetClientPortFromRequest(r)
		logging.RequestDaily(time.UnixMilli(v.RequestTime).Format("2006-01-02 15:04:05"), r.Method, v.StatusCode, r.URL.Path, fmt.Sprintf("%s:%d", clientIp, clientPort), time.Now().UnixMilli()-v.RequestTime, v.RequestBuf.Len(), v.ResponseBuf.Len(), r.UserAgent())
	}
	return true
}

func (s *Server) Run() error {
	defer func() {
		if err := recover(); err != nil {
			logging.Error(PanicTrace(err))
			log.Println("检测到panic错误，正在尝试重启Web服务...")
			err = s.Run()
			if err != nil {
				log.Println("Web服务启动失败：", err)
			}
		}
	}()
	middlewarePool := &sync.Pool{
		New: func() any {
			return new(middleWare)
		},
	}
	fileHandler := http.FileServer(fileSystems{
		http.FS(s.StaticFs),
	})

	handler := func(w http.ResponseWriter, r *http.Request) {
		w = NewLoggingResponseWriter(w, r)
		err := DrainRequestBody(w.(*LoggingResponseWriter), r)
		if err != nil {
			logging.Info("拷贝请求内容失败：", err)
		}
		defer func() {
			if err := recover(); err != nil {
				panicTraceText := PanicTrace(err)
				logging.Error(panicTraceText)

				errText := "Internal Server Error"
				if IsDebug() {
					errText = panicTraceText
				}
				http.Error(w, errText, http.StatusInternalServerError)
			}
		}()

		middleware := middlewarePool.Get().(*middleWare)
		middleware.Clear()
		defer middlewarePool.Put(middleware)
		_, skipCommonMiddleware := apiWhiteSet[r.URL.Path]
		if !skipCommonMiddleware {
			for _, f := range s.beforeRequestHandlers {
				middleware.Add(f)
			}
		}
		for _, f := range matchMiddlewareWithUri(r.URL.Path) {
			middleware.Add(f)
		}
		middleware.Add(func(w http.ResponseWriter, r *http.Request) bool {
			gzipEnabled := false
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				gzipEnabled = true
			}
			uri := r.URL.Path
			if s.handlers != nil {
				if f, ok := s.handlers[uri]; ok {
					f(w, r)
					return true
				}
			}
			if strings.HasPrefix(uri, "/api/") {
				parts := strings.SplitN(uri, "/", 5)

				if len(parts) == 4 {
					module := parts[2]
					action := parts[3]
					response, err := CallModuleAction(module, action, r)
					if err != nil {
						if err = Fail(err).WriteResponse(w, 400); err != nil {
							logging.Info(uri, "响应失败：", err)
						}
						return true
					}
					statusCode := http.StatusOK
					switch v := response.(type) {
					case *JsonResponse:
						statusCode = v.StatusCode()
					case *DownloadResponse:
						gzipEnabled = false
					}

					if gzipEnabled {
						w.Header().Set("Content-Encoding", "gzip")
						gz := gzip.NewWriter(w)
						defer gz.Close()
						w = gzipResponseWriter{Writer: gz, ResponseWriter: w}
					}
					if err = response.(Response).WriteResponse(w, statusCode); err != nil {
						logging.Info(uri, "响应失败：", err)
					}
					return true
				}
			}
			if p, ok := ParseStaticResourcePath(r, false); ok {
				if _, ok := specialPageFileTrans[p]; !ok {
					w.Header().Set("Cache-Control", "public,max-age=31536000,immutable")
				}

				if gzipEnabled {
					if fp, err := os.Open(p + ".gz"); err == nil {
						defer fp.Close()
						if fi, err := fp.Stat(); err == nil {
							w.Header().Set("Content-Encoding", "gzip")
							filename := fi.Name()
							http.ServeContent(w, r, filename[:len(filename)-3], fi.ModTime(), fp)
							return true
						}
					}
				}
				if _, err := os.Stat(p); err == nil {
					http.ServeFile(w, r, p)
					return true
				}
				if v, ok := specialPageFileTrans[p]; ok {
					for i := 0; i < 1; i++ {
						fp, err := s.StaticFs.Open(v)
						if err != nil {
							break
						}
						defer fp.Close()
						fi, err := fp.Stat()
						if err != nil {
							break
						}
						bs, err := s.StaticFs.ReadFile(v)
						if err != nil {
							break
						}
						http.ServeContent(w, r, fi.Name(), fi.ModTime(), bytes.NewReader(bs))
						return true
					}
				}
				if gzipEnabled {
					for i := 0; i < 1; i++ {
						fName := uri[1:]
						fp, err := s.StaticFs.Open(fName + ".gz")
						if err != nil {
							break
						}
						fi, err := fp.Stat()
						if err != nil {
							break
						}
						bs, err := io.ReadAll(fp)
						if err != nil {
							break
						}
						w.Header().Set("Content-Encoding", "gzip")
						filename := fi.Name()
						http.ServeContent(w, r, filename[:len(filename)-3], fi.ModTime(), bytes.NewReader(bs))
						return true
					}
				}
				fileHandler.ServeHTTP(w, r)
				return true
			}

			err = Html(`<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`).WriteResponse(w, http.StatusNotFound)
			if err != nil {
				logging.Info(uri, "响应失败：", err)
			}
			return true
		})

		middleware.Pipeline()(w, r)
		middleware.Clear()
		if !skipCommonMiddleware {
			middleware.Add(s.afterRequest)
			for _, f := range s.afterRequestHandlers {
				middleware.Add(f)
			}
			middleware.Pipeline()(w, r)
		}
	}
	mux := http.NewServeMux()
	if s.wsHandlers != nil {
		for k, v := range s.wsHandlers {
			mux.Handle(k, v)
		}
	}
	mux.HandleFunc("/", handler)
	if s.Addr == "" {
		s.Addr = ":" + GetServerPort()
	}
	srv := &http.Server{
		Addr:    s.Addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		ErrorLog: log.New(&errorLogWriter{}, "", log.LstdFlags),
	}
	return srv.ListenAndServeTLS(s.CertificatePemFile, s.PrivateKeyPemFile)
}

func (s *Server) Before(handler func(w http.ResponseWriter, r *http.Request) bool) {
	s.beforeRequestHandlers = append(s.beforeRequestHandlers, handler)
}

func (s *Server) After(handler func(w http.ResponseWriter, r *http.Request) bool) {
	s.afterRequestHandlers = append(s.afterRequestHandlers, handler)
}

func (s *Server) Route(name string, handler func(w http.ResponseWriter, r *http.Request)) {
	name = strings.TrimSpace(name)

	if s.handlers == nil {
		s.mutex.Lock()
		if s.handlers == nil {
			s.handlers = make(map[string]func(w http.ResponseWriter, r *http.Request))
		}
		s.mutex.Unlock()
	}
	s.handlers[name] = handler
}

func (s *Server) Ws(name string, handler func(ws *websocket.Conn)) {
	if s.wsHandlers == nil {
		s.mutex.Lock()
		if s.wsHandlers == nil {
			s.wsHandlers = make(map[string]websocket.Handler)
		}
		s.mutex.Unlock()
	}
	s.wsHandlers[name] = func(ws *websocket.Conn) {
		defer func() {
			if err := recover(); err != nil {
				logging.Error(PanicTrace(err))
			}
			ws.Close()
		}()
		handler(ws)
	}
}

func RegisterMiddleware(uri string, handler func(w http.ResponseWriter, r *http.Request) bool) {
	middlewareMapMutex.Lock()
	defer middlewareMapMutex.Unlock()
	uri = SnakeCase(strings.TrimSpace(uri))
	if strings.HasSuffix(uri, "*") {
		uri = strings.TrimRight(uri, "*") + "*"
		if _, ok := suffixWildcardMiddlewareMap[uri]; !ok {
			suffixWildcardMiddlewareMap[uri] = make([]func(w http.ResponseWriter, r *http.Request) bool, 0)
		}
		suffixWildcardMiddlewareMap[uri] = append(suffixWildcardMiddlewareMap[uri], handler)
		return
	}
	if _, ok := fullPathMiddlewareMap[uri]; !ok {
		fullPathMiddlewareMap[uri] = make([]func(w http.ResponseWriter, r *http.Request) bool, 0)
	}
	fullPathMiddlewareMap[uri] = append(fullPathMiddlewareMap[uri], handler)
}

func matchMiddlewareWithUri(uri string) (handlers []func(w http.ResponseWriter, r *http.Request) bool) {
	middlewareMapMutex.RLock()
	defer middlewareMapMutex.RUnlock()
	uri = SnakeCase(strings.TrimSpace(uri))
	if v, ok := fullPathMiddlewareMap[uri]; ok {
		handlers = append(handlers, v...)
	}
	for k, v := range suffixWildcardMiddlewareMap {

		if strings.HasPrefix(uri, strings.TrimRight(k, "*")) {
			handlers = append(handlers, v...)
			break
		}
	}

	return handlers
}

func ReadWebSocketMessage(ws *websocket.Conn) (message string, err error) {
	reader, err := ws.NewFrameReader()
	if err != nil {
		return message, err
	}
	buf, err := io.ReadAll(reader)
	if err != nil {
		return message, err
	}
	if len(buf) == 0 {
		return message, errors.New("检测到WebSocket客户端已主动断开连接")
	}

	return string(buf), nil
}

func WriteWebSocketMessage(ws *websocket.Conn, message string) (err error) {
	_, err = io.WriteString(ws, message)
	if err != nil {
		return err
	}
	return nil
}

func ParseStaticResourcePath(r *http.Request, strict bool) (string, bool) {
	uri := r.URL.Path
	if r.Method == "GET" {
		if !strict {
			adminPath := AdminPath()
			if adminPath != "" && adminPath != "/" && uri == AdminPath() {
				if session, err := GetSession(r); err != nil || !session.IsLogin {
					uri = "/static/login.html"
				}
			}
			if !HasSuffixWithSlice(uri, staticFileSuffixList) {
				uri = "/static/index.html"
			}
		}
		slc := staticFileSuffixList[:]
		if strict {
			slc = slc[1:]
		}
		if strings.HasPrefix(uri, "/static/") && HasSuffixWithSlice(uri, slc) {
			return AbsPath("." + uri), true
		}
	}

	return "", false
}
