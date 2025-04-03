package core

import (
	"CloudWaf/core/authorization"
	"CloudWaf/core/cache"
	"CloudWaf/core/common"
	"CloudWaf/core/logging"
	"CloudWaf/public/validate"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

var (
	registryObj      = &Registry{}
	authorizationObj = authorization.NewAuthorization()
)

type RecoveryGoroutine struct {
	handler      *reflect.Value
	args         []reflect.Value
	panicHandler func()
	deferHandler func()
}

func (rg *RecoveryGoroutine) Defer(deferHandler func()) *RecoveryGoroutine {
	rg.deferHandler = deferHandler
	return rg
}

func (rg *RecoveryGoroutine) Run(panicHandler func()) {
	if panicHandler != nil {
		rg.panicHandler = panicHandler
	}
	if rg.handler == nil {
		return
	}
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Error(PanicTrace(err))
				if rg.panicHandler != nil {
					rg.panicHandler()
				}
			}
			if rg.deferHandler != nil {
				rg.deferHandler()
			}
		}()
		rg.handler.Call(rg.args)
	}()
}

type RecoveryGoroutineGroup struct {
	recoveryGoroutines []*RecoveryGoroutine
	panicHandler       func()
	wg                 sync.WaitGroup
	ch                 chan struct{}
}

func (rg *RecoveryGoroutineGroup) Concurrent(n int) *RecoveryGoroutineGroup {
	if n > 0 && rg.ch == nil {
		rg.ch = make(chan struct{}, n)
	}
	return rg
}

func (rg *RecoveryGoroutineGroup) Panic(panicHandler func()) *RecoveryGoroutineGroup {
	rg.panicHandler = panicHandler
	return rg
}

func (rg *RecoveryGoroutineGroup) Immediate(handler any, args ...any) {
	var chExists bool
	if rg.ch != nil {
		rg.ch <- struct{}{}
		chExists = true
	}
	rg.wg.Add(1)
	RecoveryGo(handler, args...).Defer(func() {
		rg.wg.Done()
		if chExists {
			<-rg.ch
		}
	}).Run(rg.panicHandler)
}

func (rg *RecoveryGoroutineGroup) Add(handler any, args ...any) {
	rg.recoveryGoroutines = append(rg.recoveryGoroutines, RecoveryGo(handler, args...))
}

func (rg *RecoveryGoroutineGroup) Run(panicHandler func()) {
	if panicHandler != nil {
		rg.panicHandler = panicHandler
	}
	defer rg.wg.Wait()
	if len(rg.recoveryGoroutines) == 0 {
		return
	}
	for _, r := range rg.recoveryGoroutines {
		chExists := false
		if rg.ch != nil {
			rg.ch <- struct{}{}
			chExists = true
		}

		rg.wg.Add(1)
		r.Defer(func() {
			rg.wg.Done()
			if chExists {
				<-rg.ch
			}
		}).Run(rg.panicHandler)
	}
}

func (rg *RecoveryGoroutineGroup) Wait() {
	rg.wg.Wait()
}

func (rg *RecoveryGoroutineGroup) Done() chan struct{} {
	ch := make(chan struct{})
	go func() {
		rg.Wait()
		ch <- struct{}{}
	}()

	return ch
}

func RegisterModule(m interface{}) {
	registryObj.RegisterMethods(m)
}

func PatchModuleAction(module, action string, f any) {
	registryObj.Patch(module, action, f)
}

func UnpatchAllModuleAction() {
	registryObj.UnpatchAll()
}

func CallModuleAction(module, action string, args interface{}) (interface{}, error) {
	return registryObj.Call(module, action, args)
}

func CallModuleActionSimulate(module, action string, args any) (Response, error) {
	req, err := common.NewRequestWithJson(args)
	if err != nil {
		return nil, err
	}
	res, err := registryObj.Call(module, action, req)
	if err != nil {
		return nil, err
	}
	if v, ok := res.(Response); ok {
		return v, nil
	}
	return nil, errors.New("API模块没有正确响应")
}

func CallModuleActionSimulateAssertJson(module, action string, args any) (*JsonResponse, error) {
	resp, err := CallModuleActionSimulate(module, action, args)
	if err != nil {
		return nil, err
	}
	if v, ok := resp.(*JsonResponse); ok {
		return v, nil
	}
	return nil, errors.New("API模块没有正确响应JSON")
}

func AfterModuleActionCall(module, action string, handler func()) {
	registryObj.After(module, action, handler)
}

func FilterParamsSimple(params interface{}) interface{} {
	switch v := params.(type) {
	case map[string]interface{}:
		for k := range v {
			v[k] = FilterParamsSimple(v[k])
		}
		return v
	case []interface{}:
		for k := range v {
			v[k] = FilterParamsSimple(v[k])
		}
		return v
	case string:
		return strings.TrimSpace(v)
	default:
		return v
	}
}

func GetParamsFromRequest(request *http.Request) (map[string]interface{}, error) {
	var err error

	result := make(map[string]interface{})
	err = request.ParseForm()
	if err == nil {
		for k, vs := range request.Form {
			if len(vs) == 0 {
				result[k] = ""
				continue
			}
			result[k] = vs[0]
		}
		for k, vs := range request.PostForm {
			if len(vs) == 0 {
				result[k] = ""
				continue
			}
			result[k] = vs[0]
		}
	}
	ct := strings.ToLower(request.Header.Get("Content-Type"))
	if ct != "" {
		ct = strings.TrimSpace(strings.Split(ct, ";")[0])
	}
	if ct == "application/json" {
		err = json.NewDecoder(request.Body).Decode(&result)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("解析请求参数JSON失败：%s", err))
		}
	}
	FilterParamsSimple(result)
	return result, nil
}

func GetParamsFromRequestToStruct(request *http.Request, obj any) error {
	params, err := GetParamsFromRequest(request)
	if err != nil {
		return err
	}
	return MapToStruct(params, obj)
}

func GetClientIpFromRequest(request *http.Request) (clientIp string) {
	return request.RemoteAddr
}

func GetClientPortFromRequest(request *http.Request) (clientPort int) {
	_, port, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		return 0
	}
	clientPort, err = strconv.Atoi(port)
	if err != nil {
		return 0
	}
	if clientPort < 1 || clientPort > 65535 {
		return 0
	}
	return clientPort
}

func GetHostFromRequest(request *http.Request) (host string) {
	host = strings.TrimSpace(request.Host)

	if host == "" || !validate.IsHost(host) {
		host = strings.TrimSpace(request.URL.Hostname())
	}

	if host == "" || !validate.IsHost(host) {
		serverIp, _ := GetServerIp()
		port := GetServerPort()
		host = serverIp + ":" + port
	}

	h, _, err := net.SplitHostPort(host)

	if err != nil {
		return "127.0.0.1"
	}

	return h
}

func GetSessionKey(request *http.Request) string {
	ck, err := request.Cookie(authorization.SID())
	if err != nil {
		return ""
	}
	return ck.Value
}

func SetSessionWithKey(sessionKey string, key string, value any) error {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return errors.New("session not setting")
	}
	session := &types.Session{}
	if cache.Has(cache.SessionPrefix + sessionKey) {
		val := cache.Get(cache.SessionPrefix + sessionKey)

		if val != nil {
			if err := MapToStruct(val, session); err != nil {
				return err
			}
		}
	}
	m := make(map[string]any)
	m[key] = value
	if err := MapToStruct(m, session); err != nil {
		return err
	}
	return cache.Set(cache.SessionPrefix+sessionKey, session, 86400)
}

func SetSession(request *http.Request, key string, value any) error {
	sessionKey := GetSessionKey(request)
	if sessionKey == "" {
		return errors.New("session not setting")
	}
	return SetSessionWithKey(sessionKey, key, value)
}

func GetSession(request *http.Request) (*types.Session, error) {
	sessionKey := GetSessionKey(request)
	if sessionKey == "" {
		return nil, errors.New("session not setting")
	}
	if !cache.Has(cache.SessionPrefix + sessionKey) {
		return nil, errors.New("session is expired")
	}
	val := cache.Get(cache.SessionPrefix + sessionKey)
	if val == nil {
		return nil, errors.New("invalid session")
	}
	session := &types.Session{}
	if err := MapToStruct(val, session); err != nil {
		return nil, err
	}
	return session, nil
}

func HasSuffixWithSlice(s string, suffixSlice []string) bool {
	return common.HasSuffixWithSlice(s, suffixSlice)
}

func SnakeCase(s string) string {
	return common.SnakeCase(s)
}

func LocateRecursive(params interface{}) interface{} {
	return common.LocateRecursive(params)
}

func PanicTrace(err interface{}) string {
	return common.PanicTrace(err)
}

func Auth() (*authorization.Authorization, error) {
	if err := authorizationObj.Validate(); err == nil {
		return authorizationObj, nil
	}
	err := authorizationObj.ParseLicense()
	if err != nil {
		return authorizationObj, err
	}
	err = authorizationObj.Validate()
	if err != nil {
		return authorizationObj, err
	}
	return authorizationObj, nil
}

func StructToMap(obj any) (data map[string]any) {
	return common.StructToMap(obj)
}

func MapToStruct(m any, obj any) (err error) {
	return common.MapToStruct(m, obj)
}

func GetRunDir() string {
	return common.GetRunDir()
}

func AbsPath(p string) string {
	return common.AbsPath(p)
}

func RecoveryGo(handler any, args ...any) *RecoveryGoroutine {

	pv, argValues := common.ReflectFunction(handler, args...)

	return &RecoveryGoroutine{
		handler: pv,
		args:    argValues,
	}
}

func NewRecoveryGoGroup(concurrent int) *RecoveryGoroutineGroup {
	return (&RecoveryGoroutineGroup{}).Concurrent(concurrent)
}

func WrapHandler(handler any, args ...any) func() {
	pv, argValues := common.ReflectFunction(handler, args...)
	return func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Error(PanicTrace(err))
			}
		}()

		pv.Call(argValues)
	}
}
