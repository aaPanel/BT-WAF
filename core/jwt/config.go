package jwt

import (
	"CloudWaf/core/cache"
	"CloudWaf/core/common"
	"CloudWaf/core/logging"
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	PREFIX     = "bt"
	HEADER_KEY = "Authorization"
)

var (
	configFile    = common.AbsPath("./config/sysconfig.json")
	secretFile    = common.AbsPath("./data/.jwt-secret")
	blacklistFile = common.AbsPath("./data/.jwt-blacklist")
	SecretKey     string
	blackList     = &BlackList{}
)

func init() {
	blackList.Init()
	loadJwtSecret()
}

func TTL() (ttl int64) {
	ttl = 120
	cacheKey := "JWT_TTL"
	if cache.Has(cacheKey) {
		if v, ok := cache.Get(cacheKey).(int64); ok {
			return v
		}
	}
	if err := os.MkdirAll(filepath.Dir(configFile), 0644); err != nil {
		return ttl
	}
	context, err := os.ReadFile(configFile)
	if err != nil {
		return ttl
	}
	data := make(map[string]interface{})
	err = json.Unmarshal(context, &data)
	if err != nil {
		return ttl
	}
	if timeout, ok := data["session_timeout"].(float64); ok {
		ttl = int64(timeout)
	}
	if err = cache.Set(cacheKey, ttl, 60); err != nil {
		logging.Info("缓存会话过期时间失败：", err)
	}
	return ttl
}

func loadJwtSecret() {
	os.MkdirAll(filepath.Dir(secretFile), 0644)
	_, err := os.Stat(secretFile)
	if err != nil {
		SecretKey, err = RandomStr(64)
		if err != nil {
			SecretKey = RandomStr2(64)
		}
		err = os.WriteFile(secretFile, []byte(SecretKey), 0644)
		if err != nil {
			logging.Info("持久化JWT签名密钥失败：", err)
		}
	}
	if SecretKey == "" {
		bs, err := os.ReadFile(secretFile)
		if err != nil {
			SecretKey, err = RandomStr(64)

			if err != nil {
				SecretKey = RandomStr2(64)
			}
		}
		SecretKey = string(bs)
	}
}
