package jwt

import (
	"CloudWaf/core/cache"
	"CloudWaf/core/logging"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type BlackList struct {
	mutex sync.RWMutex
}

func (blackList *BlackList) Init() {
	err := blackList.loadFromFile()
	if err != nil {
		logging.Info("从持久化数据中加载JWT黑名单失败：", err)
	}
}

func (blackList *BlackList) Add(token Token) error {
	jti, err := token.GetPayload("jti")
	if err != nil {
		return err
	}
	exp, err := token.GetPayload("exp")
	if err != nil {
		return err
	}
	timeout := exp.Value().(int64) - time.Now().Unix()
	if timeout < 1 {
		return errors.New("Token is expired")
	}
	cacheKey := blackList.buildKey(jti.Value().(string))
	if cache.Has(cacheKey) {
		return nil
	}
	err = cache.Set(cacheKey, nil, timeout)
	if err != nil {
		return err
	}
	return blackList.addToFile(jti.Value().(string), timeout)
}

func (blackList *BlackList) Has(token Token) bool {
	jti, err := token.GetPayload("jti")
	if err != nil {
		return false
	}
	return cache.Has(fmt.Sprintf("JWT_BLACK_LIST:%s", jti.Value()))
}

func (blackList *BlackList) buildKey(jti string) string {
	return fmt.Sprintf("JWT_BLACK_LIST:%s", jti)
}

func (blackList *BlackList) ensureFileCreated() error {
	if err := os.MkdirAll(filepath.Dir(blacklistFile), 0644); err != nil {
		return err
	}
	_, err := os.Stat(blacklistFile)
	if err != nil {
		blackList.mutex.Lock()
		defer blackList.mutex.Unlock()
		_, err = os.Stat(blacklistFile)
		if err != nil {
			return os.WriteFile(blacklistFile, []byte{}, 0644)
		}
	}
	return nil
}

func (blackList *BlackList) addToFile(jti string, timeout int64) (err error) {
	err = blackList.ensureFileCreated()
	if err != nil {
		return err
	}
	blackList.mutex.Lock()
	defer blackList.mutex.Unlock()
	fp, err := os.OpenFile(blacklistFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = fp.WriteString(fmt.Sprintf("%d %s\n", time.Now().Unix()+timeout, jti))

	return err
}

func (blackList *BlackList) loadFromFile() (err error) {
	err = blackList.ensureFileCreated()
	if err != nil {
		return err
	}
	blackList.mutex.Lock()
	defer blackList.mutex.Unlock()

	fp, err := os.OpenFile(blacklistFile, os.O_RDWR, 0644)

	if err != nil {
		return err
	}
	defer fp.Close()
	curTime := time.Now().Unix()
	reader := bufio.NewReader(fp)
	buf := &bytes.Buffer{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		endtime, err := strconv.Atoi(parts[0])
		if err != nil || int64(endtime) <= curTime {
			continue
		}
		buf.WriteString(fmt.Sprintf("%s\n", line))
		cache.Set(blackList.buildKey(parts[1]), nil, int64(endtime)-curTime)
	}
	fp.Truncate(0)
	fp.Seek(0, 0)
	_, err = fp.Write(buf.Bytes())

	return err
}
