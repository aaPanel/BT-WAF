package cache

import (
	"CloudWaf/core/common"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	SessionPrefix = "BTWAFSESS:_"
	sessionPath   = "./data/sessions"
)

var (
	storage          = make(map[string]interface{})
	expMap           = make(map[string]int64)
	mutex            = sync.RWMutex{}
	ch               = make(chan struct{})
	timeoutHooks     = make(map[string][]func())
	timeoutHookMutex = sync.Mutex{}
)

func init() {
	loadSession()

	go func() {
		lastTime := time.Now().Unix()
		delay := 1 * time.Minute
		timer := time.NewTimer(delay)
		removeKeys := make([]string, 0, 256)

		for {
			select {
			case <-ch:
			case <-timer.C:
				timer.Reset(delay)
			}
			curTime := time.Now().Unix()
			if curTime-lastTime < 3 {
				lastTime = curTime
				continue
			}
			removeKeys = removeKeys[:0]

			mutex.RLock()
			for k, exp := range expMap {
				if exp <= curTime {
					removeKeys = append(removeKeys, k)
				}
			}
			mutex.RUnlock()
			if len(removeKeys) > 0 {
				mutex.Lock()
				for _, k := range removeKeys {
					delete(storage, k)
					delete(expMap, k)
				}
				mutex.Unlock()
				hooks := make([]func(), 0, 256)
				timeoutHookMutex.Lock()
				for _, k := range removeKeys {
					if v, ok := timeoutHooks[k]; ok {
						for _, f := range v {
							hooks = append(hooks, f)
						}
						delete(timeoutHooks, k)
					}
				}
				timeoutHookMutex.Unlock()

				if len(hooks) > 0 {
					go func(hooks []func()) {
						for _, f := range hooks {
							func(f func()) {

								defer func() {
									recover()
								}()

								f()
							}(f)
						}
						hooks = hooks[:0]
					}(hooks)
				}
				removeKeys = removeKeys[:0]
			}
			lastTime = curTime
		}
	}()
}

type sessionItem struct {
	Expires int64       `json:"expires"`
	Value   interface{} `json:"value"`
}

func Set(key string, value interface{}, timeout int64, hooks ...func()) error {
	if timeout < 1 {
		return errors.New("timeout can't less then 1")
	}

	mutex.Lock()
	defer func() {
		mutex.Unlock()
		hookNum := len(hooks)
		if hookNum > 0 {
			timeoutHookMutex.Lock()
			delete(timeoutHooks, key)
			timeoutHooks[key] = make([]func(), 0, hookNum)
			for _, v := range hooks {
				if v != nil {
					timeoutHooks[key] = append(timeoutHooks[key], v)
				}
			}
			timeoutHookMutex.Unlock()
		}
	}()

	storage[key] = value
	expMap[key] = time.Now().Unix() + timeout

	if isSessionKey(key) {
		return sessionSet(key, value, timeout)
	}

	return nil
}

func Get(key string, defaultItem ...any) interface{} {
	if !Has(key) {

		if len(defaultItem) > 0 {
			return defaultItem[0]
		}
		return nil
	}
	mutex.RLock()
	defer mutex.RUnlock()
	return storage[key]
}

func Has(key string) bool {
	ch <- struct{}{}
	mutex.RLock()
	defer mutex.RUnlock()
	exp, ok := expMap[key]
	return ok && exp > time.Now().Unix()
}

func Remove(key string) error {
	if !Has(key) {
		return nil
	}
	mutex.Lock()
	defer func() {
		mutex.Unlock()
		timeoutHookMutex.Lock()
		delete(timeoutHooks, key)
		timeoutHookMutex.Unlock()
	}()
	if _, ok := storage[key]; ok {
		delete(storage, key)
		delete(expMap, key)
	}
	if isSessionKey(key) {
		return sessionRemove(key)
	}
	return nil
}

func Inc(key string) int {
	return StepOrSet(key, -1, 1)
}

func IncOrSet(key string, timeout int64) int {
	return StepOrSet(key, timeout, 1)
}

func Dec(key string) int {
	return StepOrSet(key, -1, -1)
}

func DecOrSet(key string, timeout int64) int {
	return StepOrSet(key, timeout, -1)
}

func StepOrSet(key string, timeout int64, step int) int {
	curTime := time.Now().Unix()

	if !Has(key) {
		if timeout < 1 {
			return 0
		}
		value := step
		mutex.Lock()
		if exp, exists := expMap[key]; !exists || exp <= curTime {
			storage[key] = value
			expMap[key] = time.Now().Unix() + timeout
			if isSessionKey(key) {
				_ = sessionSet(key, value, timeout)
			}
		} else {
			if v, ok := storage[key].(int); ok {
				value = v + step
				storage[key] = value
				if isSessionKey(key) {
					_ = sessionSet(key, value, expMap[key]-curTime)
				}
			}
		}
		mutex.Unlock()
		return value
	}

	mutex.Lock()
	defer mutex.Unlock()

	if v, ok := storage[key].(int); ok {
		v += step
		storage[key] = v
		if isSessionKey(key) {
			_ = sessionSet(key, v, expMap[key]-curTime)
		}

		return v
	}

	return 0
}

func isSessionKey(key string) bool {
	return strings.HasPrefix(key, SessionPrefix)
}

func sessionFilename(key string) string {
	return common.AbsPath(sessionPath + "/" + strings.TrimPrefix(key, SessionPrefix))
}

func sessionSet(key string, value interface{}, timeout int64) error {
	bs, err := msgpack.Marshal(sessionItem{
		Expires: time.Now().Unix() + timeout,
		Value:   value,
	})

	if err != nil {
		return err
	}

	return os.WriteFile(sessionFilename(key), bs, 0644)
}

func sessionRemove(key string) error {
	filename := sessionFilename(key)

	if _, err := os.Stat(filename); err != nil {
		return err
	}

	return os.Remove(filename)
}

func loadSession() {
	if err := os.MkdirAll(common.AbsPath(sessionPath), 0644); err != nil {
		return
	}
	curTime := time.Now().Unix()
	_ = filepath.Walk(common.AbsPath(sessionPath), func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		key := SessionPrefix + fi.Name()
		bs, err := os.ReadFile(path)
		if err != nil {
			_ = sessionRemove(key)
			return nil
		}
		sessItem := sessionItem{}
		if err = msgpack.Unmarshal(bs, &sessItem); err != nil {
			_ = sessionRemove(key)
			return nil
		}
		if sessItem.Expires <= curTime {
			_ = sessionRemove(key)
			return nil
		}
		_ = Set(key, sessItem.Value, sessItem.Expires-curTime)
		return nil
	})
}
