package logging

import (
	"CloudWaf/core/common"
	"CloudWaf/core/language"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	LOG_LEVEL_NONE  = 0
	LOG_LEVEL_DEBUG = 1
	LOG_LEVEL_INFO  = 2
	LOG_LEVEL_WARN  = 3
	LOG_LEVEL_ERROR = 4
)

var (
	loggingLevelFile = common.AbsPath("./data/.logging-level")
	loggingLevel     int
	logLevelTrans    = map[int]string{
		LOG_LEVEL_NONE:  "NONE",
		LOG_LEVEL_DEBUG: "DEBUG",
		LOG_LEVEL_INFO:  "INFO",
		LOG_LEVEL_WARN:  "WARN",
		LOG_LEVEL_ERROR: "ERROR",
	}
	loggerMap = make(map[string]*log.Logger)
)

func init() {
	loadLoggingLevel()
	initLoggerMap()
}

type dailyWriter struct {
	logType   string
	buffer    *bytes.Buffer
	mutex     sync.Mutex
	timer     *time.Timer
	delay     time.Duration
	threshold int
}

func (w *dailyWriter) Flush() (int, error) {
	if w.buffer.Len() == 0 {
		return 0, nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	logFile := genLogFileDaily(w.logType)
	err := os.MkdirAll(filepath.Dir(logFile), 0644)
	if err != nil {
		return 0, err
	}
	fp, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)

	if err != nil {
		return 0, err
	}
	defer func() {
		w.buffer.Reset()
		_ = fp.Close()
	}()
	return fp.Write(w.buffer.Bytes())
}

func (w *dailyWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer func() {
		w.mutex.Unlock()
		if w.buffer.Len() < w.threshold {
			_, _ = w.Flush()
		}
	}()
	return w.buffer.Write(data)
}

func initLoggerMap() {
	requestDailyWriter := &dailyWriter{
		logType:   "request",
		buffer:    &bytes.Buffer{},
		timer:     time.NewTimer(10 * time.Second),
		delay:     10 * time.Second,
		threshold: 2097152,
	}
	loggerMap["request"] = log.New(requestDailyWriter, "", 0)
	debugDailyWriter := &dailyWriter{
		logType:   "debug",
		buffer:    &bytes.Buffer{},
		timer:     time.NewTimer(3 * time.Second),
		delay:     3 * time.Second,
		threshold: 2097152,
	}

	loggerMap["debug"] = log.New(debugDailyWriter, "", log.LstdFlags)
	go func() {
		for {
			select {
			case <-requestDailyWriter.timer.C:
				_, _ = requestDailyWriter.Flush()
				requestDailyWriter.timer.Reset(requestDailyWriter.delay)
			case <-debugDailyWriter.timer.C:
				_, _ = debugDailyWriter.Flush()
				debugDailyWriter.timer.Reset(debugDailyWriter.delay)
			}
		}
	}()
}

func loadLoggingLevel() {
	_ = os.MkdirAll(filepath.Dir(loggingLevelFile), 0644)
	loggingLevel = LOG_LEVEL_ERROR
	_, err := os.Stat(loggingLevelFile)
	if err != nil {
		_ = os.WriteFile(loggingLevelFile, []byte(FlagToString(loggingLevel)), 0644)
		return
	}
	bs, err := os.ReadFile(loggingLevelFile)
	if err != nil {
		return
	}
	loggingLevel = StringToFlag(string(bs))
}

func SetLoggingLevel(level int) {
	if _, ok := logLevelTrans[level]; ok {
		loggingLevel = level
	}
}

func StringToFlag(levelStr string) int {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "none":
		return LOG_LEVEL_NONE
	case "debug":
		return LOG_LEVEL_DEBUG
	case "info":
		return LOG_LEVEL_INFO
	case "warn":
		return LOG_LEVEL_WARN
	case "error":
		return LOG_LEVEL_ERROR
	}

	return LOG_LEVEL_DEBUG
}

func FlagToString(level int) string {
	s, ok := logLevelTrans[level]

	if !ok {
		s = "DEBUG"
	}

	return strings.ToLower(s)
}

func RequestDaily(v ...any) {
	bs, err := json.Marshal(v)
	if err != nil {
		return
	}
	loggerMap["request"].Println(string(bs))
}

func Debug(v ...any) {
	Log(LOG_LEVEL_DEBUG, v...)
}

func Info(v ...any) {
	Log(LOG_LEVEL_INFO, v...)
}

func Warn(v ...any) {
	Log(LOG_LEVEL_WARN, v...)
}

func Error(v ...any) {
	Log(LOG_LEVEL_ERROR, v...)
}

func Log(level int, v ...any) {

	if loggingLevel == LOG_LEVEL_NONE || level < loggingLevel {
		return
	}
	vDup := make([]any, 0, len(v)+1)
	vDup = append(vDup, "["+logLevelTrans[level]+"]")
	for _, s := range v {
		switch vTmp := s.(type) {
		case string:
			vDup = append(vDup, language.Locate(vTmp))
		case []byte:
			vDup = append(vDup, language.Locate(string(vTmp)))
		default:
			vDup = append(vDup, vTmp)
		}
	}
	loggerMap["debug"].Println(vDup...)
}

func genLogFileDaily(logType string) string {
	return common.AbsPath("./logs/" + logType + "/" + time.Now().Format("200601/02.log"))
}

func daily(logFile string, logFlags int, v ...any) {
	err := os.MkdirAll(filepath.Dir(logFile), 0644)
	if err != nil {
		return
	}
	fp, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer fp.Close()
	log.New(fp, "", logFlags).Println(v...)
}
