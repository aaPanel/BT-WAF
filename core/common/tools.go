package common

import (
	"CloudWaf/core/language"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mRand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

var (
	isDev = false
)

func RandomStr(n int) (string, error) {
	bs := make([]byte, n)
	_, err := rand.Read(bs)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bs)[0:n], nil
}

func RandomStr2(n int) string {
	r := mRand.New(mRand.NewSource(time.Now().UnixNano()))
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	num := len(letterBytes)
	for i := range b {
		b[i] = letterBytes[r.Intn(num)]
	}
	return string(b)
}

func RandomStr3(n int) string {
	s, err := RandomStr(n)

	if err != nil {
		s = RandomStr2(n)
	}

	return s
}

func Base64UrlEncode(s string) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(s)), "=")
}

func Base64UrlDecode(s string) (string, error) {
	remainder := len(s) % 4
	if remainder > 0 {
		s += strings.Repeat("=", 4-remainder)
	}
	bs, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

func HasSuffixWithSlice(s string, suffixSlice []string) bool {
	for _, suffix := range suffixSlice {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}

	return false
}

func SnakeCase(s string) string {
	result := make([]byte, 0)
	num := len(s)
	result = append(result, s[0])
	for i := 1; i < num; i++ {
		d := s[i]
		if d >= 'A' && d <= 'Z' && ((s[i-1] >= 'A' && s[i-1] <= 'Z') || (s[i-1] >= 'a' && s[i-1] <= 'z')) {
			result = append(result, '_')
		}
		result = append(result, d)
	}
	return strings.ToLower(string(result))
}

func LocateRecursive(params interface{}) interface{} {
	switch v := params.(type) {
	case map[string]interface{}:
		for k := range v {
			v[k] = LocateRecursive(v[k])
		}
		return v
	case []interface{}:
		for k := range v {
			v[k] = LocateRecursive(v[k])
		}
		return v
	case string:
		return language.Locate(v)
	case []byte:
		return language.Locate(string(v))
	default:
		return v
	}
}

func PanicTrace(err interface{}) string {
	buf := new(bytes.Buffer)
	_, _ = fmt.Fprintf(buf, "%v\n", err)
	for i := 1; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		_, _ = fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
	}
	return buf.String()
}

func StructToMap(obj any) (data map[string]any) {
	data = make(map[string]any)
	objV := reflect.Indirect(reflect.ValueOf(obj))
	objT := objV.Type()
	if objT.Kind() == reflect.Map {
		return objV.Interface().(map[string]any)
	}
	numField := objT.NumField()
	for i := 0; i < numField; i++ {
		field, ok := objT.Field(i).Tag.Lookup("json")
		if ok {
			data[field] = objV.Field(i).Interface()
		} else {
			data[objT.Field(i).Name] = objV.Field(i).Interface()
		}
	}
	return data
}

func SliceToSliceMap(obj any) (data []map[string]any) {
	pv := reflect.Indirect(reflect.ValueOf(obj))
	if pv.Type().Kind() == reflect.Slice {
		size := pv.Len()
		for i := 0; i < size; i++ {
			data = append(data, StructToMap(pv.Index(i).Interface()))
		}
	}
	return data
}

func MapToStruct(m any, obj any) (err error) {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:  "json",
		Metadata: nil,
		Result:   obj,
	})
	if err != nil {
		return err
	}
	return decoder.Decode(m)
}

type DeepCopyInterface interface {
	DeepCopy() interface{}
}

func Copy(src interface{}) interface{} {
	if src == nil {
		return nil
	}
	original := reflect.ValueOf(src)
	cpy := reflect.New(original.Type()).Elem()
	copyRecursive(original, cpy)
	return cpy.Interface()
}

func copyRecursive(original, cpy reflect.Value) {
	if original.CanInterface() {
		if copier, ok := original.Interface().(DeepCopyInterface); ok {
			cpy.Set(reflect.ValueOf(copier.DeepCopy()))
			return
		}
	}
	switch original.Kind() {
	case reflect.Ptr:
		originalValue := original.Elem()
		if !originalValue.IsValid() {
			return
		}
		cpy.Set(reflect.New(originalValue.Type()))
		copyRecursive(originalValue, cpy.Elem())
	case reflect.Interface:
		if original.IsNil() {
			return
		}
		originalValue := original.Elem()
		copyValue := reflect.New(originalValue.Type()).Elem()
		copyRecursive(originalValue, copyValue)
		cpy.Set(copyValue)
	case reflect.Struct:
		t, ok := original.Interface().(time.Time)
		if ok {
			cpy.Set(reflect.ValueOf(t))
			return
		}
		for i := 0; i < original.NumField(); i++ {
			if original.Type().Field(i).PkgPath != "" {
				continue
			}
			copyRecursive(original.Field(i), cpy.Field(i))
		}
	case reflect.Slice:
		if original.IsNil() {
			return
		}
		cpy.Set(reflect.MakeSlice(original.Type(), original.Len(), original.Cap()))
		for i := 0; i < original.Len(); i++ {
			copyRecursive(original.Index(i), cpy.Index(i))
		}
	case reflect.Map:
		if original.IsNil() {
			return
		}
		cpy.Set(reflect.MakeMap(original.Type()))
		for _, key := range original.MapKeys() {
			originalValue := original.MapIndex(key)
			copyValue := reflect.New(originalValue.Type()).Elem()
			copyRecursive(originalValue, copyValue)
			copyKey := Copy(key.Interface())
			cpy.SetMapIndex(reflect.ValueOf(copyKey), copyValue)
		}
	default:
		cpy.Set(original)
	}
}

func GetRunDir() string {
	if len(os.Args) == 0 {
		p, _ := os.Getwd()
		return p
	}
	exePath := filepath.Dir(os.Args[0])
	if isDev || strings.Contains(filepath.ToSlash(exePath), "/go-build") {
		isDev = true
		p, _ := os.Getwd()
		return p
	}
	p, _ := filepath.Abs(exePath)
	return p
}

func AbsPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	if len(p) > 1 && p[1] == ':' {
		return p
	}
	return filepath.Join(GetRunDir(), p)
}

func TimeCost() func() {
	start := time.Now()

	return func() {
		tc := time.Since(start)
		fmt.Printf("Time cost = %v\n", tc)
	}
}

func Round(n float64, precision int) float64 {
	val, _ := strconv.ParseFloat(fmt.Sprintf("%."+strconv.Itoa(precision)+"f", n), 64)
	return val
}

func ReflectFunction(handler any, args ...any) (*reflect.Value, []reflect.Value) {
	pv := reflect.Indirect(reflect.ValueOf(handler))
	pt := pv.Type()
	if pt.Kind() != reflect.Func {
		panic("RecoveryGo() parameter handler must a function")
	}

	numIn := pt.NumIn()
	argNum := len(args)

	if numIn != argNum {
		panic(fmt.Sprintf("RecoveryGo() parameter handler function accept %d parameters, current %d parameters given", numIn, argNum))
	}

	argValues := make([]reflect.Value, 0)
	for i := 0; i < numIn; i++ {
		var argValue reflect.Value
		inType := pt.In(i)
		if args[i] == nil {
			argValue = reflect.ValueOf([]any{nil}).Index(0)
		} else {
			argValue = reflect.ValueOf(args[i])
		}
		if inType.Kind() == reflect.Interface {
			argValues = append(argValues, argValue)
			continue
		}
		argType := argValue.Type()
		if inType != argType {
			panic(fmt.Sprintf("参数类型错误：参数[%d]的类型应该为%s，实际类型为%s", i, inType, argType))
		}
		argValues = append(argValues, argValue)
	}
	return &pv, argValues
}

func NewRequestWithJson(jsonData any) (req *http.Request, err error) {
	bs, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequest("POST", "", bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json;charset=utf-8")

	return req, nil
}
