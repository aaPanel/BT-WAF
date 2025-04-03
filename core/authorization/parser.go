package authorization

import (
	"CloudWaf/core/common"
	"CloudWaf/public/encryption"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	TYPE_FREE       = 0
	TYPE_PROFESSION = 1
	TYPE_ULTIMATE   = 2
	TYPE_ENTEPRISE  = 3
)

var (
	licenseFile   = common.AbsPath("./data/.btwaf.license")
	publicKeyPath = common.AbsPath("./data/.pk")
	siteMapEach   = map[int]map[string]int{
		TYPE_FREE: {
			"location": 0,
			"smart_cc": 0,
			"idc":      0,
			"hvv":      0,
		},
		TYPE_PROFESSION: {
			"location": 3,
			"smart_cc": 1,
			"idc":      1,
			"hvv":      1,
		},
		TYPE_ULTIMATE: {
			"location": 15,
			"smart_cc": 5,
			"idc":      5,
			"hvv":      5,
		},
		TYPE_ENTEPRISE: {
			"location": -1,
			"smart_cc": -1,
			"idc":      -1,
			"hvv":      -1,
		},
	}
)

type ExtraInfo struct {
	Type     int `json:"type"`
	Sites    int `json:"site"`
	SmartCc  int `json:"smart_cc"`
	Location int `json:"location"`
}

type AuthInfo struct {
	Menu    []string       `json:"menu"`
	Pages   []string       `json:"pages"`
	Apis    []string       `json:"apis"`
	Extra   ExtraInfo      `json:"extra"`
	SiteMap map[string]int `json:"site_map"`
}

type Authorization struct {
	Product          string   `json:"product"`
	Uid              string   `json:"uid"`
	Phone            string   `json:"phone"`
	AuthId           string   `json:"auth_id"`
	ServerId         string   `json:"server_id"`
	Auth             AuthInfo `json:"auth"`
	EndTime          int64    `json:"end_time"`
	validateHandlers map[string]func(r *http.Request, au *Authorization) error
	mutex            sync.RWMutex
}

func NewAuthorization() *Authorization {
	return &Authorization{
		Product:  "cloud_waf",
		ServerId: strings.Repeat(SID(), 2),
	}
}

func (au *Authorization) ParseLicense() (err error) {
	var (
		publicKey       string
		updatePublicKey bool
	)

	if _, err = os.Stat(licenseFile); err != nil {
		return errors.New("License not found")
	}
	bs, err := os.ReadFile(licenseFile)

	if err != nil {
		return err
	}
	auBytes := make([]byte, base64.StdEncoding.DecodedLen(len(bs)))
	n, err := base64.StdEncoding.Decode(auBytes, bs)

	if err != nil {
		return err
	}
	parts := strings.Split(string(auBytes[:n]), ".")
	partSize := len(parts)
	if partSize < 3 {
		return errors.New("Invalid Authorization: Incorrect Structure")
	}
	if partSize == 4 {
		publicKey = parts[2]
		updatePublicKey = true
	} else {
		if _, err = os.Stat(publicKeyPath); err != nil {
			return err
		}
		bs, err = os.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
		publicKey = string(bs)
	}
	if ok := encryption.RsaVerify(strings.Join(parts[:partSize-1], "."), parts[partSize-1], publicKey); !ok {
		return errors.New("Invalid Authorization: Incorrect Signature")
	}
	aesKey, err := encryption.AesDecrypt(parts[1], publicKey[:32])

	if err != nil {
		return err
	}
	authInfoStr, err := encryption.AesDecrypt(parts[0], aesKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(authInfoStr), au)
	if err != nil {
		return err
	}
	if updatePublicKey {
		if err = os.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
			return err
		}
	}
	if v, ok := siteMapEach[au.Auth.Extra.Type]; ok {
		common.MapToStruct(v, &au.Auth.SiteMap)
	}

	return nil
}

func (au *Authorization) Validate() error {
	if au.ServerId != SID() {
		au.Reset()
		return errors.New("Invalid Authorization: Invalid ServerId")
	}
	if au.EndTime <= time.Now().Unix() {
		au.Reset()
		return errors.New("Invalid Authorization: Expired")
	}

	return nil
}

func (au *Authorization) Reset() {
	au.Uid = ""
	au.Phone = ""
	au.AuthId = ""
	au.EndTime = 0
	au.Auth = AuthInfo{}
}

func (au *Authorization) VerifyApi(uri string, r *http.Request) error {
	uri = strings.TrimPrefix(uri, "/api/")
	flag := false

	for _, v := range au.Auth.Apis {
		if uri == v {
			flag = true
			break
		}
		if strings.HasSuffix(v, "*") && strings.HasPrefix(uri, strings.TrimRight(v, "*")) {
			flag = true
			break
		}
	}

	if flag {
		return au.validateWithHandler(uri, r)
	}
	return errors.New("Access Denied: UnAuthorization")
}

func (au *Authorization) RegisterValidateHandler(uri string, handler func(r *http.Request, au *Authorization) error) {
	au.mutex.Lock()
	defer au.mutex.Unlock()

	if au.validateHandlers == nil {
		au.validateHandlers = make(map[string]func(r *http.Request, au *Authorization) error)
	}

	au.validateHandlers[uri] = handler
}

func (au *Authorization) validateWithHandler(uri string, r *http.Request) error {
	au.mutex.RLock()
	if au.validateHandlers == nil {
		au.mutex.RUnlock()
		return nil
	}
	f, ok := au.validateHandlers[uri]
	au.mutex.RUnlock()
	if !ok {
		return nil
	}
	return f(r, au)
}

func ParseLicense(license []byte, publicKey string) (authorization *Authorization, err error) {
	var (
		updatePublicKey bool
	)
	bs := make([]byte, base64.StdEncoding.DecodedLen(len(license)))
	n, err := base64.StdEncoding.Decode(bs, license)

	if err != nil {
		return authorization, err
	}

	parts := strings.Split(string(bs[:n]), ".")
	partSize := len(parts)
	if partSize < 3 {
		return authorization, errors.New("Invalid Authorization: Incorrect Structure")
	}
	if publicKey == "" {
		if partSize == 4 {
			publicKey = parts[2]
			updatePublicKey = true
		} else {
			if _, err = os.Stat(publicKeyPath); err != nil {
				return authorization, err
			}
			bs, err = os.ReadFile(publicKeyPath)
			if err != nil {
				return authorization, err
			}
			publicKey = string(bs)
		}
	} else {
		updatePublicKey = true
	}
	if ok := encryption.RsaVerify(strings.Join(parts[:partSize-1], "."), parts[partSize-1], publicKey); !ok {
		return authorization, errors.New("Invalid Authorization: Incorrect Signature")
	}
	aesKey, err := encryption.AesDecrypt(parts[1], publicKey[:32])
	if err != nil {
		return authorization, err
	}
	authInfoStr, err := encryption.AesDecrypt(parts[0], aesKey)
	if err != nil {
		return authorization, err
	}
	authorization = &Authorization{}
	err = json.Unmarshal([]byte(authInfoStr), &authorization)
	if err != nil {
		return authorization, err
	}
	if updatePublicKey {
		if err = os.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
			return authorization, err
		}
	}
	if v, ok := siteMapEach[authorization.Auth.Extra.Type]; ok {
		common.MapToStruct(v, &authorization.Auth.SiteMap)
	}

	return authorization, err
}

func SaveLicenseFile(license []byte) error {
	fp, err := os.OpenFile(licenseFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)

	if err != nil {
		return err
	}

	defer fp.Close()

	if _, err = fp.Write(license); err != nil {
		return err
	}

	return nil
}

func UnsetLicenseFile() error {
	return os.Remove(licenseFile)
}
