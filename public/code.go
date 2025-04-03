package public

import (
	"CloudWaf/core"
	"encoding/json"
	"errors"
	"image/color"
	"os"
	"time"

	"github.com/mojocn/base64Captcha"
)

var (
	codeDefaultConfigFile = core.AbsPath("./config/code.json")
	codeDefaultConfig     *base64Captcha.DriverString
)

func init() {
	_, err := os.Stat(codeDefaultConfigFile)
	if err != nil {
		codeDefaultConfig = &base64Captcha.DriverString{
			Height:          50,
			Width:           200,
			NoiseCount:      0,
			ShowLineOptions: base64Captcha.OptionShowHollowLine,
			Length:          4,
			Source:          "34578abcdefhjkmnprstuvwxy",
			BgColor: &color.RGBA{
				R: 40,
				G: 30,
				B: 89,
				A: 29,
			},
			Fonts: nil,
		}
		fp, err := os.OpenFile(codeDefaultConfigFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return
		}
		defer fp.Close()
		err = json.NewEncoder(fp).Encode(codeDefaultConfig)
		if err != nil {
			return
		}
	}
	fp, err := os.Open(codeDefaultConfigFile)
	if err != nil {
		return
	}
	defer fp.Close()
	err = json.NewDecoder(fp).Decode(&codeDefaultConfig)
	if err != nil {
		return
	}
}

type CodeInfo struct {
	CodeDriver *base64Captcha.DriverString
}

func SetCodeResult(DataSize int, Errxpiration time.Duration) base64Captcha.Store {
	return base64Captcha.NewMemoryStore(DataSize, Errxpiration)
}

func DefaultConfig() *base64Captcha.DriverString {
	return codeDefaultConfig

}

func CreatStringCode(ConfigDriver *base64Captcha.DriverString, CodeResult base64Captcha.Store) (string, string, error) {
	codeinfo := &CodeInfo{}
	if ConfigDriver == nil {
		codeinfo.CodeDriver = DefaultConfig()
	} else {
		codeinfo.CodeDriver = ConfigDriver
	}
	if CodeResult == nil {
		CodeResult = base64Captcha.NewMemoryStore(20000, time.Minute*3)
	}
	if codeinfo.CodeDriver == nil {
		return "", "", errors.New("生成验证码失败")
	}
	c := base64Captcha.NewCaptcha(codeinfo.CodeDriver, CodeResult)
	id, answer, err := c.Generate()
	return id, answer, err
}

func CheckCode(result base64Captcha.Store, id, VerifyValue string) bool {

	return result.Verify(id, VerifyValue, true)
}

func GetCode(result base64Captcha.Store, codeId string) string {
	return result.Get(codeId, false)
}
