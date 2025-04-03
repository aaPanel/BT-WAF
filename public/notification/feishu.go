package notification

import (
	"CloudWaf/public"
	"CloudWaf/public/validate"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

type FeiShu struct {
	Url string `json:"url"`
}

func NewFeiShuNotifier() *FeiShu {
	return &FeiShu{}
}

func (f *FeiShu) Notify(message Message) error {
	bs, err := json.Marshal(map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": message.Text() + "<at userid='all'>所有人</at>",
		},
	})

	if err != nil {
		return err
	}

	result, err := public.HttpPostJson(f.Url, string(bs), 60)

	if err != nil {
		return err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal([]byte(result), &res)
	if err != nil {
		return err
	}
	if errcode, ok := res["code"].(float64); ok {
		if errcode != 0 {
			if errmsg, ok := res["msg"].(string); ok {
				return errors.New("[" + strconv.Itoa(int(errcode)) + "]" + errmsg)
			}

			return errors.New("发送飞书通知失败：未知错误")
		}
		return nil
	}

	return errors.New("发送飞书通知失败：未知错误")
}

func (f *FeiShu) IsConfigured() bool {
	f.Url = strings.TrimSpace(f.Url)

	if f.Url == "" {
		return false
	}
	if !validate.IsUrl(f.Url) {
		return false
	}

	return true
}

func (f *FeiShu) UpdateConfig() error {
	if !f.IsConfigured() {
		return errors.New("配置不正确")
	}

	return writeConfig()
}

func (f *FeiShu) ClearConfig() error {
	f.Url = ""
	return writeConfig()
}
