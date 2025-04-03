package notification

import (
	"CloudWaf/public"
	"CloudWaf/public/validate"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

type DingDing struct {
	Url string `json:"url"`
}

func NewDingDingNotifier() *DingDing {
	return &DingDing{}
}

func (d *DingDing) Notify(message Message) error {
	bs, err := json.Marshal(map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": message.MailTitle(),
			"text":  message.DingDingText(),
		},
		"at": map[string]interface{}{
			"atMobiles": []string{},
			"isAtAll":   true,
		},
	})
	if err != nil {
		return err
	}
	result, err := public.HttpPostJson(d.Url, string(bs), 60)

	if err != nil {
		return err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal([]byte(result), &res)

	if err != nil {
		return err
	}
	if errcode, ok := res["errcode"].(float64); ok {
		if errcode != 0 {
			if errmsg, ok := res["errmsg"].(string); ok {
				return errors.New("[" + strconv.Itoa(int(errcode)) + "]" + errmsg)
			}
			return errors.New("发送钉钉通知失败：未知错误")
		}
		return nil
	}
	return errors.New("发送钉钉通知失败：未知错误")
}

func (d *DingDing) IsConfigured() bool {
	d.Url = strings.TrimSpace(d.Url)

	if d.Url == "" {
		return false
	}
	if !validate.IsUrl(d.Url) {
		return false
	}

	return true
}

func (d *DingDing) UpdateConfig() error {
	if !d.IsConfigured() {
		return errors.New("配置不正确")
	}

	return writeConfig()
}

func (d *DingDing) ClearConfig() error {
	d.Url = ""
	return writeConfig()
}
