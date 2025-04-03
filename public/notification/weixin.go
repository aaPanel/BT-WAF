package notification

import (
	"CloudWaf/public"
	"CloudWaf/public/validate"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

type WeiXin struct {
	Url string `json:"url"`
}

func NewWeiXinNotifier() *WeiXin {
	return &WeiXin{}
}

func (w *WeiXin) Notify(message Message) error {
	bs, err := json.Marshal(map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": message.Text(),
		},
	})

	if err != nil {
		return err
	}
	result, err := public.HttpPostJson(w.Url, string(bs), 60)
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
			return errors.New("发送企业微信通知失败：未知错误")
		}
		return nil
	}
	return errors.New("发送企业微信通知失败：未知错误")
}

func (w *WeiXin) IsConfigured() bool {
	w.Url = strings.TrimSpace(w.Url)

	if w.Url == "" {
		return false
	}
	if !validate.IsUrl(w.Url) {
		return false
	}

	return true
}

func (w *WeiXin) UpdateConfig() error {
	if !w.IsConfigured() {
		return errors.New("配置不正确")
	}

	return writeConfig()
}

func (w *WeiXin) ClearConfig() error {
	w.Url = ""
	return writeConfig()
}
