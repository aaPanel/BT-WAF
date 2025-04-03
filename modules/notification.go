package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/notification"
	"CloudWaf/public/validate"
	"errors"
	"net/http"
)

func init() {

	core.RegisterModule(&Notification{})
}

type Notification struct{}

func (n *Notification) List(request *http.Request) core.Response {
	email := notification.DefaultEmailNotifier()
	dingding := notification.DefaultDingDingNotifier()
	feishu := notification.DefaultFeiShuNotifier()
	weixin := notification.DefaultWeiXinNotifier()
	return core.Success([]interface{}{
		map[string]interface{}{
			"name":          "邮箱",
			"type":          "email",
			"is_configured": email.IsConfigured(),
			"config":        email,
		},
		map[string]interface{}{
			"name":          "钉钉",
			"type":          "dingding",
			"is_configured": dingding.IsConfigured(),
			"config":        dingding,
		},
		map[string]interface{}{
			"name":          "飞书",
			"type":          "feishu",
			"is_configured": feishu.IsConfigured(),
			"config":        feishu,
		},
		map[string]interface{}{
			"name":          "企业微信",
			"type":          "weixin",
			"is_configured": weixin.IsConfigured(),
			"config":        weixin,
		},
	})
}

func (n *Notification) Update(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)

	if err != nil {
		return core.Fail(err)
	}
	notificationType := ""
	config := make(map[string]interface{})
	if v, ok := params["type"]; ok {
		notificationType = public.InterfaceToString(v)
	}

	if notificationType == "" {
		return core.Fail("缺少参数：告警通知类型")
	}
	if v, ok := params["config"]; ok {
		config, _ = v.(map[string]interface{})
	}

	if len(config) == 0 {
		return core.Fail("缺少参数：告警通知配置")
	}
	err = n.updateConfig(notificationType, config)

	if err != nil {
		return core.Fail(err)
	}

	return core.Success("ok")
}

func (n *Notification) Clear(request *http.Request) core.Response {
	params, err := core.GetParamsFromRequest(request)
	if err != nil {
		return core.Fail(err)
	}
	notificationType := ""
	if v, ok := params["type"]; ok {
		notificationType = public.InterfaceToString(v)
	}
	if notificationType == "" {
		return core.Fail("缺少参数：告警通知类型")
	}
	notifier, err := notification.Notifier(notificationType)

	if err != nil {
		return core.Fail(err)
	}
	err = notifier.ClearConfig()

	if err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (n *Notification) updateConfig(notificationType string, config map[string]interface{}) (err error) {

	msg := notification.Message{"堡塔云Waf测试消息", []string{
		"您正在堡塔云Waf进行告警通知测试操作，如非您本人操作，请忽略此消息。",
		"若您收到此消息，证明您的配置正确，且可以正常收发消息。",
	}}

	switch notificationType {
	case "email":
		if _, ok := config["email"]; !ok {
			return errors.New("缺少配置：发件人邮箱")
		}

		if _, ok := config["host"]; !ok {
			return errors.New("缺少配置：SMTP服务器主机地址")
		}

		if _, ok := config["port"]; !ok {
			return errors.New("缺少配置：SMTP服务器端口号")
		}

		if _, ok := config["password"]; !ok {
			return errors.New("缺少配置：密码")
		}

		if _, ok := config["receivers"]; !ok {
			return errors.New("缺少配置：收件人邮箱列表")
		}
		email := notification.DefaultEmailNotifier()
		if v, ok := config["email"].(string); ok {
			if !validate.IsEmail(v) {
				return errors.New("发件人邮箱地址格式错误：" + v)
			}

			email.Email = v
		}
		if v, ok := config["host"].(string); ok {
			if !validate.IsHost(v) {
				return errors.New("SMTP服务器主机地址格式错误：" + v)
			}

			email.Host = v
		}
		if v, ok := config["port"].(string); ok {
			if !validate.IsPort(v) {
				return errors.New("SMTP服务器端口号格式错误：" + v)
			}
			email.Port = v
		}
		if v, ok := config["password"].(string); ok {
			email.Password = v
		}
		if v, ok := config["receivers"].([]interface{}); ok {
			receivers := public.InterfaceArray_To_StringArray(v)
			for _, receiver := range receivers {
				if !validate.IsEmail(receiver) {
					return errors.New("收件人邮箱地址格式错误：" + receiver)
				}
			}

			if len(receivers) == 0 {
				return errors.New("收件人不能为空")
			}

			email.Receivers = receivers
		}
		err = email.Notify(msg)
		if err != nil {
			return err
		}
		return email.UpdateConfig()
	case "dingding":
		if _, ok := config["url"]; !ok {
			return errors.New("缺少配置：钉钉机器人webhook推送地址")
		}
		dingding := notification.DefaultDingDingNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New("URL格式错误：" + v)
			}

			dingding.Url = v
		}
		err = dingding.Notify(msg)

		if err != nil {
			return err
		}
		return dingding.UpdateConfig()
	case "feishu":
		if _, ok := config["url"]; !ok {
			return errors.New("缺少配置：飞书机器人webhook推送地址")
		}
		feishu := notification.DefaultFeiShuNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New("URL格式错误：" + v)
			}

			feishu.Url = v
		}
		err = feishu.Notify(msg)
		if err != nil {
			return err
		}
		return feishu.UpdateConfig()
	case "weixin":
		if _, ok := config["url"]; !ok {
			return errors.New("缺少配置：企业微信机器人webhook推送地址")
		}

		weixin := notification.DefaultWeiXinNotifier()
		if v, ok := config["url"].(string); ok {
			if !validate.IsUrl(v) {
				return errors.New("URL格式错误：" + v)
			}

			weixin.Url = v
		}
		err = weixin.Notify(msg)

		if err != nil {
			return err
		}
		return weixin.UpdateConfig()
	default:
		return errors.New("不支持的告警通知配置：" + notificationType)
	}
}
