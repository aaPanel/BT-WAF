package notification

import (
	"CloudWaf/core"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

var (
	configFile = core.AbsPath("./config/notification.json")
	notifiers  = NotifierMap{
		"email":    NewEmailNotifier(),
		"dingding": NewDingDingNotifier(),
		"feishu":   NewFeiShuNotifier(),
		"weixin":   NewWeiXinNotifier(),
	}

	mutex = sync.RWMutex{}
)

func init() {
	_, err := os.Stat(configFile)
	if err != nil {
		err = writeConfig()
		if err != nil {
			return
		}
		return
	}
	bs, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	err = json.Unmarshal(bs, &notifiers)
	if err != nil {
		return
	}
}

type Message struct {
	Title   string
	Content []string
}

func (m Message) MailTitle() string {
	return strings.Trim(strings.TrimSpace(m.Title), "#")
}

func (m Message) MailText() string {
	return "<pre style=\"margin: 0;\">" + strings.Join(m.Content, "\r\n") + "</pre>"
}

func (m Message) DingDingText() string {
	return m.Title + "\r\n\r\n" + strings.Join(m.Content, "\r\n\r\n")
}

func (m Message) Text() string {
	return m.Title + "\r\n" + strings.Join(m.Content, "\r\n")
}

func NewMessage(title string, content []string) Message {
	return Message{
		Title:   title,
		Content: content,
	}
}

type Notification interface {
	IsConfigured() bool
	UpdateConfig() error
	ClearConfig() error
	Notify(message Message) error
}

type NotifierMap map[string]Notification

func (n NotifierMap) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)

	if err != nil {
		return err
	}

	for k, v := range m {
		switch k {
		case "email":
			if email, ok := v.(map[string]interface{}); ok {
				receivers := make([]string, 0)
				for _, receiver := range email["receivers"].([]interface{}) {
					receivers = append(receivers, receiver.(string))
				}

				n[k] = &Email{
					Email:     email["email"].(string),
					Host:      email["host"].(string),
					Port:      email["port"].(string),
					Password:  email["password"].(string),
					Receivers: receivers,
				}
			}
		case "dingding":
			if dingding, ok := v.(map[string]interface{}); ok {
				n[k] = &DingDing{
					Url: dingding["url"].(string),
				}
			}
		case "feishu":
			if feishu, ok := v.(map[string]interface{}); ok {
				n[k] = &FeiShu{
					Url: feishu["url"].(string),
				}
			}
		case "weixin":
			if weixin, ok := v.(map[string]interface{}); ok {
				n[k] = &WeiXin{
					Url: weixin["url"].(string),
				}
			}
		}
	}

	return nil
}

func writeConfig() (err error) {
	mutex.Lock()
	defer mutex.Unlock()

	bs, err := json.MarshalIndent(notifiers, "", "    ")

	if err != nil {
		return err
	}

	return os.WriteFile(configFile, bs, 0644)
}

func Notify(notificationType, title string, content []string) (err error) {

	notifier, err := Notifier(notificationType)

	if err != nil {
		return err
	}
	if !notifier.IsConfigured() {
		return errors.New("告警通知【" + notificationType + "】未配置")
	}
	if err = notifier.Notify(NewMessage(title, content)); err != nil {
		return err
	}
	return nil
}

func NotifyAll(title string, content []string) {
	rg := core.NewRecoveryGoGroup(4)

	for _, notifier := range notifiers {
		if !notifier.IsConfigured() {
			continue
		}
		rg.Immediate(notifier.Notify, NewMessage(title, content))
	}
	rg.Wait()
}

func Notifier(notificationType string) (Notification, error) {
	notificationType = strings.ToLower(notificationType)

	if notifier, ok := notifiers[notificationType]; ok {
		return notifier, nil
	}

	return nil, errors.New("不支持的告警通知类型：" + notificationType)
}

func DefaultEmailNotifier() *Email {
	return notifiers["email"].(*Email)
}

func DefaultDingDingNotifier() *DingDing {
	return notifiers["dingding"].(*DingDing)
}

func DefaultFeiShuNotifier() *FeiShu {
	return notifiers["feishu"].(*FeiShu)
}

func DefaultWeiXinNotifier() *WeiXin {
	return notifiers["weixin"].(*WeiXin)
}
