package notification

import (
	"CloudWaf/core/logging"
	"CloudWaf/public/validate"
	"crypto/tls"
	"errors"
	"net/smtp"
	"strings"
)

type Email struct {
	Email     string   `json:"email"`
	Host      string   `json:"host"`
	Port      string   `json:"port"`
	Password  string   `json:"password"`
	Receivers []string `json:"receivers"`
}

func NewEmailNotifier() *Email {
	return &Email{
		Receivers: make([]string, 0),
	}
}

func (e *Email) Notify(message Message) error {
	msg := []byte("From: " + e.Email + "\r\n" +
		"To: " + strings.Join(e.Receivers, ",") + "\r\n" +
		"Subject: " + message.MailTitle() + "\r\n" +
		"Content-Type: text/html; charset=utf-8" + "\r\n" +
		"\r\n" +
		message.MailText() +
		"\r\n")

	auth := smtp.PlainAuth("", e.Email, e.Password, e.Host)

	if e.isSecure() {
		return e.sendWithSSL(msg, auth)
	}

	return e.send(msg, auth)
}

func (e *Email) sendWithSSL(msg []byte, auth smtp.Auth) error {
	conn, err := tls.Dial("tcp", e.Host+":"+e.Port, nil)

	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		return err
	}
	defer func() {
		err = c.Close()

		if err != nil {
			logging.Info("关闭SMTP客户端连接发生错误：", err)
		}
		err = c.Quit()
		if err != nil {
			logging.Info("关闭SMTP客户端连接发生错误：", err)
		}
	}()

	if err != nil {
		return err
	}

	err = c.Auth(auth)

	if err != nil {
		return err
	}

	err = c.Mail(e.Email)

	if err != nil {
		return err
	}

	for _, to := range e.Receivers {
		err = c.Rcpt(to)
		if err != nil {
			return err
		}
	}

	w, err := c.Data()

	if err != nil {
		return err
	}

	_, err = w.Write(msg)

	if err != nil {
		return err
	}

	err = w.Close()

	if err != nil {
		return err
	}

	return nil
}

func (e *Email) send(msg []byte, auth smtp.Auth) error {
	return smtp.SendMail(e.Host+":"+e.Port, auth, e.Email, e.Receivers, msg)
}

func (e *Email) isSecure() bool {
	if e.Port == "465" || e.Port == "587" {
		return true
	}

	return false
}

func (e *Email) IsConfigured() bool {
	e.Email = strings.TrimSpace(e.Email)
	e.Host = strings.TrimSpace(e.Host)
	e.Port = strings.TrimSpace(e.Port)
	e.Password = strings.TrimSpace(e.Password)

	if e.Email == "" {
		return false
	}

	if e.Host == "" {
		return false
	}

	if e.Port == "" {
		return false
	}

	if e.Password == "" {
		return false
	}
	if !validate.IsPort(e.Port) {
		return false
	}
	if !validate.IsHost(e.Host) {
		return false
	}
	if !validate.IsEmail(e.Email) {
		return false
	}

	return true
}

func (e *Email) UpdateConfig() error {
	if !e.IsConfigured() {
		return errors.New("配置不正确")
	}

	return writeConfig()
}

func (e *Email) ClearConfig() error {
	e.Email = ""
	e.Host = ""
	e.Port = ""
	e.Password = ""
	e.Receivers = make([]string, 0)
	return writeConfig()
}
