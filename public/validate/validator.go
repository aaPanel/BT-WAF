package validate

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
)

var (
	reMap = map[string]*regexp.Regexp{
		"dotAndNumber": regexp.MustCompile(`^(?:\d+|\.)+$`),
		"host":         regexp.MustCompile(`^[\w\-]+(?:\.[\w\-]+)+(?::\d+)?$`),
		"email":        regexp.MustCompile(`^.+@\[?[\w\-.]+\.(?:[a-zA-Z]{2,3}|\d{1,3})\]?$`),
		"admin_path":   regexp.MustCompile(`^[\w\/\-\.]+$`),
		"chinese":      regexp.MustCompile(`[\p{Han}]`),
		"double_byte":  regexp.MustCompile(`[^\x00-\xff]`),
		"base63":       regexp.MustCompile(`^[a-zA-Z0-9_]+$`),
	}
)

func IsHost(s string) bool {
	if reMap["dotAndNumber"].MatchString(s) {
		if ipAddr := net.ParseIP(s); ipAddr != nil {
			return true
		}

		return false
	}

	return reMap["host"].MatchString(s)
}

func IsPort(s string) bool {
	port, err := strconv.Atoi(s)

	if err != nil {
		return false
	}

	if port < 1 || port > 65535 {
		return false
	}

	return true
}

func IsEmail(s string) bool {
	return reMap["email"].MatchString(s)
}

func IsUrl(s string) bool {
	_, err := url.ParseRequestURI(s)

	if err != nil {
		return false
	}

	u, err := url.Parse(s)

	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func IsAdminPath(s string) bool {
	return reMap["admin_path"].MatchString(s)
}

func HasChinese(s string) bool {
	return reMap["chinese"].MatchString(s)
}

func HasDouble(s string) bool {
	return reMap["double_byte"].MatchString(s)
}

func IsBase63(s string) bool {
	return reMap["base63"].MatchString(s)
}
