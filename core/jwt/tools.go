package jwt

import (
	"CloudWaf/core/common"
)

func RandomStr(n int) (string, error) {
	return common.RandomStr(n)
}

func RandomStr2(n int) string {
	return common.RandomStr2(n)
}

func Base64UrlEncode(s string) string {
	return common.Base64UrlEncode(s)
}

func Base64UrlDecode(s string) (string, error) {
	return common.Base64UrlDecode(s)
}
