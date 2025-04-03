package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func HmacSha256(s, key string) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(key))
	_, err := mac.Write([]byte(s))

	if err != nil {
		return []byte{}, err
	}

	return mac.Sum(nil), nil
}

func HmacSha256ToHex(s, key string) (string, error) {
	bs, err := HmacSha256(s, key)

	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bs), nil
}

func HmacSha256ToBase64(s, key string) (string, error) {
	bs, err := HmacSha256(s, key)

	if err != nil {
		return "", err
	}

	return Base64UrlEncode(string(bs)), nil
}

func HmacSha256ToHexBase64(s, key string) (string, error) {
	hexStr, err := HmacSha256ToHex(s, key)

	if err != nil {
		return "", err
	}

	return Base64UrlEncode(hexStr), nil
}

func HmacSha256HexEquals(signature, s, key string) bool {
	bs1, err := hex.DecodeString(signature)

	if err != nil {
		return false
	}

	bs2, err := HmacSha256(s, key)

	if err != nil {
		return false
	}

	return hmac.Equal(bs1, bs2)
}

func HmacSha256Base64Equals(signature, s, key string) bool {
	s1, err := Base64UrlDecode(signature)

	if err != nil {
		return false
	}

	bs2, err := HmacSha256(s, key)

	if err != nil {
		return false
	}

	return hmac.Equal([]byte(s1), bs2)
}

func HmacSha256HexBase64Equals(signature, s, key string) bool {

	s1, err := Base64UrlDecode(signature)

	if err != nil {
		return false
	}

	bs1, err := hex.DecodeString(s1)

	if err != nil {
		return false
	}

	bs2, err := HmacSha256(s, key)

	if err != nil {
		return false
	}

	return hmac.Equal(bs1, bs2)
}
