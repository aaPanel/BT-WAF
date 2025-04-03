package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

func PKCS7Padding(data []byte, blockSize int) string {
	length := len(data)

	amountToPad := blockSize - (length % blockSize)

	if amountToPad == 0 {
		amountToPad = blockSize
	}

	pad := byte(amountToPad)

	for i := 0; i < amountToPad; i++ {
		data = append(data, pad)
	}

	return string(data)
}

func PKCS7UnPadding(data []byte, blockSize int) []byte {
	length := len(data)
	pad := int(data[length-1])

	if pad < 1 || pad > blockSize {
		pad = 0
	}

	return data[:(length - pad)]
}

func AesEncrypt(origData string, key string) (string, error) {
	origData = strings.TrimSpace(origData)
	key = strings.TrimSpace(key)

	if len(origData) == 0 || len(key) == 0 {
		return "", errors.New("origData or key is empty")
	}

	keyBytes := []byte(key)
	blockSize := len(keyBytes)

	if blockSize < 16 || blockSize%16 != 0 {
		return "", errors.New("Aes key length must multiple of 16 and greater than 15")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	origData = PKCS7Padding([]byte(origData), blockSize)

	data := []byte(origData)

	blockMode := cipher.NewCBCEncrypter(block, []byte(key)[:16])
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func AesDecrypt(encrypted string, key string) (string, error) {
	encrypted = strings.TrimSpace(encrypted)
	key = strings.TrimSpace(key)
	if len(encrypted) == 0 || len(key) == 0 {
		return "", errors.New("crypted or key is empty")
	}

	bs, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	keyBytes := []byte(key)
	blockSize := len(keyBytes)

	if blockSize < 16 || blockSize%16 != 0 {
		return "", errors.New("Aes key length must multiple of 16 and greater than 15")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCDecrypter(block, keyBytes[:16])
	origData := make([]byte, len(bs))
	blockMode.CryptBlocks(origData, bs)
	origData = PKCS7UnPadding(origData, blockSize)

	return string(origData), nil
}

func AesEncryptCBC(origData string, key string, iv string) (string, error) {
	origData = strings.TrimSpace(origData)
	key = strings.TrimSpace(key)
	iv = strings.TrimSpace(iv)

	if len(origData) == 0 || len(key) == 0 || len(iv) == 0 {
		return "", errors.New("origData or key or iv is empty")
	}

	keyBytes := []byte(key)
	blockSize := len(keyBytes)

	if blockSize < 16 || blockSize%16 != 0 {
		return "", errors.New("Aes key length must multiple of 16 and greater than 15")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	origData = PKCS7Padding([]byte(origData), blockSize)

	data := []byte(origData)

	blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func AesDecryptCBC(encrypted string, key string, iv string) (string, error) {
	encrypted = strings.TrimSpace(encrypted)
	key = strings.TrimSpace(key)
	iv = strings.TrimSpace(iv)

	if len(encrypted) == 0 || len(key) == 0 || len(iv) == 0 {
		return "", errors.New("crypted or key or iv is empty")
	}

	bs, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	keyBytes := []byte(key)
	blockSize := len(keyBytes)

	if blockSize < 16 || blockSize%16 != 0 {
		return "", errors.New("Aes key length must multiple of 16 and greater than 15")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	origData := make([]byte, len(bs))
	blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
	blockMode.CryptBlocks(origData, bs)
	origData = PKCS7UnPadding(origData, blockSize)
	return string(origData), nil
}
