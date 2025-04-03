package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

func RsaGenerateKey(bits int) (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(privateKeyBytes), nil
}

func RsaPublicKey(privateKey string) (string, error) {
	privKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err := x509.ParsePKCS1PrivateKey(privKey)
	if err != nil {

		v, err := x509.ParsePKCS8PrivateKey(privKey)

		if err != nil {
			return "", err
		}

		if privateKey, ok := v.(*rsa.PrivateKey); ok {
			publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

			if err != nil {
				return "", err
			}

			return base64.StdEncoding.EncodeToString(publicKeyBytes), nil
		} else {
			return "", errors.New("无效的私钥")
		}
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKeyBytes.PublicKey)
	return base64.StdEncoding.EncodeToString(publicKeyBytes), nil
}

func RsaGenerateKeyPair(bits int) (string, string, error) {
	privateKey, err := RsaGenerateKey(bits)
	if err != nil {
		return "", "", err
	}
	publicKey, err := RsaPublicKey(privateKey)
	if err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

func RsaEncrypt(origData string, publicKey string) (string, error) {
	pubKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	pub, err := parsePublicKey(pubKey)

	if err != nil {
		return "", err
	}

	origData = strings.TrimSpace(origData)
	if len(origData) == 0 {
		return "", errors.New("origData is empty")
	}

	origDataByte := []byte(origData)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, origDataByte)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func RsaDecrypt(encrypted string, privateKey string) (string, error) {
	privKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	priv, err := parsePrivateKey(privKey)
	if err != nil {
		return "", err
	}

	encrypted = strings.TrimSpace(encrypted)
	if len(encrypted) == 0 {
		return "", errors.New("encrypted is empty")
	}

	encryptedByte, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	origDataByte, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedByte)
	if err != nil {
		return "", err
	}

	return string(origDataByte), nil
}

func RsaSign(data, privateKey string) (string, error) {
	privKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}

	priv, err := parsePrivateKey(privKey)
	if err != nil {
		return "", err
	}

	data = strings.TrimSpace(data)
	if data == "" {
		return "", errors.New("cannot sign empty string")
	}

	h := sha256.New()
	h.Write([]byte(data))

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h.Sum(nil))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func RsaVerify(data, signature, publicKey string) bool {
	pubKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return false
	}

	pub, err := parsePublicKey(pubKey)
	if err != nil {
		return false
	}

	data = strings.TrimSpace(data)
	if data == "" {
		return false
	}

	signature = strings.TrimSpace(signature)
	if data == "" {
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	h := sha256.New()
	h.Write([]byte(data))

	if err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), signatureBytes); err != nil {
		return false
	}

	return true
}

func parsePublicKey(publicKey []byte) (pub *rsa.PublicKey, err error) {
	var (
		ok bool
	)

	pub, err = x509.ParsePKCS1PublicKey(publicKey)

	if err != nil {

		v, err := x509.ParsePKIXPublicKey(publicKey)

		if err != nil {
			return pub, err
		}

		if pub, ok = v.(*rsa.PublicKey); !ok {
			return pub, errors.New("无效的公钥")
		}
	}

	return pub, nil
}

func parsePrivateKey(privateKey []byte) (priv *rsa.PrivateKey, err error) {
	var (
		ok bool
	)

	priv, err = x509.ParsePKCS1PrivateKey(privateKey)

	if err != nil {

		v, err := x509.ParsePKCS8PrivateKey(privateKey)

		if err != nil {
			return priv, err
		}

		if priv, ok = v.(*rsa.PrivateKey); !ok {
			return priv, errors.New("无效的公钥")
		}

		return priv, err
	}

	return priv, nil
}
