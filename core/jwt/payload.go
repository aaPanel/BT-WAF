package jwt

import (
	"errors"
	"time"
)

type Claim interface {
	Value() interface{}
	Validate() error
}

type Iss string

type Sub string

type Aud string

type Exp int64

type Nbf int64

type Iat int64

type Jti string

func (iss Iss) Validate() error {
	return nil
}

func (iss Iss) Value() interface{} {
	return string(iss)
}

func (sub Sub) Validate() error {
	return nil
}

func (sub Sub) Value() interface{} {
	return string(sub)
}

func (aud Aud) Validate() error {
	return nil
}

func (aud Aud) Value() interface{} {
	return string(aud)
}

func (exp Exp) Validate() error {

	if time.Now().Unix() >= int64(exp) {
		return errors.New("Token is expired")
	}

	return nil
}

func (exp Exp) Value() interface{} {
	return int64(exp)
}

func (nbf Nbf) Validate() error {

	if time.Now().Unix() < int64(nbf) {
		return errors.New("Token invalid")
	}

	return nil
}

func (nbf Nbf) Value() interface{} {
	return int64(nbf)
}

func (iat Iat) Validate() error {
	return nil
}

func (iat Iat) Value() interface{} {
	return int64(iat)
}

func (jti Jti) Validate() error {
	return nil
}

func (jti Jti) Value() interface{} {
	return string(jti)
}
