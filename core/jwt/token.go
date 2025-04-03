package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload map[string]Claim

type Token struct {
	Header  Header
	Payload Payload
}

func (header Header) String() string {
	bs, err := json.Marshal(header)

	if err != nil {
		return ""
	}

	return Base64UrlEncode(string(bs))
}

func (payload Payload) String() string {
	bs, err := json.Marshal(payload)

	if err != nil {
		return ""
	}

	return Base64UrlEncode(string(bs))
}

func (payload Payload) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)

	if err != nil {
		return err
	}

	for k, v := range m {
		switch k {
		case "iss":
			payload[k] = Iss(v.(string))
		case "sub":

			switch v2 := v.(type) {
			case float64:
				payload[k] = Sub(strconv.Itoa(int(v2)))
			case string:
				payload[k] = Sub(v2)
			}
		case "aud":
			payload[k] = Aud(v.(string))
		case "exp":
			payload[k] = Exp(int64(v.(float64)))
		case "nbf":
			payload[k] = Nbf(int64(v.(float64)))
		case "iat":
			payload[k] = Iat(int64(v.(float64)))
		case "jti":
			payload[k] = Jti(v.(string))
		}
	}

	return nil
}

func (token Token) Validate() error {

	if blackList.Has(token) {
		return errors.New("Token invalid")
	}

	for _, claim := range token.Payload {
		err := claim.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

func (token Token) Refresh() (Token, error) {
	sub, err := token.GetPayload("sub")
	if err != nil {
		return token, err
	}
	newToken, err := BuildToken(sub.Value().(string))

	if err != nil {
		return token, err
	}
	err = blackList.Add(token)
	if err != nil {
		return token, err
	}
	return newToken, nil
}

func (token Token) Invalidate() error {
	return blackList.Add(token)
}

func (token Token) GetPayload(key string) (Claim, error) {
	claim, ok := token.Payload[key]

	if !ok {
		return claim, errors.New(fmt.Sprintf("载荷 %s 不存在", key))
	}

	return claim, nil
}

func (token Token) String() string {
	headerStr := token.Header.String()
	payloadStr := token.Payload.String()
	signature, err := HmacSha256ToBase64(headerStr+"."+payloadStr, SecretKey)
	if err != nil {
		return ""
	}
	return headerStr + "." + payloadStr + "." + signature
}

func (token Token) Uid() int {
	sub, err := token.GetPayload("sub")
	if err != nil {
		return 0
	}
	uid, err := strconv.Atoi(sub.Value().(string))
	if err != nil {
		return 0
	}
	return uid
}
