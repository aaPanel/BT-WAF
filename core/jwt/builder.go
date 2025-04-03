package jwt

import (
	"time"
)

func BuildToken(subject string) (Token, error) {
	token := Token{}

	randomStr, err := RandomStr(64)

	if err != nil {
		randomStr = RandomStr2(64)
	}

	curTime := time.Now().Unix()

	token.Header = Header{
		Alg: "SHA256",
		Typ: "JWT",
	}

	token.Payload = Payload{
		"iss": Iss("BT_CLOUD_WAF"),
		"sub": Sub(subject),
		"aud": Aud(subject),
		"exp": Exp(curTime + (TTL() * 60)),
		"nbf": Nbf(curTime),
		"iat": Iat(curTime),
		"jti": Jti(randomStr),
	}

	return token, nil
}
