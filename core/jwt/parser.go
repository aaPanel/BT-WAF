package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Parser struct {
	RawToken      string
	RawTokenParts []string
}

func ParseTokenWithRequest(request *http.Request) (Token, error) {

	return ParseTokenWithString(request.Header.Get(HEADER_KEY))
}

func ParseTokenWithString(s string) (Token, error) {
	token := Token{}

	s = strings.TrimSpace(s)

	if s == "" {
		return token, errors.New("Token not provide")
	}
	if !strings.HasPrefix(s, PREFIX) {
		return token, errors.New("Invalid Token")
	}
	s = strings.TrimSpace(strings.TrimLeft(s, PREFIX))
	parser := &Parser{RawToken: s}
	header, err := parser.ParseHeader()
	if err != nil {
		return token, err
	}
	payload, err := parser.ParsePayload()
	if err != nil {
		return token, err
	}
	if !parser.VerifySignature() {
		return token, errors.New("Token Signature invalid")
	}
	token.Header = header
	token.Payload = payload
	err = token.Validate()
	if err != nil {
		return token, err
	}
	return token, nil
}

func (parser *Parser) ParseRawToken() error {
	if parser.RawTokenParts != nil {
		return nil
	}
	parser.RawTokenParts = strings.Split(parser.RawToken, ".")
	if len(parser.RawTokenParts) != 3 {
		return errors.New("Invalid token structure")
	}
	return nil
}

func (parser *Parser) ParseHeader() (Header, error) {
	header := Header{}

	if parser.RawTokenParts == nil {
		err := parser.ParseRawToken()
		if err != nil {
			return header, err
		}
	}
	s, err := Base64UrlDecode(parser.RawTokenParts[0])
	if err != nil {
		return header, err
	}
	err = json.Unmarshal([]byte(s), &header)
	return header, err
}

func (parser *Parser) ParsePayload() (Payload, error) {
	payload := make(Payload)
	if parser.RawTokenParts == nil {
		err := parser.ParseRawToken()
		if err != nil {
			return payload, err
		}
	}
	s, err := Base64UrlDecode(parser.RawTokenParts[1])
	if err != nil {
		return payload, err
	}
	err = json.Unmarshal([]byte(s), &payload)
	return payload, err
}

func (parser *Parser) VerifySignature() bool {
	if parser.RawTokenParts == nil {
		err := parser.ParseRawToken()
		if err != nil {
			return false
		}
	}
	return HmacSha256Base64Equals(parser.RawTokenParts[2], parser.RawTokenParts[0]+"."+parser.RawTokenParts[1], SecretKey)
}
