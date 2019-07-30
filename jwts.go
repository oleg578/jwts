package jwts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Token struct {
	RawStr    string
	Header    map[string]string
	Payload   map[string]string
	Signature string
	IsValid   bool
}

func hashMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func CreateTokenHS256(payload map[string]string, secret string) (token Token, err error) {
	if len(secret) != 32 {
		token.IsValid = false
		return token, fmt.Errorf("The secret length must be 32 bytes")
	}
	//create header
	header := make(map[string]string, 2)
	header["alg"] = "HS256"
	header["typ"] = "JWT"
	token.Header = header
	headerM, errM := json.Marshal(header)
	if errM != nil {
		token.IsValid = false
		return token, errM
	}
	headerEncoded := base64.RawStdEncoding.EncodeToString(headerM)
	//create payload
	token.Payload = payload
	payloadM, errM := json.Marshal(payload)
	if errM != nil {
		token.IsValid = false
		return token, errM
	}
	payloadEncoded := base64.RawStdEncoding.EncodeToString(payloadM)
	unsignedTok := headerEncoded + "." + payloadEncoded
	//signing
	token.Signature = base64.RawStdEncoding.EncodeToString(
		hashMAC([]byte(unsignedTok), []byte(secret)))
	//assembly token
	token.RawStr = unsignedTok + "." + token.Signature
	//no err?
	token.IsValid = true
	return
}

//TODO:

//verify
func IsValid(token, secret string) bool {
	return false
}

//parse
func Parse(token string) (t *Token, err error) {

	return
}
