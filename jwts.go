package jwts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type Token struct {
	RawStr    string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	IsValid   bool
}

func hashMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func CreateTokenHS256(payload map[string]interface{}, secret string) (token Token, err error) {
	if len(secret) != 32 {
		token.IsValid = false
		return token, fmt.Errorf("The secret length must be 32 bytes")
	}
	//create header
	header := make(map[string]interface{}, 2)
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
	if _, ok := payload["exp"]; !ok {
		token.IsValid = false
		return token, fmt.Errorf("need exp value")
	}
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

func SetExp(dur interface{}) int64 {
	now := time.Now()
	exp := now.Add(time.Minute * time.Duration(int64(dur.(int))))
	return exp.Unix()
}

//verify
func IsValid(token, secret string) bool {
	return false
}

//parse
func Parse(token string) (t *Token, err error) {

	return
}
