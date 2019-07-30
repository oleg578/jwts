package jwts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func hashMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func CreateTokenHS256(payload interface{}, secret string) (token string, err error) {
	if len(secret) != 32 {
		return "", fmt.Errorf("The secret length must be 32 bytes")
	}
	//create header
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: "HS256",
		Typ: "JWT",
	}
	headerM, errM := json.Marshal(header)
	if errM != nil {
		return "", errM
	}
	headerEncoded := base64.RawStdEncoding.EncodeToString(headerM)
	//create payload
	payloadM, errM := json.Marshal(payload)
	if errM != nil {
		return "", errM
	}
	payloadEncoded := base64.RawStdEncoding.EncodeToString(payloadM)
	unsignedTok := headerEncoded + "." + payloadEncoded
	//signing
	signature := base64.RawStdEncoding.EncodeToString(
		hashMAC([]byte(unsignedTok), []byte(secret)))
	//assembly token
	return unsignedTok + "." + signature, nil
}
