package jwts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

//TODO:

//verify
func IsValid(token, secret string) bool {
	return false
}

//parse
func Parse(token string) (header, payload interface{}, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, nil, fmt.Errorf("wrong token - must have 3 segments")
	}
	head, err := base64.RawStdEncoding.DecodeString(segments[0])
	if err != nil {
		return
	}
	if err = json.Unmarshal(head, &header); err != nil {
		return
	}
	pl, err := base64.RawStdEncoding.DecodeString(segments[1])
	if err != nil {
		return
	}
	if err = json.Unmarshal(pl, &payload); err != nil {
		return
	}
	return
}
