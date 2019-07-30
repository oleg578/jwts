package jwts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
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

//validate exp, sign
func (t *Token) Validate(secret string) error {
	timemark := time.Now().Unix()
	if _, ok := t.Payload["exp"]; !ok {
		t.IsValid = false
		return fmt.Errorf("exp claim needed")
	}
	if t.Payload["exp"].(int64) <= timemark {
		t.IsValid = false
		return fmt.Errorf("expired")
	}
	//test sign
	segments := strings.Split(t.RawStr, ".")
	unsign := segments[0] + "." + segments[1]
	if t.Signature != base64.RawStdEncoding.EncodeToString(
		hashMAC([]byte(unsign), []byte(secret))) {
		t.IsValid = false
		return fmt.Errorf("wrong sign")
	}
	t.IsValid = true
	return nil
}

//parse
func Parse(token string) (t Token, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return t, fmt.Errorf("wrong token")
	}
	t.Signature = segments[2]
	t.IsValid = true
	t.RawStr = token
	//get header
	headerDecoded, err := base64.RawStdEncoding.DecodeString(segments[0])
	if err != nil {
		return t, err
	}
	err = json.Unmarshal(headerDecoded, &t.Header)
	if err != nil {
		return t, err
	}
	//get payload
	payloadDecoded, err := base64.RawStdEncoding.DecodeString(segments[1])
	if err != nil {
		return t, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(payloadDecoded))
	dec.UseNumber()
	for {
		var c map[string]interface{}
		if err := dec.Decode(&c); err == io.EOF {
			break
		} else if err != nil {
			return t, err
		}
		for k, v := range c {
			if reflect.TypeOf(v).Name() == "Number" {
				vv := v.(json.Number)
				if newval, err := vv.Int64(); err != nil {
					c[k] = vv.String()
				} else {
					c[k] = newval
				}
			}
		}
		t.Payload = c
	}

	if err != nil {
		return t, err
	}
	return
}
