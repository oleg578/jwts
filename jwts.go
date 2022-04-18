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
	Valid     bool
	Expired   bool
}

func hashMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func CreateTokenHS256(payload map[string]interface{}, secret string) (token Token, err error) {
	//create header
	header := make(map[string]interface{}, 2)
	header["alg"] = "HS256"
	header["typ"] = "JWT"
	token.Header = header
	headerM, errM := json.Marshal(header)
	if errM != nil {
		token.Valid = false
		return token, errM
	}
	headerEncoded := base64.RawStdEncoding.EncodeToString(headerM)
	//create payload
	token.Payload = payload
	if _, ok := payload["exp"]; !ok {
		token.Valid = false
		return token, fmt.Errorf("need exp value")
	}
	payloadM, errM := json.Marshal(payload)
	if errM != nil {
		token.Valid = false
		return token, errM
	}
	payloadEncoded := base64.RawStdEncoding.EncodeToString(payloadM)
	unsignedTok := headerEncoded + "." + payloadEncoded
	//signing
	token.Signature = base64.RawURLEncoding.EncodeToString(
		hashMAC([]byte(unsignedTok), []byte(secret)))
	//assembly token
	token.RawStr = unsignedTok + "." + token.Signature
	//no err?
	token.Valid = true
	return
}

func (t *Token) IsExpired() error {
	timemark := time.Now().Unix()
	if _, ok := t.Payload["exp"]; !ok {
		t.Expired = true
		return fmt.Errorf("exp claim needed")
	}
	if t.Payload["exp"].(int64) <= timemark {
		t.Expired = true
		return fmt.Errorf("expired")
	}
	t.Expired = false
	return nil
}

//validate exp, sign
func (t *Token) Validate(secret string) error {
	//test sign
	segments := strings.Split(t.RawStr, ".")
	unsign := segments[0] + "." + segments[1]
	if t.Signature != base64.RawStdEncoding.EncodeToString(
		hashMAC([]byte(unsign), []byte(secret))) {
		t.Valid = false
		return fmt.Errorf("wrong sign")
	}
	t.Valid = true
	return nil
}

//parse
func Parse(token string) (t Token, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return t, fmt.Errorf("wrong token")
	}
	t.Signature = segments[2]
	t.RawStr = token
	//get header
	headerDecoded, errHdr := base64.RawStdEncoding.DecodeString(segments[0])
	if errHdr != nil {
		return t, errHdr
	}
	if errUm := json.Unmarshal(headerDecoded, &t.Header); errUm != nil {
		return t, errUm
	}
	//get payload
	payloadDecoded, errPld := base64.RawStdEncoding.DecodeString(segments[1])
	if errPld != nil {
		return t, errPld
	}
	dec := json.NewDecoder(bytes.NewBuffer(payloadDecoded))
	dec.UseNumber()
	var c map[string]interface{}
	for {
		errDec := dec.Decode(&c)
		if errDec == io.EOF {
			break
		}
		if errDec != nil {
			err = errDec
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
	return
}
