package jwts

import (
	"reflect"
	"testing"
)

func Test_hashMAC(t *testing.T) {
	type args struct {
		message []byte
		key     []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			"genKeyOK",
			args{
				message: []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ1c2VyMTIzIn0`),
				key:     []byte(`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`),
			},
			[]byte{122, 19, 108, 122, 116, 122, 182,
				116, 142, 246, 8, 86, 180, 132,
				222, 96, 167, 207, 29, 53, 107,
				91, 159, 74, 16, 151, 103, 105, 124, 91, 100, 105},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashMAC(tt.args.message, tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hashMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateTokenHS256(t *testing.T) {
	type args struct {
		payload map[string]interface{}
		secret  string
	}
	pl := make(map[string]interface{})
	pl["uid"] = "user123"
	pl["exp"] = 2428485259
	h := make(map[string]interface{})
	h["alg"] = "HS256"
	h["typ"] = "JWT"
	tests := []struct {
		name      string
		args      args
		wantToken Token
		wantErr   bool
	}{
		{
			"getTokOK",
			args{
				pl,
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			Token{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI0Mjg0ODUyNTksInVpZCI6InVzZXIxMjMifQ.qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				h,
				pl,
				`qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				true,
				false,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, err := CreateTokenHS256(tt.args.payload, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTokenHS256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotToken, tt.wantToken) {
				t.Errorf("CreateTokenHS256() = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}

func TestIsExpired(t *testing.T) {
	type fields struct {
		RawStr    string
		Header    map[string]interface{}
		Payload   map[string]interface{}
		Signature string
		Valid     bool
		Expired   bool
	}
	h := make(map[string]interface{})
	h["alg"] = `HS256`
	h["typ"] = `JWT`
	pl := make(map[string]interface{})
	pl["exp"] = int64(1564569962)
	pl["uid"] = `user123`
	plwrong := make(map[string]interface{})
	plwrong["exp"] = int64(1000)
	plwrong["uid"] = `user123`
	type args struct {
		secret string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"IsExpired_False",
			fields{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjQ1Njk5NjIsInVpZCI6InVzZXIxMjMifQ.WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				h,
				pl,
				`WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				true,
				false,
			},
			args{
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			false,
		},
		{
			"IsExpired_False",
			fields{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AyJleHAiOjE1NjQ1Njk5NjIsInVpZCI6InVzZXIxMjMifQ.WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				h,
				plwrong,
				`WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				false,
				false,
			},
			args{
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{
				RawStr:    tt.fields.RawStr,
				Header:    tt.fields.Header,
				Payload:   tt.fields.Payload,
				Signature: tt.fields.Signature,
				Valid:     tt.fields.Valid,
				Expired:   tt.fields.Expired,
			}
			if err := tok.IsExpired(); (err != nil) == tt.wantErr {
				t.Logf("Token.IsExpired() error = %v, wantErr %v\n token: %+v\n", err, tt.wantErr, tok)
			}
		})
	}
}

func TestToken_Validate(t *testing.T) {
	type fields struct {
		RawStr    string
		Header    map[string]interface{}
		Payload   map[string]interface{}
		Signature string
		Valid     bool
		Expired   bool
	}
	h := make(map[string]interface{})
	h["alg"] = `HS256`
	h["typ"] = `JWT`
	pl := make(map[string]interface{})
	pl["exp"] = int64(1564569962)
	pl["uid"] = `user123`
	type args struct {
		secret string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"ValidateOK",
			fields{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjQ1Njk5NjIsInVpZCI6InVzZXIxMjMifQ.WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				h,
				pl,
				`WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				true,
				false,
			},
			args{
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			false,
		},
		{
			"ValidatePayloadWrong",
			fields{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AyJleHAiOjE1NjQ1Njk5NjIsInVpZCI6InVzZXIxMjMifQ.WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				h,
				pl,
				`WwsQ+wku4rkYOP3QoI+FzInOb22BKpzGVWjuT3HlhPI`,
				false,
				false,
			},
			args{
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &Token{
				RawStr:    tt.fields.RawStr,
				Header:    tt.fields.Header,
				Payload:   tt.fields.Payload,
				Signature: tt.fields.Signature,
				Valid:     tt.fields.Valid,
				Expired:   tt.fields.Expired,
			}
			if err := tok.Validate(tt.args.secret); (err != nil) == tt.wantErr {
				t.Logf("Token.Validate() error = %v, wantErr %v\n token: %+v\n", err, tt.wantErr, tok)
			}
		})
	}
}

func TestParse(t *testing.T) {
	pl := make(map[string]interface{})
	pl["uid"] = "user123"
	pl["exp"] = int64(2428485259)
	h := make(map[string]interface{})
	h["alg"] = "HS256"
	h["typ"] = "JWT"
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantT   Token
		wantErr bool
	}{
		{"ParseOK",
			args{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI0Mjg0ODUyNTksInVpZCI6InVzZXIxMjMifQ.qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
			},
			Token{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI0Mjg0ODUyNTksInVpZCI6InVzZXIxMjMifQ.qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				h,
				pl,
				`qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				false,
				false,
			},
			true,
		},
		{"ParseFault",
			args{
				`AyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI0Mjg0ODUyNTksInVpZCI6InVzZXIxMjMifQ.qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
			},
			Token{
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI0Mjg0ODUyNTksInVpZCI6InVzZXIxMjMifQ.qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				h,
				pl,
				`qxmN9W1qtRariMTHS5fIudyTMJ0qAI88CoexkYwJqWs`,
				false,
				false,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotT, err := Parse(tt.args.token)
			if (err != nil) == tt.wantErr {
				t.Logf("Parse() error = %v,\n wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotT, tt.wantT) {
				t.Errorf("Parse() = %+v,\n want %+v", gotT, tt.wantT)
			}
		})
	}
}
