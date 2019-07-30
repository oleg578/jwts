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
	pl["exp"] = 1564561928
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
				`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjQ1NjE5MjgsInVpZCI6InVzZXIxMjMifQ.MuGRKA3A52foIVI1miVZT6Hu1CPW+4Ngz2dbUe5JesU`,
				h,
				pl,
				`MuGRKA3A52foIVI1miVZT6Hu1CPW+4Ngz2dbUe5JesU`,
				true,
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

func TestParse(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		wantT   *Token
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotT, err := Parse(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotT, tt.wantT) {
				t.Errorf("Parse() = %v, want %v", gotT, tt.wantT)
			}
		})
	}
}
