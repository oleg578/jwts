package jwts

import (
	"reflect"
	"testing"
)

//SECRETKEY = `Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`
/*
pl := struct {
	UserId string `json:"uid"`
}{
	UserId: "user123",
}
*/
// token :
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ1c2VyMTIzIn0.ehNsenR6tnSO9ghWtITeYKfPHTVrW59KEJdnaXxbZGk
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
			"genKey",
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
		payload interface{}
		secret  string
	}
	tests := []struct {
		name      string
		args      args
		wantToken string
		wantErr   bool
	}{
		{
			"CreateTokenHS256",
			args{
				struct {
					UserId string `json:"uid"`
				}{
					UserId: "user123",
				},
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCkw`,
			},
			`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJ1c2VyMTIzIn0.ehNsenR6tnSO9ghWtITeYKfPHTVrW59KEJdnaXxbZGk`,
			false,
		},
		{
			"WrongTokenHS256",
			args{
				struct {
					UserId string `json:"uid"`
				}{
					UserId: "user123",
				},
				`Jkk6BxVNDEema7PXRYBNgbeECXwHnCk`,
			},
			``,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, err := CreateTokenHS256(tt.args.payload, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTokenHS256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotToken != tt.wantToken {
				t.Errorf("CreateTokenHS256() = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}
