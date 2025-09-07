# jwts

A simple Go library for creating, parsing, and validating JWT tokens using HMAC SHA256 (HS256).

## Features

- Create JWT tokens with custom payloads and expiration (`exp` claim required)
- Parse and validate JWT tokens
- Check token expiration
- Minimal dependencies, easy to use

## Installation

```sh
go get github.com/oleg578/jwts
```

## Usage

```go
import "github.com/oleg578/jwts"
```

### Creating a Token

```go
payload := map[string]interface{}{
	"uid": "user123",
	"exp": 2428485259, // Unix timestamp
}
secret := "your-secret-key"
token, err := jwts.CreateTokenHS256(payload, secret)
if err != nil {
	// handle error
}
fmt.Println("JWT:", token.RawStr)
```

### Parsing a Token

```go
parsedToken, err := jwts.Parse(token.RawStr)
if err != nil {
	// handle error
}
```

### Validating a Token

```go
err := parsedToken.Validate(secret)
if err != nil {
	// invalid signature
}
```

### Checking Expiration

```go
err := parsedToken.IsExpired()
if err != nil {
	// token is expired
}
```

## API

- `CreateTokenHS256(payload map[string]interface{}, secret string) (Token, error)`
- `Parse(token string) (Token, error)`
- `Token.Validate(secret string) error`
- `Token.IsExpired() error`

## Token Structure

```go
type Token struct {
	RawStr    string
	Header    map[string]any
	Payload   map[string]any
	Signature string
	Valid     bool
	Expired   bool
}
```

## Testing

Run all tests:

```sh
go test
```

## License

MIT
