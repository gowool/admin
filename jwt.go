package admin

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverifiedJWT parses JWT and returns its claims
// but DOES NOT verify the signature.
//
// It verifies only the exp, iat and nbf claims.
func ParseUnverifiedJWT(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parser := &jwt.Parser{}
	_, _, err := parser.ParseUnverified(token, claims)

	if err == nil {
		if err = new(jwt.Validator).Validate(claims); err != nil {
			err = errors.Join(jwt.ErrTokenInvalidClaims, err)
		}
	}

	return claims, err
}

// ParseJWT verifies and parses JWT and returns its claims.
func ParseJWT(token string, verificationKey string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))

	parsedToken, err := parser.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(verificationKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}

// NewJWT generates and returns new HS256 signed JWT.
func NewJWT(payload jwt.MapClaims, signingKey string, exp time.Duration) (string, error) {
	claims := jwt.MapClaims{"exp": time.Now().Add(exp).Unix()}

	for k, v := range payload {
		claims[k] = v
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
}
