package repo

import (
	"fmt"
	"time"

	"github.com/VirgilSecurity/virgil-services-auth/db"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
)

const accessTokenExpiresIn time.Duration = 10 * time.Minute

type myClaims struct {
	OwnerID   string `json:"own"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

func (c *myClaims) Valid() error {
	return nil
}

type AccessToken struct {
	PrivateKey virgilcrypto.PrivateKey
	PublicKey  virgilcrypto.PublicKey
}

func (r *AccessToken) Make(ownerId string, scope string) (*db.AccessToken, error) {
	iat := time.Now().UTC().Truncate(time.Second)
	t := jwt.NewWithClaims(SigningMethodVirgilCrypt, &myClaims{
		OwnerID:   ownerId,
		Scope:     scope,
		ExpiresAt: iat.Add(accessTokenExpiresIn).Unix(),
		IssuedAt:  iat.Unix(),
		Issuer:    "Virgil Security, Inc",
	})
	tstr, err := t.SignedString(r.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &db.AccessToken{
		Token:     tstr,
		Expired:   iat.Add(accessTokenExpiresIn),
		ExpiresIn: int(accessTokenExpiresIn.Seconds()),
		OwnerID:   ownerId,
		Scope:     scope,
	}, nil
}

func (r *AccessToken) Get(token string) (*db.AccessToken, error) {
	c := new(myClaims)
	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != SigningMethodVirgilCrypt.Alg() {
			return nil, jwt.NewValidationError(fmt.Sprintf("signing method %v is invalid", t.Method.Alg()), jwt.ValidationErrorSignatureInvalid)
		}

		return r.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	iat, eat := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	return &db.AccessToken{
		Token:     token,
		ExpiresIn: int(eat.Sub(iat).Seconds()),
		Expired:   eat.UTC(),
		OwnerID:   c.OwnerID,
		Scope:     c.Scope,
	}, nil
}

type SigningMethodVirgil struct {
}

var SigningMethodVirgilCrypt *SigningMethodVirgil = &SigningMethodVirgil{}

func init() {
	jwt.RegisterSigningMethod(SigningMethodVirgilCrypt.Alg(), func() jwt.SigningMethod {
		return SigningMethodVirgilCrypt
	})
}

func (s *SigningMethodVirgil) Verify(signingString, signature string, key interface{}) error { // Returns nil if signature is valid
	k, ok := key.(virgilcrypto.PublicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	// Decode signature, for comparison
	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	ok, err = virgilcrypto.DefaultCrypto.Verify([]byte(signingString), sig, k)
	if err != nil {
		return err
	}

	if !ok {
		return jwt.ErrSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil

}
func (s *SigningMethodVirgil) Sign(signingString string, key interface{}) (string, error) { // Returns encoded signature or error
	k, ok := key.(virgilcrypto.PrivateKey)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}
	sig, err := virgilcrypto.DefaultCrypto.Sign([]byte(signingString), k)
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(sig), nil
}

func (s *SigningMethodVirgil) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return "virgil"
}
