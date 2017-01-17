package repo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"gopkg.in/virgil.v4/virgilcrypto"
)

var appPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICM4hGSdeteNCGAmgI1rYo9lEq91bsgqIIOs4mC4h+IK
-----END PRIVATE KEY-----`)

func TestReversibility(t *testing.T) {
	kpriv, _ := virgilcrypto.DefaultCrypto.ImportPrivateKey(appPrivateKey, "")
	kpub, _ := kpriv.ExtractPublicKey()
	a := AccessToken{PrivateKey: kpriv, PublicKey: kpub}
	t1, _ := a.Make("ownerId", "test_scope")
	t2, _ := a.Get(t1.Token)

	assert.Equal(t, t1, t2)
}

func TestGet_ParsReturnErr_ReturnErr(t *testing.T) {
	a := AccessToken{}
	_, err := a.Get("")
	assert.NotNil(t, err)
}

func TestVerfy_UnsuportedKey_Err(t *testing.T) {
	s := SigningMethodVirgil{}
	err := s.Verify("signingString", "signature", 12)
	assert.Equal(t, jwt.ErrInvalidKeyType, err)
}

func TestSign_UnsuportedKey_Err(t *testing.T) {
	s := SigningMethodVirgil{}
	_, err := s.Sign("signingString", 12)
	assert.Equal(t, jwt.ErrInvalidKeyType, err)
}
