package repo

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/cryptoimpl"
)

var appPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICM4hGSdeteNCGAmgI1rYo9lEq91bsgqIIOs4mC4h+IK
-----END PRIVATE KEY-----`)

func TestReversibility(t *testing.T) {
	crypto := cryptoimpl.NewVirgilCrypto()
	kpriv, _ := crypto.ImportPrivateKey(appPrivateKey, "")
	kpub, _ := crypto.ExtractPublicKey(kpriv)
	a := AccessToken{PrivateKey: kpriv, PublicKey: kpub, Crypto: crypto}

	t1, err := a.Make("ownerId", "test_scope")
	require.NoError(t, err)
	t2, err := a.Get(t1.Token)

	require.NoError(t, err)
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
