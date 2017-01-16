package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
)

func TestReversibility(t *testing.T) {
	pk, _ := virgilcrypto.DefaultCrypto.ImportPrivateKey([]byte(`MC4CAQAwBQYDK2VwBCIEIAMIR/IZeffxbUT+BmbQSWv+E0QELSC9zhwq4jPp0zEp`), "")
	pbk, _ := virgilcrypto.DefaultCrypto.ImportPublicKey([]byte(`MCowBQYDK2VwAyEA9C2xSdT5c+0Y1K87vH0c17gOrAZhXNGxW6sgjotoDOs=`))

	c := Crypto{
		PrivateKey: pk,
		Crypto:     virgilcrypto.DefaultCrypto,
	}
	msg := []byte(`message`)
	emsg, _ := c.Encrypt(msg, pbk)
	ok := c.Validate(emsg, msg)

	assert.True(t, ok)
}

func TestValidate_MsgNotEquals_ReturnFalse(t *testing.T) {
	pk, _ := virgilcrypto.DefaultCrypto.ImportPrivateKey([]byte(`MC4CAQAwBQYDK2VwBCIEIAMIR/IZeffxbUT+BmbQSWv+E0QELSC9zhwq4jPp0zEp`), "")
	pbk, _ := virgilcrypto.DefaultCrypto.ImportPublicKey([]byte(`MCowBQYDK2VwAyEA9C2xSdT5c+0Y1K87vH0c17gOrAZhXNGxW6sgjotoDOs=`))

	c := Crypto{
		PrivateKey: pk,
		Crypto:     virgilcrypto.DefaultCrypto,
	}
	msg := []byte(`message`)
	emsg, _ := c.Encrypt([]byte("broken message"), pbk)
	ok := c.Validate(emsg, msg)

	assert.False(t, ok)
}
