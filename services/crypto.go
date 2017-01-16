package services

import (
	"bytes"

	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
)

type Crypto struct {
	PrivateKey virgilcrypto.PrivateKey
	Crypto     virgilcrypto.Crypto
}

func (c *Crypto) Encrypt(data []byte, recipient virgilcrypto.PublicKey) ([]byte, error) {
	return c.Crypto.Encrypt(data, recipient)
}
func (c *Crypto) Validate(CipherData, plainData []byte) bool {
	decryptData, _ := c.Crypto.Decrypt(CipherData, c.PrivateKey)

	return bytes.Equal(decryptData, plainData)
}

func (c *Crypto) Sign(data []byte) ([]byte, error) {
	return c.Crypto.Sign(data, c.PrivateKey)
}
