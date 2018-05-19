package services

import (
	"bytes"

	"gopkg.in/virgil.v5/cryptoapi"
)

type CryptoProvider interface {
	Encrypt(data []byte, key ...interface {
		IsPublic() bool
		Identifier() []byte
	}) ([]byte, error)
	Decrypt(cipherData []byte, key interface {
		IsPrivate() bool
		Identifier() []byte
	}) ([]byte, error)
	Sign(data []byte, key interface {
		IsPrivate() bool
		Identifier() []byte
	}) ([]byte, error)
}
type Crypto struct {
	PrivateKey cryptoapi.PrivateKey
	Crypto     CryptoProvider
}

func (c *Crypto) Encrypt(data []byte, recipient cryptoapi.PublicKey) ([]byte, error) {
	return c.Crypto.Encrypt(data, recipient)
}
func (c *Crypto) Validate(CipherData, plainData []byte) bool {
	decryptData, _ := c.Crypto.Decrypt(CipherData, c.PrivateKey)

	return bytes.Equal(decryptData, plainData)
}

func (c *Crypto) Sign(data []byte) ([]byte, error) {
	return c.Crypto.Sign(data, c.PrivateKey)
}
