//+build c_crypto

package app

import (
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

func init() {
	crypto = virgil_crypto_go.NewVirgilCrypto()
	cardCrypto = virgil_crypto_go.NewVirgilCardCrypto()
	tokenSigner = virgil_crypto_go.NewVirgilAccessTokenSigner()
}
