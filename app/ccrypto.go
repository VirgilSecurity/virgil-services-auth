//+build c_crypto

package app

import (
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

func setupCrypto(useSha256Fingerprints bool) {
	c := virgil_crypto_go.NewVirgilCrypto()
	c.UseSha256Fingerprints = useSha256Fingerprints
	crypto = c
	cardCrypto = &virgil_crypto_go.CardCrypto{Crypto: c}
	tokenSigner = virgil_crypto_go.NewVirgilAccessTokenSigner()
}
