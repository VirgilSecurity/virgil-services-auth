//+build !c_crypto

package app

import (
	"gopkg.in/virgil.v5/cryptoimpl"
)

func setupCrypto(useSha256Fingerprints bool) {
	c := cryptoimpl.NewVirgilCrypto()
	c.UseSHA256Fingerprints = useSha256Fingerprints

	crypto = c
	cardCrypto = &cryptoimpl.VirgilCardCrypto{
		Crypto: c,
	}
	tokenSigner = cryptoimpl.NewVirgilAccessTokenSigner()
}
