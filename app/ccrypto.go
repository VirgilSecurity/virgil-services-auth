//+build c_crypto

package app

import (
	"gopkg.in/virgil.v4/virgilcrypto"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v4"
)

func init() {
	virgilcrypto.DefaultCrypto = &virgil_crypto_go.NativeCrypto{}
}
