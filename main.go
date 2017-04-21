package main

import (
	"github.com/VirgilSecurity/virgil-services-auth/app"
	"github.com/namsral/flag"
)

var (
	config  app.Config
	Version string
	address string
)

func init() {
	flag.StringVar(&config.DBConnection, "db", "127.0.0.1:27017/virgil-auth", "Connection string to mongodb")
	flag.StringVar(&config.VirgilClient.Token, "token", "", "(*) Token to get access to Virgil Cards service")
	flag.StringVar(&config.VirgilClient.Host, "cards-address", "", "Address of Cards service. By default used the Virgil Cards service")
	flag.StringVar(&config.PrivateServiceKey.Key, "key", "", `(*) Private key for response signing and message decryption (encoded into bas64)`)
	flag.StringVar(&config.PrivateServiceKey.Passowrd, "key-password", "", `Passphrase for the private key`)
	flag.StringVar(&address, "address", ":8080", "Virgil Auth service address")
	flag.StringVar(&config.VirgilClient.AuthorityCardID, "authority-id", "", "Authority card id. A client's card must have signature of the authority. By default usege Virgil Cards Service id.")
	flag.StringVar(&config.VirgilClient.AuthorityPublicKey, "authority-pubkey", "", "Authority public key (encoded into bas64).  Authority card id. A client's card must have signature of the authority. By default usege Virgil Cards Service public key.")
}

func main() {
	config.Version = Version
	flag.Parse()
	app.Init(config)
	app.Run(address)
}
