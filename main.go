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
	flag.StringVar(&config.VirgilClient.APIKeyID, "api-key-id", "", "(*) Virgil API key id")
	flag.StringVar(&config.VirgilClient.APIKeyStr, "api-key", "", "(*) Virgil API key")
	flag.StringVar(&config.VirgilClient.APIKeyPassword, "api-key-password", "", "(*) Virgil API key password")
	flag.StringVar(&config.VirgilClient.AppID, "app-id", "", "(*) Virgil application id")
	flag.StringVar(&config.VirgilClient.Host, "virgil-api-address", "https://api.virgilsecurity.com", "Address of Virgil cloud")
	flag.StringVar(&config.PrivateServiceKey.Key, "key", "", `(*) Private key for response signing and message decryption (encoded into bas64)`)
	flag.StringVar(&config.PrivateServiceKey.Password, "key-password", "", `Passphrase for the private key`)
	flag.StringVar(&config.VirgilClient.AuthorityCardID, "authority-id", "", "Authority card id. A client's card must have signature of the authority. By default usage Virgil Cards Service id.")
	flag.StringVar(&config.VirgilClient.AuthorityPublicKey, "authority-pubkey", "", "Authority public key (encoded into bas64).  Authority card id. A client's card must have signature of the authority. By default usege Virgil Cards Service public key.")
	flag.StringVar(&address, "address", ":8080", "Virgil Auth service address")
}

func main() {
	config.Version = Version
	flag.Parse()
	app.Init(config)
	app.Run(address)
}
