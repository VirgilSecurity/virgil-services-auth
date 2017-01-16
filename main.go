package main

import (
	"github.com/namsral/flag"
	"github.com/virgilsecurity/virgil-services-auth/app"
)

var (
	config  app.Config
	address string
)

func init() {
	flag.StringVar(&config.DBConnection, "db", "", "(*) Connection string to mongodb")
	flag.StringVar(&config.VirgilClient.Token, "token", "", "(*) Token for connect to other our services")
	flag.StringVar(&config.VirgilClient.Host, "host", "", "Domain of Card service. By default use Virgil Cards service")
	flag.StringVar(&config.PrivateServiceKey, "key", "", `(*) Private key for response signing and message decryption`)
	flag.StringVar(&address, "address", ":8080", "Service address")
	flag.StringVar(&config.VirgilClient.AuthorityCardID, "authid", "", "Authority card id. All client card must be signed the Authority. By default usege Virgil Cards Service id.")
	flag.StringVar(&config.VirgilClient.AuthorityPublicKey, "authpubkey", "", "Authority public key.  All client card must be signed the Authority. By default usege Virgil Cards Service public key.")
}

func main() {
	flag.Parse()
	app.Init(config)
	app.Run(address)
}
