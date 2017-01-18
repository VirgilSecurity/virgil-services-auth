package main

import (
	"github.com/VirgilSecurity/virgil-services-auth/app"
	"github.com/namsral/flag"
)

var (
	config  app.Config
	address string
)

func init() {
	flag.StringVar(&config.DBConnection, "db", "127.0.0.1:27017", "Connection string to mongodb")
	flag.StringVar(&config.VirgilClient.Token, "token", "", "(*) Token for connect to other our services")
	flag.StringVar(&config.VirgilClient.Host, "host", "", "Domain of Card service. By default use Virgil Cards service")
	flag.StringVar(&config.PrivateServiceKey, "key", "", `(*) Private key for response signing and message decryption (encoded into bas64)`)
	flag.StringVar(&address, "address", ":8080", "Service address")
	flag.StringVar(&config.VirgilClient.AuthorityCardID, "authid", "", "Authority card id. All client card must be signed the Authority. By default usege Virgil Cards Service id.")
	flag.StringVar(&config.VirgilClient.AuthorityPublicKey, "authpubkey", "", "Authority public key (encoded into bas64).  All client card must be signed the Authority. By default usege Virgil Cards Service public key.")
}

func main() {
	flag.Parse()
	app.Init(config)
	app.Run(address)
}
