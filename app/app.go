package app

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/VirgilSecurity/virgil-services-auth/core/handlers"
	"github.com/VirgilSecurity/virgil-services-auth/db/repo"
	"github.com/VirgilSecurity/virgil-services-auth/http"
	"github.com/VirgilSecurity/virgil-services-auth/services"
	"github.com/valyala/fasthttp"
	"gopkg.in/mgo.v2"
	virgil "gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/transport/virgilhttp"
	"gopkg.in/virgil.v4/virgilcrypto"
	crypto "gopkg.in/virgilsecurity/virgil-crypto-go.v4"
)

type VirgilClient struct {
	Token              string
	Host               string
	AuthorityCardID    string
	AuthorityPublicKey string
}
type Config struct {
	DBConnection      string
	VirgilClient      VirgilClient
	PrivateServiceKey string
}

var (
	server fasthttp.Server
	logger *log.Logger
)

func Init(conf Config) {
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
	virgilcrypto.DefaultCrypto = &crypto.NativeCrypto{}

	if conf.DBConnection == "" || conf.VirgilClient.Token == "" || conf.PrivateServiceKey == "" {
		logger.Fatalf("Required arguments were not filled. Run '[CMD] --help' for more information. Required arguments are marked *")
	}

	session, err := mgo.Dial(conf.DBConnection)
	if err != nil {
		logger.Fatalf("Cannot connect to db: %v", err)
	}
	db := session.DB("auth")

	b, err := base64.StdEncoding.DecodeString(conf.PrivateServiceKey)
	if err != nil {
		logger.Fatalf("Cannot decode key from base64 string: %+v", err)
	}
	privk, err := virgil.Crypto().ImportPrivateKey(b, "")
	if err != nil {
		logger.Fatalf("Cannot import private.key: %v", err)
	}
	pubk, err := privk.ExtractPublicKey()
	if err != nil {
		logger.Fatalf("Cannot extract public key: %v", err)
	}

	var clientOptions []func(*virgil.Client)
	if conf.VirgilClient.Host != "" {
		clientOptions = append(clientOptions, virgil.ClientTransport(virgilhttp.NewTransportClient(conf.VirgilClient.Host, conf.VirgilClient.Host, conf.VirgilClient.Host, conf.VirgilClient.Host)))
	}
	if conf.VirgilClient.AuthorityCardID != "" && conf.VirgilClient.AuthorityPublicKey != "" {
		b, err = base64.StdEncoding.DecodeString(conf.VirgilClient.AuthorityPublicKey)
		if err != nil {
			logger.Fatalf("Cannot decode authpubkey from base64 string: %+v", err)
		}

		pub, err := virgil.Crypto().ImportPublicKey(b)
		if err != nil {
			logger.Fatalf("Cannot import authority public key: %v", err)
		}
		validator := virgil.NewCardsValidator()
		validator.AddVerifier(conf.VirgilClient.AuthorityCardID, pub)
		clientOptions = append(clientOptions, virgil.ClientCardsValidator(validator))
	}

	virgilClient, err := virgil.NewClient(conf.VirgilClient.Token, clientOptions...)
	if err != nil {
		logger.Fatalf("Cannot create virgil client: %v", err)
	}

	routing := http.Router{
		Auth: &http.Auth{
			Handler: &handlers.Auth{
				Logger: logger,
				CodeRepo: &repo.Code{
					C: db.C("code"),
				},
				TokenRepo: &repo.AccessToken{
					PrivateKey: privk,
					PublicKey:  pubk,
				},
				RefreshRepo: &repo.Refresh{
					C: db.C("refresh_token"),
				},
			},
		},
		Grant: &http.Grant{
			Handler: &handlers.Grant{
				Logger: logger,
				MakeCode: &repo.Code{
					C: db.C("code"),
				},
				AttemptRepo: &repo.Attempt{
					C: db.C("attemt"),
				},
				Cipher: &services.Crypto{
					PrivateKey: privk,
					Crypto:     virgil.Crypto(),
				},
				Client: virgilClient,
			},
		},
		HealthChecker: &http.HealthChekcer{
			CheckList: []http.Checker{
				&repo.HealthChecker{
					S: session,
				},
			},
		},
	}
	server = fasthttp.Server{
		Handler: routing.Handler,
	}
}

func Run(address string) {
	logger.Fatal(server.ListenAndServe(address))
}
