package app

import (
	"log"
	"os"

	"github.com/valyala/fasthttp"
	crypto "github.com/virgilsecurity/virgil-crypto-go"
	"github.com/virgilsecurity/virgil-services-auth/core/handlers"
	"github.com/virgilsecurity/virgil-services-auth/db/repo"
	"github.com/virgilsecurity/virgil-services-auth/http"
	"github.com/virgilsecurity/virgil-services-auth/services"
	"gopkg.in/mgo.v2"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/transport/virgilhttp"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
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

	privk, err := virgil.Crypto().ImportPrivateKey([]byte(conf.PrivateServiceKey), "")
	if err != nil {
		logger.Fatalf("Cannot import private.key: %v", err)
	}
	pubk, err := privk.ExtractPublicKey()
	if err != nil {
		logger.Fatalf("Cannot extract public key: %v", err)
	}

	var clientOptions []func(*virgil.Client)
	if conf.VirgilClient.Host != "" {
		clientOptions = append(clientOptions, virgil.ClientTransport(virgilhttp.NewTransportClient(conf.VirgilClient.Host, conf.VirgilClient.Host, conf.VirgilClient.Host)))
	}
	if conf.VirgilClient.AuthorityCardID != "" && conf.VirgilClient.AuthorityPublicKey != "" {
		pub, err := virgil.Crypto().ImportPublicKey([]byte(conf.VirgilClient.AuthorityPublicKey))
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
