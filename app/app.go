package app

import (
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
)

type VirgilClient struct {
	Token              string
	Host               string
	AuthorityCardID    string
	AuthorityPublicKey string
}
type PrivateKey struct {
	Key      string
	Passowrd string
}
type Config struct {
	DBConnection      string
	VirgilClient      VirgilClient
	PrivateServiceKey PrivateKey
}

var (
	server fasthttp.Server
	logger *log.Logger
)

func Init(conf Config) {
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)

	if conf.DBConnection == "" || conf.VirgilClient.Token == "" || conf.PrivateServiceKey.Key == "" {
		logger.Fatalf("Required arguments were not filled. Run '[CMD] --help' for more information. Required arguments are marked *")
	}

	session, err := mgo.Dial(conf.DBConnection)
	if err != nil {
		logger.Fatalf("Cannot connect to db: %+v", err)
	}
	db := session.DB("")

	privk, err := virgil.Crypto().ImportPrivateKey([]byte(conf.PrivateServiceKey.Key), conf.PrivateServiceKey.Passowrd)
	if err != nil {
		logger.Fatalf("Cannot import private.key: %+v", err)
	}
	pubk, err := privk.ExtractPublicKey()
	if err != nil {
		logger.Fatalf("Cannot extract public key: %+v", err)
	}

	var clientOptions []func(*virgil.Client)
	if conf.VirgilClient.Host != "" {
		clientOptions = append(clientOptions, virgil.ClientTransport(virgilhttp.NewTransportClient(conf.VirgilClient.Host, conf.VirgilClient.Host, conf.VirgilClient.Host, conf.VirgilClient.Host)))
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
		logger.Fatalf("Cannot create virgil client: %+v", err)
	}

	var checkCardId = conf.VirgilClient.AuthorityCardID
	if checkCardId == "" {
		checkCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853" // Virgil Card service
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
		HealthChecker: &http.HealthChecker{
			CheckList: []http.Checker{
				&repo.HealthChecker{
					S: session,
				},
				&services.CardsServiceHealthChecker{
					Vclient: virgilClient,
					CardId:  checkCardId,
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
