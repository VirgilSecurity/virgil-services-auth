package app

import (
	"log"
	"os"
	"time"

	"github.com/valyala/fasthttp"
	"gopkg.in/mgo.v2"
	"gopkg.in/virgil.v5/cryptoapi"
	sdk "gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-services-auth/core/handlers"
	"github.com/VirgilSecurity/virgil-services-auth/db/repo"
	"github.com/VirgilSecurity/virgil-services-auth/http"
	"github.com/VirgilSecurity/virgil-services-auth/services"
)

var (
	crypto interface {
		ImportPrivateKey([]byte, string) (interface {
			IsPrivate() bool
			Identifier() []byte
		}, error)
		ImportPublicKey([]byte) (interface {
			IsPublic() bool
			Identifier() []byte
		}, error)

		ExtractPublicKey(interface {
			IsPrivate() bool
			Identifier() []byte
		}) (interface {
			IsPublic() bool
			Identifier() []byte
		}, error)

		Encrypt(data []byte, key ...interface {
			IsPublic() bool
			Identifier() []byte
		}) ([]byte, error)

		Decrypt(cipherData []byte, key interface {
			IsPrivate() bool
			Identifier() []byte
		}) ([]byte, error)

		Sign(data []byte, key interface {
			IsPrivate() bool
			Identifier() []byte
		}) ([]byte, error)

		VerifySignature(data []byte, signature []byte, key interface {
			IsPublic() bool
			Identifier() []byte
		}) (err error)
	}

	cardCrypto cryptoapi.CardCrypto

	tokenSigner interface {
		GenerateTokenSignature(data []byte, privateKey interface {
			IsPrivate() bool
			Identifier() []byte
		}) ([]byte, error)

		VerifyTokenSignature(data []byte, signature []byte, publicKey interface {
			IsPublic() bool
			Identifier() []byte
		}) error

		GetAlgorithm() string
	}
)

type VirgilClient struct {
	APIKeyStr          string
	APIKeyPassword     string
	APIKeyID           string
	AppID              string
	Host               string
	AuthorityCardID    string
	AuthorityPublicKey string
}
type PrivateKey struct {
	Key      string
	Password string
}
type Config struct {
	DBConnection          string
	Version               string
	VirgilClient          VirgilClient
	PrivateServiceKey     PrivateKey
	UseSha256Fingerprints bool
}

var (
	server fasthttp.Server
	logger *log.Logger
)

func Init(conf Config) {

	setupCrypto(conf.UseSha256Fingerprints)
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)

	requiredParams := []string{
		conf.DBConnection,
		conf.VirgilClient.AppID,
		conf.VirgilClient.APIKeyID,
		conf.VirgilClient.APIKeyStr,
		conf.PrivateServiceKey.Key,
	}
	for _, val := range requiredParams {
		if val == "" {
			logger.Fatalf("Required arguments were not filled. Run '[CMD] --help' for more information. Required arguments are marked *")
		}
	}
	db, err := initDB(conf.DBConnection)
	if err != nil {
		logger.Fatalf("Cannot connect to db: %+v", err)
	}

	cardManager, err := initCardManager(conf.VirgilClient)
	if err != nil {
		logger.Fatalf("Cannot init card manager: %+v", err)
	}

	sk, err := crypto.ImportPrivateKey([]byte(conf.PrivateServiceKey.Key), conf.PrivateServiceKey.Password)
	if err != nil {
		logger.Fatalf("Cannot import private.key: %+v", err)
	}
	pk, err := crypto.ExtractPublicKey(sk)
	if err != nil {
		logger.Fatalf("Cannot extract public key: %+v", err)
	}

	routing := http.Router{
		Auth: &http.Auth{
			Handler: &handlers.Auth{
				Logger: logger,
				CodeRepo: &repo.Code{
					C: db.C("code"),
				},
				TokenRepo: &repo.AccessToken{
					PrivateKey: sk,
					PublicKey:  pk,
					Crypto:     crypto,
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
					C: db.C("attempt"),
				},
				Cipher: &services.Crypto{
					PrivateKey: sk,
					Crypto:     crypto,
				},
				Client: cardManager,
			},
		},
		HealthChecker: &http.HealthChecker{
			CheckList: []http.Checker{
				&repo.HealthChecker{
					S: db.Session,
				},
				versionChecker{conf.Version},
			},
		},
	}
	server = fasthttp.Server{
		Handler: routing.Handler,
	}
}

func initDB(conStr string) (*mgo.Database, error) {
	session, err := mgo.Dial(conStr)
	if err != nil {
		return nil, err
	}
	return session.DB(""), nil
}

func initCardManager(conf VirgilClient) (*sdk.CardManager, error) {
	// import a private key
	apiKey, err := crypto.ImportPrivateKey([]byte(conf.APIKeyStr), conf.APIKeyPassword)
	if err != nil {
		logger.Fatalf("Cannot import API key: %+v", err)
	}
	// setup JWT generator
	jwtGenerator := sdk.NewJwtGenerator(apiKey, conf.APIKeyID, tokenSigner, conf.AppID, 24*time.Hour)
	authenticatedQueryToServerSide := func(context *sdk.TokenContext) (*sdk.Jwt, error) {
		return jwtGenerator.GenerateToken("auth service", nil)
	}
	accessTokenProvider := sdk.NewCachingJwtProvider(authenticatedQueryToServerSide)

	// setup card verifier
	var cardVerifier *sdk.VirgilCardVerifier
	if conf.AuthorityPublicKey != "" {
		if conf.AuthorityCardID == "" {
			logger.Fatalf("Authority card id missed")
		}

		authPK, err := crypto.ImportPublicKey([]byte(conf.AuthorityPublicKey))
		if err != nil {
			logger.Fatalf("Cannot import authority public key: %+v", err)
		}

		cardVerifier, err = sdk.NewVirgilCardVerifier(cardCrypto, true, false, sdk.NewWhitelist(&sdk.VerifierCredentials{
			Signer:    conf.AuthorityCardID,
			PublicKey: authPK,
		}))
	} else {
		cardVerifier, err = sdk.NewVirgilCardVerifier(cardCrypto, true, true)
	}

	if err != nil {
		logger.Fatalf("Cannot create Virgil card verifier: %+v", err)
	}

	return sdk.NewCardManager(&sdk.CardManagerParams{
		Crypto:              cardCrypto,
		CardVerifier:        cardVerifier,
		AccessTokenProvider: accessTokenProvider,
		ApiUrl:              conf.Host,
	})
}

func Run(address string) {
	logger.Fatal(server.ListenAndServe(address))
}

type versionChecker struct {
	Version string
}

func (c versionChecker) Name() string {
	return "info"
}
func (c versionChecker) Info() (map[string]interface{}, error) {
	return map[string]interface{}{
		"version": c.Version,
	}, nil
}
