package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"gopkg.in/mgo.v2"
	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/cryptoimpl"
	virgil "gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-services-auth/app"
)

type entity struct {
	SK   cryptoapi.PrivateKey
	PK   cryptoapi.PublicKey
	ID   string
	Card *virgil.RawSignedModel
}

type Config struct {
	authority         entity
	client            entity
	untrustedClient   entity
	authServicePK     cryptoapi.PublicKey
	authServiceSK     cryptoapi.PrivateKey
	Crypto            *cryptoimpl.VirgilCrypto
	CardCrypto        *cryptoimpl.VirgilCardCrypto
	AccessTokenSigner *cryptoimpl.VirgilAccessTokenSigner
	cardsHost         string
	apiKey            cryptoapi.PrivateKey
	apiKeyID          string
	authHost          string
	DBConnection      string
	appID             string
	session           *mgo.Session
}

var config Config

func setupDB(dbconn string) {
	config.DBConnection = dbconn

	session, err := mgo.Dial(dbconn)
	if err != nil {
		fmt.Println("Cannot connect to db:", err)
		os.Exit(1)
	}
	config.session = session
}

func setupAuthority() {
	keyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Authority cannot generate Keypair:", err)
		os.Exit(1)
	}
	req, err := virgil.GenerateRawCard(config.CardCrypto, &virgil.CardParams{
		Identity:   "root",
		PublicKey:  keyPair.PublicKey(),
		PrivateKey: keyPair.PrivateKey(),
	}, time.Now())
	if err != nil {
		fmt.Println("Authority create card request:", err)
		os.Exit(1)
	}

	signer := virgil.ModelSigner{Crypto: config.CardCrypto}
	err = signer.SelfSign(req, keyPair.PrivateKey(), nil)
	if err != nil {
		fmt.Println("Authority cannot add self sign:", err)
		os.Exit(1)
	}

	id, _ := virgil.GenerateCardId(config.CardCrypto, req.ContentSnapshot)
	config.authority = entity{
		PK:   keyPair.PublicKey(),
		SK:   keyPair.PrivateKey(),
		ID:   id,
		Card: req,
	}
}

func setupClient() {
	keyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Client cannot generate Keypair:", err)
		os.Exit(1)
	}
	req, err := virgil.GenerateRawCard(config.CardCrypto, &virgil.CardParams{
		Identity:   "bob",
		PublicKey:  keyPair.PublicKey(),
		PrivateKey: keyPair.PrivateKey(),
	}, time.Now())
	if err != nil {
		fmt.Println("Client create card request:", err)
		os.Exit(1)
	}

	signer := virgil.ModelSigner{Crypto: config.CardCrypto}
	signer.Sign(req, config.authority.ID, config.authority.SK, nil)
	err = signer.SelfSign(req, keyPair.PrivateKey(), nil)
	if err != nil {
		fmt.Println("Client client create card request:", err)
		os.Exit(1)
	}

	v, _ := virgil.NewVirgilCardVerifier(config.CardCrypto, true, false, virgil.NewWhitelist(&virgil.VerifierCredentials{
		Signer:    config.authority.ID,
		PublicKey: config.authority.PK,
	}))
	card, _ := virgil.ParseRawCard(config.CardCrypto, req, false)
	if err := v.VerifyCard(card); err != nil {
		panic(err)
	}

	id, _ := virgil.GenerateCardId(config.CardCrypto, req.ContentSnapshot)
	config.client = entity{
		PK:   keyPair.PublicKey(),
		SK:   keyPair.PrivateKey(),
		ID:   id,
		Card: req,
	}
}

func setupUntrustedClient() {
	keyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Untrusted client cannot generate Keypair:", err)
		os.Exit(1)
	}
	req, err := virgil.GenerateRawCard(config.CardCrypto, &virgil.CardParams{
		Identity:   "alice",
		PublicKey:  keyPair.PublicKey(),
		PrivateKey: keyPair.PrivateKey(),
	}, time.Now())
	if err != nil {
		fmt.Println("Untrusted client create card request:", err)
		os.Exit(1)
	}
	signer := virgil.ModelSigner{Crypto: config.CardCrypto}
	err = signer.SelfSign(req, keyPair.PrivateKey(), nil)
	if err != nil {
		fmt.Println("Untrusted cannot add self sign:", err)
		os.Exit(1)
	}

	id, _ := virgil.GenerateCardId(config.CardCrypto, req.ContentSnapshot)
	config.untrustedClient = entity{
		PK:   keyPair.PublicKey(),
		SK:   keyPair.PrivateKey(),
		ID:   id,
		Card: req,
	}
}

func setupCardsService() {
	kp, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Cannot generate API key")
		os.Exit(1)
	}

	config.apiKey = kp.PrivateKey()
	config.apiKeyID = "integration tests"
	config.appID = "test auth app id"

	cards := map[string]*virgil.RawSignedModel{
		config.authority.ID:       config.authority.Card,
		config.client.ID:          config.client.Card,
		config.untrustedClient.ID: config.untrustedClient.Card,
	}

	jwtVerifier := virgil.NewJwtVerifier(kp.PublicKey(), config.apiKeyID, config.AccessTokenSigner)

	handler := func(ctx *fasthttp.RequestCtx) {
		token := ctx.Request.Header.Peek("Authorization")[len("Virgil "):]
		jwt, err := virgil.JwtFromString(string(token))
		if err != nil {
			ctx.Error(`{"code":20302,"message":"unauthorized"}`, fasthttp.StatusUnauthorized)
			return
		}
		if err = jwtVerifier.VerifyToken(jwt); err != nil {
			ctx.Error(`{"code":20302,"message":"unauthorized"}`, fasthttp.StatusUnauthorized)
			return
		}
		if jwt.BodyContent.AppID != config.appID {
			ctx.Error(`{"code":20302,"message":"unauthorized"}`, fasthttp.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(string(ctx.Path()), "/card/v5") {
			ctx.Error("", fasthttp.StatusNotFound)
			return
		}
		id := ctx.Path()[len("/card/v5/"):]
		if v, ok := cards[string(id)]; ok {
			b, _ := json.Marshal(v)
			ctx.Write(b)
			return
		}
		ctx.Error("", fasthttp.StatusNotFound)
	}

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Cannot start listen a fake cards service")
		os.Exit(1)
	}
	go fasthttp.Serve(l, handler)

	config.cardsHost = "http://" + l.Addr().String()
}

func setupAuthService() {
	pk, err := config.Crypto.ExportPublicKey(config.authority.PK)
	if err != nil {
		fmt.Println("Cannot start listen a fake cards service")
		os.Exit(1)
	}
	sk, err := config.Crypto.ExportPrivateKey(config.authServiceSK, "123")
	if err != nil {
		fmt.Println("Cannot start listen a fake cards service")
		os.Exit(1)
	}
	apiKeyStr, err := config.Crypto.ExportPrivateKey(config.apiKey, "431")
	if err != nil {
		fmt.Println("Cannot export API key")
		os.Exit(1)
	}
	app.Init(app.Config{
		DBConnection: config.DBConnection,
		VirgilClient: app.VirgilClient{
			APIKeyID:           config.apiKeyID,
			APIKeyStr:          string(apiKeyStr),
			APIKeyPassword:     "431",
			Host:               config.cardsHost,
			AuthorityCardID:    config.authority.ID,
			AuthorityPublicKey: string(pk),
			AppID:              config.appID,
		},
		PrivateServiceKey: app.PrivateKey{
			Key:      string(sk),
			Password: "123",
		},
	})
	go app.Run(":8080")
}

func clear() {
	config.session.DB("auth").DropDatabase()
	config.session.Clone()
}
