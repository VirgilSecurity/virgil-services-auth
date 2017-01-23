package integration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/VirgilSecurity/virgil-services-auth/app"
	"github.com/valyala/fasthttp"
	"gopkg.in/mgo.v2"
	virgil "gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type card struct {
	ID       string   `json:"id"`
	Snapshot []byte   `json:"content_snapshot"`
	Meta     cardMeta `json:"meta"`
}

type cardMeta struct {
	CreatedAt   string            `json:"created_at"`
	CardVersion string            `json:"card_version"`
	Signs       map[string][]byte `json:"signs"`
}

type entity struct {
	KeyPair virgilcrypto.Keypair
	Card    card
}

type Config struct {
	authority          entity
	client             entity
	untrustedClient    entity
	authServiceKeyPair virgilcrypto.Keypair
	Crypto             virgilcrypto.Crypto
	cardsHost          string
	token              string
	authHost           string
	DBConnection       string
	session            *mgo.Session
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
	req, err := virgil.NewCreateCardRequest("root", "type", keyPair.PublicKey(), virgil.CardParams{})
	if err != nil {
		fmt.Println("Authority create card request:", err)
		os.Exit(1)
	}

	signer := virgil.RequestSigner{}
	signer.SelfSign(req, keyPair.PrivateKey())

	config.authority.KeyPair = keyPair
	config.authority.Card = card{
		ID:       hex.EncodeToString(config.Crypto.CalculateFingerprint(req.Snapshot)),
		Snapshot: req.Snapshot,
		Meta: cardMeta{
			CreatedAt:   "today",
			CardVersion: "v4",
			Signs:       req.Meta.Signatures,
		},
	}
}

func setupClient() {
	keyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Client cannot generate Keypair:", err)
		os.Exit(1)
	}
	req, err := virgil.NewCreateCardRequest("bob", "type", keyPair.PublicKey(), virgil.CardParams{})
	if err != nil {
		fmt.Println("Client create card request:", err)
		os.Exit(1)
	}

	signer := virgil.RequestSigner{}
	signer.SelfSign(req, keyPair.PrivateKey())
	signer.AuthoritySign(req, config.authority.Card.ID, config.authority.KeyPair.PrivateKey())

	config.client.KeyPair = keyPair
	config.client.Card = card{
		ID:       hex.EncodeToString(config.Crypto.CalculateFingerprint(req.Snapshot)),
		Snapshot: req.Snapshot,
		Meta: cardMeta{
			CreatedAt:   "today",
			CardVersion: "v4",
			Signs:       req.Meta.Signatures,
		},
	}
}

func setupUntrustedClient() {
	keyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Untrusted client cannot generate Keypair:", err)
		os.Exit(1)
	}
	req, err := virgil.NewCreateCardRequest("bob", "type", keyPair.PublicKey(), virgil.CardParams{})
	if err != nil {
		fmt.Println("Untrusted client create card request:", err)
		os.Exit(1)
	}

	signer := virgil.RequestSigner{}
	signer.SelfSign(req, keyPair.PrivateKey())

	config.untrustedClient.KeyPair = keyPair
	config.untrustedClient.Card = card{
		ID:       hex.EncodeToString(config.Crypto.CalculateFingerprint(req.Snapshot)),
		Snapshot: req.Snapshot,
		Meta: cardMeta{
			CreatedAt:   "today",
			CardVersion: "v4",
			Signs:       req.Meta.Signatures,
		},
	}
}

func setupCardsService() {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	authHeader := "VIRGIL " + token

	cards := map[string]card{
		config.authority.Card.ID:       config.authority.Card,
		config.client.Card.ID:          config.client.Card,
		config.untrustedClient.Card.ID: config.untrustedClient.Card,
	}
	handler := func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Request.Header.Peek("Authorization")) != authHeader {
			ctx.Error(`{"code":20302}`, fasthttp.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(string(ctx.Path()), "/v4/card/") {
			ctx.Error("", fasthttp.StatusNotFound)
			return
		}
		id := ctx.Path()[len("/v4/card/"):]
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
	config.token = token
}

func setupAuthService() {
	pub, err := config.authority.KeyPair.PublicKey().Encode()
	if err != nil {
		fmt.Println("Cannot start listen a fake cards service")
		os.Exit(1)
	}
	priv, err := config.authServiceKeyPair.PrivateKey().Encode([]byte("123"))
	if err != nil {
		fmt.Println("Cannot start listen a fake cards service")
		os.Exit(1)
	}
	app.Init(app.Config{
		DBConnection: config.DBConnection,
		VirgilClient: app.VirgilClient{
			Token:              config.token,
			Host:               config.cardsHost,
			AuthorityCardID:    config.authority.Card.ID,
			AuthorityPublicKey: string(pub),
		},
		PrivateServiceKey: app.PrivateKey{
			Key:      string(priv),
			Passowrd: "123",
		},
	})
	go app.Run(":8080")
}

func clear() {
	config.session.DB("auth").DropDatabase()
	config.session.Clone()
}
