// +build integration

package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/namsral/flag"
	"github.com/stretchr/testify/assert"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
	"gopkg.in/virgil.v5/cryptoimpl"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
	"github.com/VirgilSecurity/virgil-services-auth/db/repo"
)

var (
	dbConnection string
)

func init() {
	flag.StringVar(&dbConnection, "db", "127.0.0.1:27017", "Connection string to mongodb")
}

func TestMain(m *testing.M) {
	flag.Parse()

	config.Crypto = cryptoimpl.NewVirgilCrypto()
	config.CardCrypto = cryptoimpl.NewVirgilCardCrypto()
	config.AccessTokenSigner = cryptoimpl.NewVirgilAccessTokenSigner()

	setupDB(dbConnection)
	setupAuthority()
	setupClient()
	setupUntrustedClient()
	setupCardsService()

	authKeyPair, err := config.Crypto.GenerateKeypair()
	if err != nil {
		fmt.Println("Cannot generate Keypair:", err)
		os.Exit(1)
	}
	config.authServicePK = authKeyPair.PublicKey()
	config.authServiceSK = authKeyPair.PrivateKey()

	setupAuthService()
	code := m.Run()
	clear()
	os.Exit(code)
}

func TestCorrectScenario(t *testing.T) {
	c := MakeClient()
	msg, err := c.GetMessage(config.client.ID)
	require.Nil(t, err)

	rMsg, err := config.Crypto.Decrypt(msg.Message, config.client.SK)
	require.Nil(t, err)
	eMsg, err := config.Crypto.Encrypt(rMsg, config.authServicePK)
	require.Nil(t, err)
	code, err := c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: msg.AttemptId,
	})
	require.Nil(t, err)

	token1, err := c.GetToken(code)
	require.Nil(t, err)

	actual1, err := c.Verify(token1.Token)
	require.Nil(t, err)

	token2, err := c.Refresh(token1.Refresh)
	require.Nil(t, err)

	actual2, err := c.Verify(token2.Token)
	require.Nil(t, err)

	require.Equal(t, config.client.ID, actual1)
	require.Equal(t, config.client.ID, actual2)
}

func TestGetCode_SendBrokenMessage_Err(t *testing.T) {
	c := MakeClient()
	msg, err := c.GetMessage(config.client.ID)
	assert.Nil(t, err)

	_, err = c.GetCode(core.EncryptedMessage{
		Message:   []byte(`Broken message`),
		AttemptId: msg.AttemptId,
	})
	assert.Equal(t, &errorResponse{Code: core.StatusErrorEncryptedMessageValidationFailed, StatusCode: http.StatusBadRequest}, err)
}

func TestGetCode_SendBrokenEncryptedMessage_Err(t *testing.T) {
	c := MakeClient()
	msg, err := c.GetMessage(config.client.ID)
	assert.Nil(t, err)

	eMsg, err := config.Crypto.Encrypt([]byte(`Broken message`), config.authServicePK)
	assert.Nil(t, err)

	_, err = c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: msg.AttemptId,
	})
	assert.Equal(t, &errorResponse{Code: core.StatusErrorEncryptedMessageValidationFailed, StatusCode: http.StatusBadRequest}, err)
}

func TestGetCode_AttemptIdIncorrect_Err(t *testing.T) {
	c := MakeClient()
	_, err := c.GetCode(core.EncryptedMessage{
		Message:   []byte(`asdf`),
		AttemptId: "broken id",
	})
	assert.Equal(t, &errorResponse{StatusCode: http.StatusNotFound}, err)
}

func TestGetMessage_CardIdIvalid_Err(t *testing.T) {
	c := MakeClient()
	// len must 64 and it should be hex
	b := make([]byte, 32)
	_, err := c.GetMessage(hex.EncodeToString(b))
	assert.Equal(t, &errorResponse{Code: core.StatusErrorCardNotFound, StatusCode: http.StatusBadRequest}, err)
}

func TestGetToken_IncorrectCode_Err(t *testing.T) {
	c := MakeClient()
	_, err := c.GetToken("incorrect code")
	assert.Equal(t, &errorResponse{Code: core.StatusErrorCodeNotFound, StatusCode: http.StatusBadRequest}, err)
}

func TestVerify_IncorrectToken1_Err(t *testing.T) {
	c := MakeClient()
	_, err := c.Verify("incorrect token")
	assert.Equal(t, &errorResponse{Code: core.StatusErrorAccessTokenBroken, StatusCode: http.StatusBadRequest}, err)
}

func TestVerify_IncorrectToken2_Err(t *testing.T) {
	c := MakeClient()
	_, err := c.Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
	assert.Equal(t, &errorResponse{Code: core.StatusErrorAccessTokenBroken, StatusCode: http.StatusBadRequest}, err)
}

func TestRefresh_IncorrectRefreshToken_Err(t *testing.T) {
	c := MakeClient()
	_, err := c.Refresh("incorrect refresh token")
	assert.Equal(t, &errorResponse{Code: core.StatusErrorRefreshTokenNotFound, StatusCode: http.StatusBadRequest}, err)
}

func TestVerify_TokenExpired_ReturnErr(t *testing.T) {
	iat := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	token := jwt.NewWithClaims(repo.SigningMethodVirgilCrypt, jwt.StandardClaims{
		ExpiresAt: iat.Add(10 * time.Minute).Unix(),
		IssuedAt:  iat.Unix(),
		Issuer:    "Virgil Security, Inc",
	})
	tstr, err := token.SignedString(repo.KeyCryptoPair{Crypto: config.Crypto, Key: config.authServiceSK})
	assert.Nil(t, err)
	c := MakeClient()

	_, err = c.Verify(tstr)

	assert.Equal(t, &errorResponse{Code: core.StatusErrorAccessTokenExpired, StatusCode: http.StatusBadRequest}, err)
}

func Test_GetTokenByOneCode_ReturnErr(t *testing.T) {

	c := MakeClient()
	msg, err := c.GetMessage(config.client.ID)
	assert.Nil(t, err)

	rMsg, err := config.Crypto.Decrypt(msg.Message, config.client.SK)
	assert.Nil(t, err)
	eMsg, err := config.Crypto.Encrypt(rMsg, config.authServicePK)
	assert.Nil(t, err)
	code, err := c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: msg.AttemptId,
	})
	assert.Nil(t, err)

	_, err = c.GetToken(code)
	assert.Nil(t, err)

	_, err = c.GetToken(code)
	assert.Equal(t, &errorResponse{Code: core.StatusErrorCodeWasUsed, StatusCode: http.StatusBadRequest}, err)
}

func TestGetMessage_ReqBodyNil_ReturnErr(t *testing.T) {
	resp, err := http.Post("http://localhost:8080/v5/authorization-grant/actions/get-challenge-message", "application/json", nil)
	assert.Nil(t, err)
	defer resp.Body.Close()

	b, _ := ioutil.ReadAll(resp.Body)
	e := &errorResponse{
		StatusCode: resp.StatusCode,
	}
	err = json.Unmarshal(b, e)
	assert.Nil(t, err)

	assert.Equal(t, &errorResponse{Code: core.StatusErrorUUIDValidFailed, StatusCode: http.StatusBadRequest}, e)
}

func TestGetMessage_ReqBodyIncorrect_ReturnErr(t *testing.T) {
	resp, err := http.Post("http://localhost:8080/v5/authorization-grant/actions/get-challenge-message", "application/json", ioutil.NopCloser(strings.NewReader("{}")))
	assert.Nil(t, err)
	defer resp.Body.Close()

	b, _ := ioutil.ReadAll(resp.Body)
	e := &errorResponse{
		StatusCode: resp.StatusCode,
	}
	err = json.Unmarshal(b, e)
	assert.Nil(t, err)

	assert.Equal(t, &errorResponse{Code: core.StatusErrorUUIDValidFailed, StatusCode: http.StatusBadRequest}, e)
}

func TestGetToken_UnsupportedGrantType_ReturnErr(t *testing.T) {
	b, _ := json.Marshal(core.AccessCode{
		GrantType: "broken",
		Code:      "",
	})
	resp, err := http.Post("http://localhost:8080/v5/authorization/actions/obtain-access-token", "application/json", ioutil.NopCloser(bytes.NewReader(b)))
	assert.Nil(t, err)
	defer resp.Body.Close()

	b, _ = ioutil.ReadAll(resp.Body)
	e := &errorResponse{
		StatusCode: resp.StatusCode,
	}
	err = json.Unmarshal(b, e)
	assert.Nil(t, err)

	assert.Equal(t, &errorResponse{Code: core.StatusErrorUnsupportedGrantType, StatusCode: http.StatusBadRequest}, e)
}

func TestRefresh_UnsupportedGrantType_ReturnErr(t *testing.T) {
	b, _ := json.Marshal(core.Token{
		Type: "broken",
	})
	resp, err := http.Post("http://localhost:8080/v5/authorization/actions/refresh-access-token", "application/json", ioutil.NopCloser(bytes.NewReader(b)))
	assert.Nil(t, err)
	defer resp.Body.Close()

	b, _ = ioutil.ReadAll(resp.Body)
	e := &errorResponse{
		StatusCode: resp.StatusCode,
	}
	err = json.Unmarshal(b, e)
	assert.Nil(t, err)

	assert.Equal(t, &errorResponse{Code: core.StatusErrorUnsupportedGrantType, StatusCode: http.StatusBadRequest}, e)
}

func TestGetToken_CodeExpired_ReturnErr(t *testing.T) {
	cb := make([]byte, 32)
	rand.Read(cb)
	code := hex.EncodeToString(cb)

	c := MakeClient()

	codes := config.session.DB("").C("code")
	codes.Insert(db.Code{
		Code:    code,
		OwnerID: "123",
		Used:    false,
		Expired: time.Now().UTC().Add(-repo.CodeExpiresIn),
	})
	cccc := new(db.Code)
	codes.FindId(code).One(cccc)
	_, err := c.GetToken(code)
	assert.Equal(t, &errorResponse{Code: core.StatusErrorCodeExpired, StatusCode: http.StatusBadRequest}, err)
}

func TestGetCode_AttemptExpired_ReturnErr(t *testing.T) {
	cb := make([]byte, 32)
	rand.Read(cb)
	code := hex.EncodeToString(cb)

	c := MakeClient()
	attempts := config.session.DB("").C("attempt")
	attempts.Insert(db.Attempt{
		OwnerID: "123",
		Message: "secret message",
		ID:      code,
		Expired: time.Now().UTC().Add(-repo.AttemptExpiresIn),
	})

	eMsg, err := config.Crypto.Encrypt([]byte("secret message"), config.authServicePK)
	assert.Nil(t, err)

	_, err = c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: code,
	})

	assert.Equal(t, &errorResponse{StatusCode: http.StatusNotFound}, err)
}

func TestGetCode_AttemptUseTwice_ReturnErr(t *testing.T) {
	c := MakeClient()
	msg, err := c.GetMessage(config.client.ID)
	assert.Nil(t, err)

	rMsg, err := config.Crypto.Decrypt(msg.Message, config.client.SK)
	assert.Nil(t, err)
	eMsg, err := config.Crypto.Encrypt(rMsg, config.authServicePK)
	assert.Nil(t, err)

	_, err = c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: msg.AttemptId,
	})
	assert.Nil(t, err)

	_, err = c.GetCode(core.EncryptedMessage{
		Message:   eMsg,
		AttemptId: msg.AttemptId,
	})
	assert.Equal(t, &errorResponse{StatusCode: http.StatusNotFound}, err)
}

func TestHealthStatus(t *testing.T) {
	resp, err := http.Get("http://localhost:8080/v5/health/status")

	assert.Nil(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

type healthInfo struct {
	Status  int
	Latency float64
}

func TestHealthInfo(t *testing.T) {
	resp, err := http.Get("http://localhost:8080/v5/health/info")

	assert.Nil(t, err)
	b, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	health := make(map[string]healthInfo)
	json.Unmarshal(b, &health)
	mongo := health["mongo"]
	assert.Equal(t, http.StatusOK, mongo.Status)
}

func TestGetMessage_CardNotGlobal_ReturnErr(t *testing.T) {
	c := MakeClient()
	_, err := c.GetMessage(config.untrustedClient.ID)
	assert.Equal(t, &errorResponse{StatusCode: http.StatusBadRequest, Code: core.StatusErrorCardInvalid}, err)
}
