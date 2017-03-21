package handlers

import (
	"fmt"
	"testing"
	"time"

	virgil "gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
	"github.com/stretchr/testify/mock"
)

type FakeLogger struct {
	mock.Mock
}

func (l *FakeLogger) Printf(format string, args ...interface{}) {
	l.Called()
}

type FakeAttemptRepo struct {
	mock.Mock
}

func (s *FakeAttemptRepo) Make(ownerID string, scope string) (a *db.Attempt, err error) {
	args := s.Called(ownerID, scope)
	a, _ = args.Get(0).(*db.Attempt)
	err = args.Error(1)
	return
}

func (s *FakeAttemptRepo) Get(id string) (a *db.Attempt, err error) {
	args := s.Called(id)
	a, _ = args.Get(0).(*db.Attempt)
	err = args.Error(1)
	return
}

func (s *FakeAttemptRepo) Remove(id string) error {
	args := s.Called(id)
	return args.Error(0)
}

type FakeCardClient struct {
	mock.Mock
}

func (c *FakeCardClient) GetCard(id string) (card *virgil.Card, err error) {
	args := c.Called(id)
	card, _ = args.Get(0).(*virgil.Card)
	err = args.Error(1)
	return
}

type FakeMakeCode struct {
	mock.Mock
}

func (m *FakeMakeCode) Make(ownerID string, scope string) (c *db.Code, err error) {
	args := m.Called(ownerID, scope)
	c, _ = args.Get(0).(*db.Code)
	err = args.Error(1)
	return
}

type FakeCipher struct {
	mock.Mock
}

func (c *FakeCipher) Encrypt(data []byte, recipient virgilcrypto.PublicKey) (m []byte, err error) {
	args := c.Called(data, recipient)
	m, _ = args.Get(0).([]byte)
	err = args.Error(1)
	return
}
func (c *FakeCipher) Validate(CipherData, plainData []byte) bool {
	args := c.Called(CipherData, plainData)
	return args.Bool(0)
}

func TestHandshake_CardClientReturnErr_LogAndReturnInternalError(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(nil, fmt.Errorf("format"))

	l := new(FakeLogger)
	l.On("Printf").Once()

	s := Grant{Client: c, Logger: l}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestHandshake_CardNotFound_ReturnCardNotFoundStat(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCardNotFound).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(nil, virgil.ErrNotFound)

	s := Grant{Client: c}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
}

func TestHandshake_CardProtected401_ReturnCardNotFoundStat(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCardNotFound).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(nil, errors.NewServiceError(20300, 401, ""))

	s := Grant{Client: c}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
}

func TestHandshake_CardProtected403_ReturnCardNotFoundStat(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCardNotFound).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(nil, errors.NewServiceError(20500, 403, ""))

	s := Grant{Client: c}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
}

func TestHandshake_CardNotVerified_ReturnCardNotValided(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCardInvalid).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(nil, fmt.Errorf("Card 1234 does not have signature for verifier ID 123432"))

	s := Grant{Client: c}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
}

func TestHandshake_AttemptRepoReturnErr_ReturnInternalErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(&virgil.Card{}, nil)

	l := new(FakeLogger)
	l.On("Printf").Once()

	a := new(FakeAttemptRepo)
	a.On("Make", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	s := Grant{Client: c, Logger: l, AttemptRepo: a}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestHandshake_CipherReturnErr_ReturnInternalErr(t *testing.T) {
	card := &virgil.Card{
		Scope: virgil.CardScope.Global,
	}

	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	c := new(FakeCardClient)
	c.On("GetCard", mock.Anything).Return(card, nil)

	l := new(FakeLogger)
	l.On("Printf").Once()

	a := new(FakeAttemptRepo)
	a.On("Make", mock.Anything, mock.Anything).Return(&db.Attempt{Message: "fake message"}, nil)

	ch := new(FakeCipher)
	ch.On("Encrypt", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	s := Grant{Client: c, Logger: l, AttemptRepo: a, Cipher: ch}
	s.Handshake(resp, core.OwnerCard{ID: "id"})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestHandshake_ReturnResp(t *testing.T) {
	const msg = "fake message"
	expected := &core.EncryptedMessage{
		AttemptId: "id",
		Message:   []byte("encrypted message"),
	}

	pk, _ := virgil.Crypto().ImportPublicKey([]byte(`MCowBQYDK2VwAyEA9C2xSdT5c+0Y1K87vH0c17gOrAZhXNGxW6sgjotoDOs=`))
	card := &virgil.Card{
		Scope:     virgil.CardScope.Global,
		PublicKey: pk,
	}

	resp := new(FakeResponse)
	resp.On("Success", expected).Once()

	c := new(FakeCardClient)
	c.On("GetCard", "id").Return(card, nil)

	a := new(FakeAttemptRepo)
	a.On("Make", "id", "test_scope").Return(&db.Attempt{ID: expected.AttemptId, Message: msg}, nil)

	ch := new(FakeCipher)
	ch.On("Encrypt", []byte(msg), pk).Return(expected.Message, nil)

	s := Grant{Client: c, AttemptRepo: a, Cipher: ch}
	s.Handshake(resp, core.OwnerCard{ID: "id", Scope: "test_scope"})

	resp.AssertExpectations(t)
}

func TestAcknowledge_AttempRepoReturnErr_LogAndReturnInternalError(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", mock.Anything).Return(nil, fmt.Errorf("format"))

	l := new(FakeLogger)
	l.On("Printf").Once()

	s := Grant{AttemptRepo: a, Logger: l}
	s.Acknowledge(resp, core.EncryptedMessage{})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestAcknowledge_AttempRepoReturnNil_ReturnAttemptNotFound(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorAttemptNotFound).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", mock.Anything).Return(nil, nil)

	s := Grant{AttemptRepo: a}
	s.Acknowledge(resp, core.EncryptedMessage{})

	resp.AssertExpectations(t)
}

func TestAcknowledge_AttempExpire_ReturnAttemptNotFound(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorAttemptNotFound).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", mock.Anything).Return(&db.Attempt{Expired: time.Unix(0, 0)}, nil)

	s := Grant{AttemptRepo: a}
	s.Acknowledge(resp, core.EncryptedMessage{})

	resp.AssertExpectations(t)
}

func TestAcknowledge_CipherReturnFalse_ReturnEncryptedMessageValidationFaild(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorEncryptedMessageValidationFailed).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", mock.Anything).Return(&db.Attempt{Expired: time.Now().Add(10 * time.Minute)}, nil)
	ch := new(FakeCipher)
	ch.On("Validate", mock.Anything, mock.Anything).Return(false)

	s := Grant{AttemptRepo: a, Cipher: ch}
	s.Acknowledge(resp, core.EncryptedMessage{})

	resp.AssertExpectations(t)
}

func TestAcknowledge_CodeRepoReturnErr_LogAndReturnInternalErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", mock.Anything).Return(&db.Attempt{Expired: time.Now().Add(10 * time.Minute)}, nil)

	c := new(FakeMakeCode)
	c.On("Make", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	ch := new(FakeCipher)
	ch.On("Validate", mock.Anything, mock.Anything).Return(true)

	l := new(FakeLogger)
	l.On("Printf").Once()

	s := Grant{AttemptRepo: a, Logger: l, MakeCode: c, Cipher: ch}
	s.Acknowledge(resp, core.EncryptedMessage{})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}
func TestAcknowledge_RemoveAttemptReturnErr_ReturnErr(t *testing.T) {
	const (
		attemtID  = "attempt id"
		ownerID   = "owner id"
		code      = "code"
		CipherMsg = "Cipher message"
		plainMsg  = "plain msg"
		scope     = "test_scope"
	)

	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", attemtID).Return(&db.Attempt{Expired: time.Now().Add(10 * time.Minute), OwnerID: ownerID, Message: plainMsg, Scope: scope}, nil)
	a.On("Remove", attemtID).Return(fmt.Errorf("Error"))

	l := new(FakeLogger)
	l.On("Printf").Once()

	c := new(FakeMakeCode)
	c.On("Make", ownerID, scope).Return(&db.Code{Code: code}, nil)

	ch := new(FakeCipher)
	ch.On("Validate", []byte(CipherMsg), []byte(plainMsg)).Return(true)

	s := Grant{AttemptRepo: a, MakeCode: c, Logger: l, Cipher: ch}
	s.Acknowledge(resp, core.EncryptedMessage{AttemptId: attemtID, Message: []byte(CipherMsg)})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestAcknowledge_ReturnVal(t *testing.T) {
	const (
		attemtID  = "attempt id"
		ownerID   = "owner id"
		code      = "code"
		CipherMsg = "Cipher message"
		plainMsg  = "plain msg"
		scope     = "test_scope"
	)

	resp := new(FakeResponse)
	resp.On("Success", &core.AccessCode{Code: code}).Once()

	a := new(FakeAttemptRepo)
	a.On("Get", attemtID).Return(&db.Attempt{Expired: time.Now().Add(10 * time.Minute), OwnerID: ownerID, Message: plainMsg, Scope: scope}, nil)
	a.On("Remove", attemtID).Return(nil)

	c := new(FakeMakeCode)
	c.On("Make", ownerID, scope).Return(&db.Code{Code: code}, nil)

	ch := new(FakeCipher)
	ch.On("Validate", []byte(CipherMsg), []byte(plainMsg)).Return(true)

	s := Grant{AttemptRepo: a, MakeCode: c, Cipher: ch}
	s.Acknowledge(resp, core.EncryptedMessage{AttemptId: attemtID, Message: []byte(CipherMsg)})

	resp.AssertExpectations(t)
}
