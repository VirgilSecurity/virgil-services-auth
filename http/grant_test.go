package http

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/VirgilSecurity/virgil-services-auth/core"
)

type FakeGrantService struct {
	mock.Mock
}

func (s *FakeGrantService) Handshake(resp core.Response, card core.OwnerCard) {
	s.Called(resp, card)
}

func (s *FakeGrantService) Acknowledge(resp core.Response, m core.EncryptedMessage) {
	s.Called(resp, m)
}

func TestHandshake_BodyIncorrect_ReturnErr(t *testing.T) {
	r := makeRequestCtx("asd,fd")
	g := Grant{}
	g.Handshake(r)

	assertResponse(t, core.StatusErrorUUIDValidFailed, r)
}

func TestHandshake_BodyIncorrectStruc_ReturnErr(t *testing.T) {
	r := makeRequestCtx("{}")
	g := Grant{}
	g.Handshake(r)

	assertResponse(t, core.StatusErrorUUIDValidFailed, r)
}

func TestHandshake_ScopeMiss_SetWildcardScope(t *testing.T) {
	r := makeRequestCtx(core.OwnerCard{ID: "id"})
	s := new(FakeGrantService)
	s.On("Handshake", mock.Anything, core.OwnerCard{ID: "id", Scope: "*"}).Once()
	g := Grant{Handler: s}
	g.Handshake(r)

	s.AssertExpectations(t)
}

func TestHandshake_MethodInvoked(t *testing.T) {
	ownCard := core.OwnerCard{
		ID:    "id",
		Scope: "test1 test2",
	}
	r := makeRequestCtx(ownCard)
	s := new(FakeGrantService)
	s.On("Handshake", mock.Anything, ownCard).Once()
	g := Grant{Handler: s}
	g.Handshake(r)

	s.AssertExpectations(t)
}

func TestAcknowledge_BodyIncorrect_ReturnErr(t *testing.T) {
	r := makeRequestCtx("asd,fd")
	g := Grant{}
	g.Acknowledge("12", r)

	assertResponse(t, core.StatusErrorEncryptedMessageValidationFailed, r)
}

func TestAcknowledge_StatusOk_ReturnResp(t *testing.T) {
	r := makeRequestCtx(core.EncryptedMessage{
		Message: []byte("message"),
	})
	s := new(FakeGrantService)
	s.On("Acknowledge", mock.Anything, core.EncryptedMessage{AttemptId: "id", Message: []byte("message")}).Once()

	g := Grant{Handler: s}
	g.Acknowledge("id", r)

	s.AssertExpectations(t)
}
