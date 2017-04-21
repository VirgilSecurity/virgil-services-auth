package http

import (
	"testing"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/stretchr/testify/mock"
)

type FakeAuthService struct {
	mock.Mock
}

func (s *FakeAuthService) AccessToken(resp core.Response, m core.AccessCode) {
	s.Called(resp, m)
}

func (s *FakeAuthService) Refresh(resp core.Response, grantType string, token string) {
	s.Called(resp, grantType, token)
}

func (s *FakeAuthService) Verify(resp core.Response, token string) {
	s.Called(resp, token)
}

func TestAccessToken_BodyIncorrect_ReturnErr(t *testing.T) {
	r := makeRequestCtx("asdf,sa")
	c := &Auth{}
	c.AccessToken(r)

	assertResponse(t, core.StatusErrorCodeNotFound, r)
}

func TestAccessToken_MethodInvoked(t *testing.T) {
	at := core.AccessCode{
		GrantType: "type",
		Code:      "code",
	}
	r := makeRequestCtx(at)

	s := new(FakeAuthService)
	s.On("AccessToken", mock.Anything, at).Once()

	g := Auth{Handler: s}
	g.AccessToken(r)

	s.AssertExpectations(t)
}

func TestRefresh_BodyIncorrect_ReturnErr(t *testing.T) {
	r := makeRequestCtx("asdf,sa")
	c := new(Auth)
	c.Refresh(r)

	assertResponse(t, core.StatusErrorRefreshTokenNotFound, r)
}

func TestRefresh_MethodInvoked(t *testing.T) {
	tk := map[string]string{
		"grant_type":    "type",
		"refresh_token": "refresh",
	}
	r := makeRequestCtx(tk)
	s := new(FakeAuthService)
	s.On("Refresh", mock.Anything, "type", "refresh").Once()

	g := Auth{Handler: s}
	g.Refresh(r)

	s.AssertExpectations(t)
}

func TestVerify_BodyIncorrect_ReturnErr(t *testing.T) {
	r := makeRequestCtx("asdf,sa")
	c := &Auth{}
	c.Verify(r)

	assertResponse(t, core.StatusErrorAttemptNotFound, r)
}

func TestVerify_MethodInvoked(t *testing.T) {
	r := makeRequestCtx(&core.Token{
		Token: "token",
	})
	s := new(FakeAuthService)
	s.On("Verify", mock.Anything, "token").Once()

	g := Auth{Handler: s}
	g.Verify(r)

	s.AssertExpectations(t)
}
