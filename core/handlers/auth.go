package handlers

import (
	"time"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
)

const (
	grantTypeAccessCode   = "access_code"
	grantTypeRefreshToken = "refresh_token"
)

type Auth struct {
	Logger      Logger
	CodeRepo    db.CodeRepo
	TokenRepo   db.TokenRepo
	RefreshRepo db.RefreshRepo
}

func (s *Auth) AccessToken(resp core.Response, code core.AccessCode) {
	if code.GrantType != grantTypeAccessCode {
		resp.Error(core.StatusErrorUnsupportedGrantType)
		return
	}
	m, err := s.CodeRepo.GetCode(code.Code)
	if err != nil {
		s.Logger.Printf("AccessToken[GetCode]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	if m == nil {
		resp.Error(core.StatusErrorCodeNotFound)
		return
	}
	if m.Used {
		resp.Error(core.StatusErrorCodeWasUsed)
		return
	}
	if time.Now().UTC().After(m.Expired) {
		resp.Error(core.StatusErrorCodeExpired)
		return
	}
	token, err := s.TokenRepo.Make(m.OwnerID, m.Scope)
	if err != nil {
		s.Logger.Printf("AccessToken[Make token]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	refresh, err := s.RefreshRepo.Make(m.OwnerID, m.Scope)
	if err != nil {
		s.Logger.Printf("AccessToken[Make refresh token]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	resp.Success(&core.Token{
		Token:     token.Token,
		Refresh:   refresh.Token,
		ExpiresIn: token.ExpiresIn,
		Type:      "bearer",
	})
}
func (s *Auth) Refresh(resp core.Response, grantType string, token string) {
	if grantType != grantTypeRefreshToken {
		resp.Error(core.StatusErrorUnsupportedGrantType)
		return
	}
	refreshToken, err := s.RefreshRepo.Get(token)
	if err != nil {
		s.Logger.Printf("Refresh[Get refresh token]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	if refreshToken == nil {
		resp.Error(core.StatusErrorRefreshTokenNotFound)
		return
	}
	accessToken, err := s.TokenRepo.Make(refreshToken.OwnerID, refreshToken.Scope)
	if err != nil {
		s.Logger.Printf("Refresh[Get access token]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	resp.Success(&core.Token{
		Token:     accessToken.Token,
		ExpiresIn: accessToken.ExpiresIn,
	})
}
func (s *Auth) Verify(resp core.Response, token string) {
	accessToken, err := s.TokenRepo.Get(token)
	if err != nil {
		// HACK: We don't log this err because it contains many correct errors (token="", sign fraud and etc)
		//s.Logger.Printf("Verify[get token]: %v", err)
		resp.Error(core.StatusErrorAccessTokenBroken)
		return
	}

	if time.Now().After(accessToken.Expired) {
		resp.Error(core.StatusErrorAccessTokenExpired)
		return
	}
	resp.Success(&core.OwnerCard{ID: accessToken.OwnerID, Scope: accessToken.Scope})
}
