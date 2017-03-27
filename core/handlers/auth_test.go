package handlers

import (
	"fmt"
	"testing"
	"time"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
	"github.com/stretchr/testify/mock"
)

type FakeResponse struct {
	mock.Mock
	Model interface{}
}

func (r *FakeResponse) Error(code core.ResponseStatus) {
	r.Called(code)
}

func (r *FakeResponse) Success(model interface{}) {
	r.Called(model)
}

type FakeCodeRepo struct {
	mock.Mock
}

func (r *FakeCodeRepo) GetCode(code string) (dCode *db.Code, err error) {
	args := r.Called(code)
	dCode, _ = args.Get(0).(*db.Code)
	err = args.Error(1)
	return
}

type FakeTokenRepo struct {
	mock.Mock
}

func (s *FakeTokenRepo) Make(ownerId string, scope string) (t *db.AccessToken, err error) {
	args := s.Called(ownerId)
	t, _ = args.Get(0).(*db.AccessToken)
	err = args.Error(1)
	return
}

func (s *FakeTokenRepo) Get(token string) (t *db.AccessToken, err error) {
	args := s.Called(token)
	t, _ = args.Get(0).(*db.AccessToken)
	err = args.Error(1)
	return
}

type FakeRefreshRepo struct {
	mock.Mock
}

func (r *FakeRefreshRepo) Make(ownerId string, scope string) (t *db.RefreshToken, err error) {
	args := r.Called(ownerId)
	t, _ = args.Get(0).(*db.RefreshToken)
	err = args.Error(1)
	return
}
func (r *FakeRefreshRepo) Get(token string) (t *db.RefreshToken, err error) {
	args := r.Called(token)
	t, _ = args.Get(0).(*db.RefreshToken)
	err = args.Error(1)
	return
}

func TestAccessToken_UnsupportedGrantType_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorUnsupportedGrantType).Once()

	a := Auth{}
	a.AccessToken(resp, core.AccessCode{GrantType: "unsupported"})

	resp.AssertExpectations(t)
}

func TestAccessToken_CodeRepoReturnErr_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	l := new(FakeLogger)
	l.On("Printf").Once()

	a := Auth{CodeRepo: r, Logger: l}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestAccessToken_CodeRepoReturnNil_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCodeNotFound).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(nil, nil)

	a := Auth{CodeRepo: r}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

	resp.AssertExpectations(t)
}

func TestAccessToken_CodeRepoCodeUsed_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCodeWasUsed).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(&db.Code{Used: true}, nil)

	a := Auth{CodeRepo: r}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

}

func TestAccessToken_CodeRepoCodeExpired_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorCodeExpired).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(&db.Code{Used: false, Expired: time.Now().Add(-10 * time.Hour).UTC()}, nil)

	a := Auth{CodeRepo: r}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

	resp.AssertExpectations(t)
}

func TestAccessToken_TokenRepoReturnErr_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(&db.Code{Used: false, Expired: time.Now().Add(10 * time.Hour).UTC()}, nil)

	l := new(FakeLogger)
	l.On("Printf").Once()

	tr := new(FakeTokenRepo)
	tr.On("Make", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	a := Auth{CodeRepo: r, Logger: l, TokenRepo: tr}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestAccessToken_RefreshRepoReturnErr_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", mock.Anything).Return(&db.Code{Used: false, Expired: time.Now().Add(10 * time.Hour).UTC()}, nil)

	l := new(FakeLogger)
	l.On("Printf").Once()

	tr := new(FakeTokenRepo)
	tr.On("Make", mock.Anything, mock.Anything).Return(&db.AccessToken{}, nil)

	rr := new(FakeRefreshRepo)
	rr.On("Make", mock.Anything).Return("", fmt.Errorf("ERROR"))

	a := Auth{CodeRepo: r, Logger: l, TokenRepo: tr, RefreshRepo: rr}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode})

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestAccessToken_ReturnResult(t *testing.T) {
	expected := &core.Token{
		Token:     "token",
		Refresh:   "refresh",
		ExpiresIn: 600,
		Type:      "bearer",
	}

	var (
		code    = "code"
		ownerId = "ownerID"
	)

	resp := new(FakeResponse)
	resp.On("Success", expected).Once()

	r := new(FakeCodeRepo)
	r.On("GetCode", code).Return(&db.Code{Used: false, OwnerID: ownerId, Expired: time.Now().Add(10 * time.Hour).UTC()}, nil)

	tr := new(FakeTokenRepo)
	tr.On("Make", ownerId).Return(&db.AccessToken{Token: expected.Token, ExpiresIn: expected.ExpiresIn}, nil)

	rr := new(FakeRefreshRepo)
	rr.On("Make", ownerId).Return(&db.RefreshToken{Token: expected.Refresh}, nil)

	a := Auth{CodeRepo: r, TokenRepo: tr, RefreshRepo: rr}
	a.AccessToken(resp, core.AccessCode{GrantType: grantTypeAccessCode, Code: code})

	resp.AssertExpectations(t)
}

func TestRefresh_UnsupportedGrantType_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorUnsupportedGrantType).Once()

	a := Auth{}
	a.Refresh(resp, "unsupported", "")

	resp.AssertExpectations(t)
}

func TestRefresh_RefreshRepoReturnErr_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	l := new(FakeLogger)
	l.On("Printf").Once()

	rr := new(FakeRefreshRepo)
	rr.On("Get", mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	a := Auth{RefreshRepo: rr, Logger: l}
	a.Refresh(resp, grantTypeRefreshToken, "")

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestRefresh_RefreshRepoReturnResultNil_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorRefreshTokenNotFound).Once()

	rr := new(FakeRefreshRepo)
	rr.On("Get", mock.Anything).Return(nil, nil)

	a := Auth{RefreshRepo: rr}
	a.Refresh(resp, grantTypeRefreshToken, "")

	resp.AssertExpectations(t)
}

func TestRefresh_TokenRepoReturnErr_ReturnErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorInernalApplicationError).Once()

	l := new(FakeLogger)
	l.On("Printf").Once()

	rr := new(FakeRefreshRepo)
	rr.On("Get", mock.Anything).Return(&db.RefreshToken{OwnerID: "ownerId"}, nil)

	tr := new(FakeTokenRepo)
	tr.On("Make", mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	a := Auth{RefreshRepo: rr, Logger: l, TokenRepo: tr}
	a.Refresh(resp, grantTypeRefreshToken, "")

	resp.AssertExpectations(t)
	l.AssertExpectations(t)
}

func TestRefresh_ReturnVal(t *testing.T) {
	var (
		refreshToken = "referesh token"
		ownerID      = "owner id"
	)
	expected := &core.RefreshAccessToken{
		Token:     "token",
		ExpiresIn: 600,
	}

	resp := new(FakeResponse)
	resp.On("Success", expected).Once()

	l := new(FakeLogger)
	l.On("Printf").Once()

	rr := new(FakeRefreshRepo)
	rr.On("Get", refreshToken).Return(&db.RefreshToken{OwnerID: ownerID}, nil)

	tr := new(FakeTokenRepo)
	tr.On("Make", ownerID).Return(&db.AccessToken{Token: expected.Token, ExpiresIn: expected.ExpiresIn}, nil)

	a := Auth{RefreshRepo: rr, Logger: l, TokenRepo: tr}
	a.Refresh(resp, grantTypeRefreshToken, refreshToken)

	resp.AssertExpectations(t)
}

func TestVerify_TokenRepoRerturnErr_ReturnInternalErr(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorAccessTokenBroken).Once()

	l := new(FakeLogger)
	l.On("Printf")

	tr := new(FakeTokenRepo)
	tr.On("Get", mock.Anything).Return(nil, fmt.Errorf("ERROR"))

	a := Auth{Logger: l, TokenRepo: tr}
	a.Verify(resp, "token")

	resp.AssertExpectations(t)
}

// func TestVerify_TokenNotFound_ReturnTokenExpired(t *testing.T) {
// 	l := &FakeLogger{}
// 	tr := &FakeTokenRepo{}
// 	tr.On("Get", mock.Anything).Return(nil, nil)
// 	a := Auth{Logger: l, TokenRepo: tr}
// 	_, s := a.Verify("token")
//
// 	assert.Equal(t, core.StatusErrorAccessTokenBroken, s)
// }

func TestVerify_TokenExpired_ReturnTokenExpired(t *testing.T) {
	resp := new(FakeResponse)
	resp.On("Error", core.StatusErrorAccessTokenExpired).Once()

	tr := new(FakeTokenRepo)
	tr.On("Get", mock.Anything).Return(&db.AccessToken{Expired: time.Unix(0, 0)}, nil)

	a := Auth{TokenRepo: tr}
	a.Verify(resp, "token")

	resp.AssertExpectations(t)
}

func TestVerify_ReturnVal(t *testing.T) {
	expected := &core.OwnerCard{
		ID: "owner id",
	}
	resp := new(FakeResponse)
	resp.On("Success", expected).Once()

	tr := new(FakeTokenRepo)
	tr.On("Get", mock.Anything).Return(&db.AccessToken{Expired: time.Now().Add(100 * time.Minute), OwnerID: expected.ID}, nil)

	a := Auth{TokenRepo: tr}
	a.Verify(resp, "token")

	resp.AssertExpectations(t)
}
