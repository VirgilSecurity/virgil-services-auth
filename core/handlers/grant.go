package handlers

import (
	"net/http"
	"strings"
	"time"

	"gopkg.in/virgil.v5/cryptoapi"
	verrors "gopkg.in/virgil.v5/errors"
	virgil "gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
)

type CardClient interface {
	GetCard(id string) (card *virgil.Card, err error)
}

type Logger interface {
	Printf(format string, args ...interface{})
}

type Cipher interface {
	Encrypt(data []byte, recipient cryptoapi.PublicKey) ([]byte, error)
	Validate(CipherData, plainData []byte) bool
}

type Grant struct {
	Client      CardClient
	Logger      Logger
	AttemptRepo db.AttemptRepo
	MakeCode    db.CodeMaker
	Cipher      Cipher
}

func (s *Grant) Handshake(resp core.Response, ownerCard core.OwnerCard) {
	card, err := s.Client.GetCard(ownerCard.ID)
	if err != nil {
		if verr, ok := verrors.ToSdkError(err); ok && verr.IsHTTPError() {
			if verr.IsHTTPError() {
				// Card not found
				if verr.HTTPErrorCode() == http.StatusNotFound {
					resp.Error(core.StatusErrorCardNotFound)
					return
				}
				// Card found but permission denied
				if verr.HTTPErrorCode() == http.StatusUnauthorized || verr.HTTPErrorCode() == http.StatusForbidden {
					resp.Error(core.StatusErrorCardProtected)
					return
				}
			}
			// if verr.Message == virgil.CardValidationExpectedSignerWasNotFoundErr
		}
		if strings.Contains(err.Error(), "invalid card id") {
			resp.Error(core.StatusErrorCardInvalid)
			return
		}
		if strings.Contains(err.Error(), "does not have signature for verifier ID") || strings.Contains(err.Error(), "signature validation failed") {
			resp.Error(core.StatusErrorCardInvalid)
			return
		}
		s.Logger.Printf("Handshake[GetCard]: %+v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	a, err := s.AttemptRepo.Make(ownerCard.ID, ownerCard.Scope)
	if err != nil {
		s.Logger.Printf("Handshake[make attempt]: %+v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	m, err := s.Cipher.Encrypt([]byte(a.Message), card.PublicKey)
	if err != nil {
		s.Logger.Printf("Handshake[encrypt msg]: %+v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	resp.Success(&core.EncryptedMessage{
		AttemptId: a.ID,
		Message:   m,
	})
}

func (s *Grant) Acknowledge(resp core.Response, msg core.EncryptedMessage) {
	a, err := s.AttemptRepo.Get(msg.AttemptId)
	if err != nil {
		s.Logger.Printf("Acknowledge[Get attempt]: %v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	if a == nil {
		resp.Error(core.StatusErrorAttemptNotFound)
		return
	}
	if time.Now().After(a.Expired) {
		resp.Error(core.StatusErrorAttemptNotFound)
		return
	}
	ok := s.Cipher.Validate([]byte(msg.Message), []byte(a.Message))
	if !ok {
		resp.Error(core.StatusErrorEncryptedMessageValidationFailed)
		return
	}
	code, err := s.MakeCode.Make(a.OwnerID, a.Scope)
	if err != nil {
		s.Logger.Printf("Acknowledge[Make code]: %v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	err = s.AttemptRepo.Remove(msg.AttemptId)
	if err != nil {
		s.Logger.Printf("Acknowledge[Remove attempt]: %v", err)
		resp.Error(core.StatusErrorInternalApplicationError)
		return
	}
	resp.Success(map[string]string{"code": code.Code})
}
