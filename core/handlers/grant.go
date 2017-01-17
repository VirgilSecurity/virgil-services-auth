package handlers

import (
	"strings"
	"time"

	"github.com/VirgilSecurity/virgil-services-auth/core"
	"github.com/VirgilSecurity/virgil-services-auth/db"
	"github.com/pkg/errors"
	virgil "gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type CardClient interface {
	GetCard(id string) (card *virgil.Card, err error)
}

type Logger interface {
	Printf(format string, args ...interface{})
}

type Cipher interface {
	Encrypt(data []byte, recipient virgilcrypto.PublicKey) ([]byte, error)
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
		verr := errors.Cause(err)
		if verr == virgil.ErrNotFound {
			resp.Error(core.StatusErrorCardNotFound)
			return
		}
		if strings.Contains(err.Error(), "does not have signature for verifier ID") || strings.Contains(err.Error(), "signature validation failed") {
			resp.Error(core.StatusErrorCardNotValided)
			return
		}
		s.Logger.Printf("Handshake[GetCard]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	a, err := s.AttemptRepo.Make(ownerCard.ID, ownerCard.Scope)
	if err != nil {
		s.Logger.Printf("Handshake[make attempt]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	m, err := s.Cipher.Encrypt([]byte(a.Message), card.PublicKey)
	if err != nil {
		s.Logger.Printf("Handshake[encrypt msg]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
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
		resp.Error(core.StatusErrorInernalApplicationError)
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
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	err = s.AttemptRepo.Remove(msg.AttemptId)
	if err != nil {
		s.Logger.Printf("Acknowledge[Remove attempt]: %v", err)
		resp.Error(core.StatusErrorInernalApplicationError)
		return
	}
	resp.Success(&core.AccessCode{Code: code.Code})
}
