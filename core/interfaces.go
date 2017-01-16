package core

type Response interface {
	Error(code ResponseStatus)
	Success(model interface{})
}

type AuthHandler interface {
	AccessToken(resp Response, code AccessCode)
	Refresh(resp Response, grantType string, token string)
	Verify(resp Response, token string)
}

type GrantHandler interface {
	Handshake(resp Response, card OwnerCard)
	Acknowledge(resp Response, msg EncryptedMessage)
}
