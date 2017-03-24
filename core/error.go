package core

type ResponseStatus int

const (
	StatusErrorAttemptNotFound ResponseStatus = 404 // special case for 404 response

	StatusErrorUUIDValidFailed                  ResponseStatus = 53000
	StatusErrorCardNotFound                     ResponseStatus = 53010
	StatusErrorCardProtected                    ResponseStatus = 53011
	StatusErrorEncryptedMessageValidationFailed ResponseStatus = 53020
	StatusErrorAccessTokenExpired               ResponseStatus = 53030
	StatusErrorUnsupportedGrantType             ResponseStatus = 53040
	StatusErrorCodeNotFound                     ResponseStatus = 53050
	StatusErrorCodeExpired                      ResponseStatus = 53060
	StatusErrorCodeWasUsed                      ResponseStatus = 53070
	StatusErrorAccessTokenBroken                ResponseStatus = 53080
	StatusErrorRefreshTokenNotFound             ResponseStatus = 53090
	StatusErrorCardInvalid                      ResponseStatus = 53100

	StatusErrorInernalApplicationError ResponseStatus = 10000
)
