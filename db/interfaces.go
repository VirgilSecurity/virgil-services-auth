package db

type CodeRepo interface {
	GetCode(string) (*Code, error)
}

type CodeMaker interface {
	Make(ownerID string, scope string) (*Code, error)
}

type TokenRepo interface {
	Make(ownerId string, scope string) (*AccessToken, error)
	Get(string) (*AccessToken, error)
}
type RefreshRepo interface {
	Make(ownerId string, scope string) (*RefreshToken, error)
	Get(token string) (*RefreshToken, error)
}

type AttemptRepo interface {
	Make(ownerID string, scope string) (*Attempt, error)
	Get(id string) (*Attempt, error)
	Remove(id string) error
}
