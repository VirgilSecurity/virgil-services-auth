package db

import "time"

type Code struct {
	Code    string    `bson:"_id"`
	OwnerID string    `bson:"owner_id"`
	Scope   string    `bson:"scope"`
	Used    bool      `bson:"used"`
	Expired time.Time `bson:"expired"`
}

type AccessToken struct {
	Token     string
	OwnerID   string
	Scope     string `bson:"scope"`
	ExpiresIn int
	Expired   time.Time
}

type RefreshToken struct {
	Token   string    `bson:"_id"`
	Expired time.Time `bson:"expired"`
	OwnerID string    `bson:"owner_id"`
	Scope   string    `bson:"scope"`
}

type Attempt struct {
	ID      string    `bson:"_id"`
	OwnerID string    `bson:"owner_id"`
	Scope   string    `bson:"scope"`
	Message string    `bson:"msg"`
	Expired time.Time `bson:"expired"`
}
