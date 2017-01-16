package repo

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/virgilsecurity/virgil-services-auth/db"
	mgo "gopkg.in/mgo.v2"
)

type Refresh struct {
	C *mgo.Collection
}

func (r *Refresh) Make(ownerId string, scope string) (*db.RefreshToken, error) {
	b := make([]byte, 32)
	rand.Read(b)

	t := &db.RefreshToken{
		OwnerID: ownerId,
		Scope:   scope,
		Expired: time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
		Token:   base64.RawURLEncoding.EncodeToString(b),
	}
	err := r.C.Insert(t)
	if err != nil {
		return nil, err
	}
	return t, nil
}
func (r *Refresh) Get(token string) (*db.RefreshToken, error) {
	t := new(db.RefreshToken)
	err := r.C.FindId(token).One(t)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}
