package repo

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/VirgilSecurity/virgil-services-auth/db"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const AttemptExpiresIn time.Duration = 2 * time.Minute
const codeLength = 38

type Attempt struct {
	C *mgo.Collection
}

func (r *Attempt) Make(ownerID string, scope string) (*db.Attempt, error) {
	b := make([]byte, 32)
	rand.Read(b)

	a := &db.Attempt{
		OwnerID: ownerID,
		Scope:   scope,
		Expired: time.Now().Add(AttemptExpiresIn),
		Message: base64.RawURLEncoding.EncodeToString(b),
		ID:      bson.NewObjectId().Hex(),
	}
	err := r.C.Insert(a)
	if err != nil {
		return nil, err
	}
	return a, nil
}
func (r *Attempt) Get(id string) (*db.Attempt, error) {
	a := new(db.Attempt)
	err := r.C.Find(bson.M{"_id": id}).One(a)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *Attempt) Remove(id string) error {
	return r.C.RemoveId(id)
}
