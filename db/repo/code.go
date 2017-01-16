package repo

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/virgilsecurity/virgil-services-auth/db"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const CodeExpiresIn time.Duration = 2 * time.Minute

type Code struct {
	C *mgo.Collection
}

func (r *Code) GetCode(code string) (*db.Code, error) {
	c := new(db.Code)
	err := r.C.FindId(code).One(c)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.C.UpdateId(code, bson.M{"used": true})

	return c, nil
}
func (r *Code) Make(ownerID string, scope string) (*db.Code, error) {
	b := make([]byte, 32)
	rand.Read(b)
	c := &db.Code{
		OwnerID: ownerID,
		Scope:   scope,
		Expired: time.Now().Add(CodeExpiresIn),
		Code:    base64.RawURLEncoding.EncodeToString(b),
	}
	err := r.C.Insert(c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
