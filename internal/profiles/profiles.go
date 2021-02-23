package profiles

import (
	"errors"
	"fmt"

	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/boltprim"
	bolt "go.etcd.io/bbolt"
)

type ProfileStore struct {
	ID string

	DB *bolt.DB
}

func New(id string, db *bolt.DB) *ProfileStore {
	return &ProfileStore{ID: id, DB: db}
}

func (ps *ProfileStore) Install(pb []byte) error {
	if len(pb) == 0 {
		return errors.New("empty profile")
	}
	p := &cfgprofiles.Profile{}
	err := plist.Unmarshal(pb, p)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s_%s", ps.ID, p.PayloadIdentifier)
	return ps.DB.Update(func(tx *bolt.Tx) error {
		return boltprim.BucketPutOrDelete(tx, "profiles", key, pb)
	})
}

func (ps *ProfileStore) Load(id string) (p *cfgprofiles.Profile, err error) {
	pb := []byte{}
	key := fmt.Sprintf("%s_%s", ps.ID, id)
	err = ps.DB.View(func(tx *bolt.Tx) error {
		pb = boltprim.BucketGet(tx, "profiles", key)
		return nil
	})
	if err != nil {
		return
	}
	p = &cfgprofiles.Profile{}
	err = plist.Unmarshal(pb, p)
	return
}
