package keychain

import (
	bolt "go.etcd.io/bbolt"
)

const (
	KeychainSystem = "System"
)

type Keychain struct {
	ID   string
	Type string

	DB *bolt.DB
}

func New(id, kcType string, db *bolt.DB) *Keychain {
	return &Keychain{
		ID:   id,
		Type: kcType,
		DB:   db,
	}
}
