package device

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

func NewKeychain(id, kcType string, db *bolt.DB) *Keychain {
	return &Keychain{
		ID:   id,
		Type: kcType,
		DB:   db,
	}
}

func (device *Device) SystemKeychain() *Keychain {
	if device.sysKeychain == nil {
		device.sysKeychain = NewKeychain(device.UDID, KeychainSystem, device.boltDB)
	}
	return device.sysKeychain
}
