package device

import (
	"errors"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func (kci *KeychainItem) boltKey() string {
	return strings.Join([]string{kci.Keychain.ID, kci.Keychain.Type, kci.UUID}, "_")
}

// Save writes a keychain item to a keychain's BoltDB.
func (kci *KeychainItem) Save() error {
	err := kci.encode()
	if err != nil {
		return err
	}
	return kci.Keychain.DB.Update(func(tx *bolt.Tx) error {
		err := BucketPutOrDelete(tx, "keychain_items_item", kci.boltKey(), kci.Item)
		if err != nil {
			return err
		}
		return BucketPutOrDeleteInt(tx, "keychain_item_class", kci.boltKey(), kci.Class)
	})
}

func (kci *KeychainItem) Delete() error {
	return kci.Keychain.DB.Update(func(tx *bolt.Tx) error {
		err := BucketPutOrDelete(tx, "keychain_items_item", kci.boltKey(), nil)
		if err != nil {
			return err
		}
		return BucketPutOrDeleteInt(tx, "keychain_item_class", kci.boltKey(), 0)
	})
}

// LoadKeychainItem loads a *KeychainItem from a keychain's BoltDB.
func LoadKeychainItem(kc *Keychain, uuid string) (kci *KeychainItem, err error) {
	kci = &KeychainItem{
		Keychain: kc,
		UUID:     uuid,
	}
	err = kc.DB.View(func(tx *bolt.Tx) error {
		kci.Item = BucketGet(tx, "keychain_items_item", kci.boltKey())
		if len(kci.Item) == 0 {
			return errors.New("empty keychain item")
		}
		kci.Class = BucketGetInt(tx, "keychain_item_class", kci.boltKey())
		if kci.Class == 0 {
			return errors.New("invalid keychain item class 0")
		}
		return nil
	})
	if err != nil {
		return
	}
	err = kci.decode()
	return
}
