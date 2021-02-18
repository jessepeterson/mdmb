package keychain

import (
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func (kci *KeychainItem) boltKey(keytype string) []byte {
	return []byte(strings.Join([]string{kci.Keychain.ID, kci.Keychain.Type, kci.UUID, keytype}, "_"))
}

func (kci *KeychainItem) Save() error {
	return kci.Keychain.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("keychain_items"))
		if err != nil {
			return err
		}
		keyBytes := kci.boltKey("item")
		// if len(kci.Item) == 0 {
		// 	return kci.Delete()
		// }
		err = b.Put(keyBytes, kci.Item)
		if err != nil {
			return err
		}
		keyBytes = kci.boltKey("class")
		return b.Put(keyBytes, []byte(strconv.Itoa(kci.Class)))
	})
}

// func LoadKeychainItem(kc *Keychain, uuid string) (*KeychainItem, error) {
// 	return nil, nil
// }

// func (kci *KeychainItem) Delete() error {
// 	return nil
// }
