package keychain

import (
	"strings"

	"github.com/google/uuid"
)

const (
	_ = iota
	ClassCertificate
	ClassKey
	ClassIdentity
)

type KeychainItem struct {
	Keychain *Keychain

	UUID  string
	Class int
	Item  []byte
}

func NewKeychainItem(kc *Keychain, class int) *KeychainItem {
	return &KeychainItem{
		Keychain: kc,
		UUID:     strings.ToUpper(uuid.NewString()),
		Class:    class,
	}
}
