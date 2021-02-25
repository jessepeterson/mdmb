package device

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
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

	// ClassIdentity
	IdentityCertificateUUID string
	IdentityKeyUUID         string

	// ClassKey
	Key *rsa.PrivateKey

	// ClassCertificate
	Certificate *x509.Certificate
}

func NewKeychainItem(kc *Keychain, class int) *KeychainItem {
	return &KeychainItem{
		Keychain: kc,
		UUID:     strings.ToUpper(uuid.NewString()),
		Class:    class,
	}
}

// encodes the keychain item into the raw Item member
func (kci *KeychainItem) encode() error {
	switch kci.Class {
	case ClassCertificate:
		kci.Item = kci.Certificate.Raw
	case ClassKey:
		kci.Item = x509.MarshalPKCS1PrivateKey(kci.Key)
	case ClassIdentity:
		if kci.IdentityCertificateUUID == "" || kci.IdentityKeyUUID == "" {
			return errors.New("must provide UUIDs for key and cert for identity keychain item")
		}
		kci.Item = []byte(strings.Join([]string{kci.IdentityKeyUUID, kci.IdentityCertificateUUID}, ","))
	default:
		return errors.New("invalid keychain item class")
	}
	return nil
}

// decodes the raw keychain item into item members
func (kci *KeychainItem) decode() error {
	var err error
	switch kci.Class {
	case ClassCertificate:
		kci.Certificate, err = x509.ParseCertificate(kci.Item)
		if err != nil {
			return err
		}
	case ClassKey:
		kci.Key, err = x509.ParsePKCS1PrivateKey(kci.Item)
		if err != nil {
			return err
		}
	case ClassIdentity:
		split := strings.Split(string(kci.Item), ",")
		if len(split) != 2 {
			return errors.New("invalid identity keychain item")
		}
		kci.IdentityKeyUUID = split[0]
		kci.IdentityCertificateUUID = split[1]
	default:
		return errors.New("invalid keychain item class")
	}
	return nil
}
