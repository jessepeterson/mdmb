package mdmclient

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"strings"

	"github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/internal/keychain"
)

type MDMClient struct {
	Device     *device.Device
	Keychain   *keychain.Keychain
	MDMPayload *cfgprofiles.MDMPayload

	IdentityCertificate *x509.Certificate
	IdentityPrivateKey  *rsa.PrivateKey
}

func NewMDMClient(device *device.Device, kc *keychain.Keychain) *MDMClient {
	return &MDMClient{Device: device, Keychain: kc}
}

// Enroll attempts an Apple MDM enrollment using profile ep
func (c *MDMClient) Enroll(ep []byte, rand io.Reader) error {
	profile := &cfgprofiles.Profile{}

	err := plist.Unmarshal(ep, profile)
	if err != nil {
		return err
	}

	mdmPlds := profile.MDMPayloads()
	if len(mdmPlds) != 1 {
		return errors.New("enrollment profile must contain an MDM payload")
	}
	c.MDMPayload = mdmPlds[0]

	scepPlds := profile.SCEPPayloads()
	// TODO: support non-SCEP enrollment some day?
	if len(mdmPlds) != 1 {
		return errors.New("SCEP profile payload required")
	}
	scepPld := scepPlds[0]

	if !c.MDMPayload.SignMessage {
		return errors.New("non-SignMessage (mTLS) enrollment not supported")
	}

	c.IdentityPrivateKey, err = keyFromSCEPProfilePayload(scepPld, rand)
	if err != nil {
		return err
	}

	csrBytes, err := csrFromSCEPProfilePayload(scepPld, c.Device, rand, c.IdentityPrivateKey)
	if err != nil {
		return err
	}

	c.IdentityCertificate, err = scepNewPKCSReq(csrBytes, scepPld.PayloadContent.URL, scepPld.PayloadContent.Challenge)
	if err != nil {
		return err
	}

	err = c.SaveMDMIdentity()
	if err != nil {
		return err
	}

	err = c.authenticate()
	if err != nil {
		return err
	}

	err = c.tokenUpdate()
	if err != nil {
		return err
	}

	return nil
}

func (c *MDMClient) SaveMDMIdentity() error {
	// save pk to device keychain

	kciKey := keychain.NewKeychainItem(c.Keychain, keychain.ClassKey)
	kciKey.Item = x509.MarshalPKCS1PrivateKey(c.IdentityPrivateKey)
	kciKey.Save()

	kciCert := keychain.NewKeychainItem(c.Keychain, keychain.ClassCertificate)
	kciCert.Item = c.IdentityCertificate.Raw
	kciCert.Save()

	kciID := keychain.NewKeychainItem(c.Keychain, keychain.ClassIdentity)
	kciID.Item = []byte(strings.Join([]string{kciKey.UUID, kciCert.UUID}, ","))
	kciID.Save()

	// save cert to device keychain
	// save "identity" to device keychain
	return nil
}

// func (c *MDMClient) LoadMDMIdentity() error {
// 	// load "identity" from device keychain
// 	// load cert from device keychain
// 	// load pk from device keychain
// }
