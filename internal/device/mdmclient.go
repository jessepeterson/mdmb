package device

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/jessepeterson/cfgprofiles"
)

type MDMClient struct {
	Device     *Device
	MDMPayload *cfgprofiles.MDMPayload

	IdentityCertificate *x509.Certificate
	IdentityPrivateKey  *rsa.PrivateKey
}

func (c *MDMClient) loadIdentityFromKeychain(uuid string) error {
	if uuid == "" {
		return errors.New("invalid keychain UUID")
	}
	kciID, err := LoadKeychainItem(c.Device.SystemKeychain(), uuid)
	if err != nil {
		return err
	}

	kciKey, err := LoadKeychainItem(c.Device.SystemKeychain(), kciID.IdentityKeyUUID)
	if err != nil {
		return err
	}

	kciCert, err := LoadKeychainItem(c.Device.SystemKeychain(), kciID.IdentityCertificateUUID)
	if err != nil {
		return err
	}

	c.IdentityPrivateKey = kciKey.Key
	c.IdentityCertificate = kciCert.Certificate
	return nil
}

func newMDMClientUsingPayload(device *Device, mdmPld *cfgprofiles.MDMPayload) (*MDMClient, error) {
	c := &MDMClient{Device: device, MDMPayload: mdmPld}
	err := c.loadIdentityFromKeychain(device.MDMIdentityKeychainUUID)
	return c, err
}

func (c *MDMClient) loadMDMPayload(profileID string) error {
	if profileID == "" {
		return errors.New("no MDM profile installed on device")
	}
	profile, err := c.Device.SystemProfileStore().Load(profileID)
	if err != nil {
		return err
	}
	mdmPlds := profile.MDMPayloads()
	if len(mdmPlds) != 1 {
		return errors.New("enrollment profile must contain one MDM payload")
	}
	c.MDMPayload = mdmPlds[0]
	return nil
}

func newMDMClient(device *Device) (*MDMClient, error) {
	c := &MDMClient{Device: device}
	if device.MDMIdentityKeychainUUID == "" {
		return c, errors.New("device not enrolled (no identity uuid)")
	}
	err := c.loadIdentityFromKeychain(device.MDMIdentityKeychainUUID)
	if err != nil {
		return c, err
	}
	err = c.loadMDMPayload(device.MDMProfileIdentifier)
	if err != nil {
		return c, err
	}
	if !c.enrolled() {
		return c, errors.New("device not enrolled")
	}
	return c, nil
}

func (c *MDMClient) enroll(profileID string) error {
	if c.MDMPayload == nil {
		return errors.New("no MDM payload")
	}
	if !c.MDMPayload.SignMessage {
		return errors.New("non-SignMessage (mTLS) enrollment not supported")
	}

	err := c.authenticate()
	if err != nil {
		return err
	}

	err = c.TokenUpdate("")
	if err != nil {
		return err
	}

	c.Device.MDMProfileIdentifier = profileID
	return nil
}

func (c *MDMClient) unenroll() error {
	// c.MDMPayload.CheckOutWhenRemoved
	c.IdentityPrivateKey = nil
	c.IdentityCertificate = nil
	c.MDMPayload = nil
	c.Device.MDMProfileIdentifier = ""
	c.Device.MDMIdentityKeychainUUID = ""
	return nil
}

func (c *MDMClient) enrolled() bool {
	checks := []bool{
		c.Device.MDMProfileIdentifier != "",
		c.Device.MDMIdentityKeychainUUID != "",
		c.MDMPayload != nil,
		c.IdentityCertificate != nil,
		c.IdentityPrivateKey != nil,
	}
	for _, v := range checks {
		if !v {
			return false
		}
	}
	return true
}

func (device *Device) MDMClient() (*MDMClient, error) {
	var err error
	if device.mdmClient == nil {
		device.mdmClient, err = newMDMClient(device)
	}
	return device.mdmClient, err
}
