package device

import "crypto/rsa"

// Device represents a pseudo Apple device for MDM interactions
type Device struct {
	UDID         string
	Serial       string
	ComputerName string

	DeviceIdentityKey *rsa.PrivateKey
}
