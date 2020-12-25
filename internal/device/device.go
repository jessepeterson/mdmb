package device

import (
	"crypto/rsa"
	"crypto/x509"
)

// Device represents a pseudo Apple device for MDM interactions
type Device struct {
	UDID         string
	Serial       string
	ComputerName string

	IdentityCertificate *x509.Certificate
	IdentityPrivateKey  *rsa.PrivateKey
}
