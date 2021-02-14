package device

import (
	"crypto/rsa"
	"crypto/x509"
	"math/rand"
	"strings"

	"github.com/google/uuid"
)

// Device represents a pseudo Apple device for MDM interactions
type Device struct {
	UDID         string
	Serial       string
	ComputerName string

	IdentityCertificate *x509.Certificate
	IdentityPrivateKey  *rsa.PrivateKey
}

// New creates a new device with a random serial number and UDID
func New(name string) *Device {
	device := &Device{
		ComputerName: name,
		Serial:       randSerial(),
		UDID:         strings.ToUpper(uuid.NewString()),
	}
	if name == "" {
		device.ComputerName = device.Serial + "'s Computer"
	}
	return device
}

// numbers plus capital letters without I, L, O for readability
const serialLetters = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ"

func randSerial() string {
	b := make([]byte, 12)
	for i := range b {
		b[i] = serialLetters[rand.Intn(len(serialLetters))]
	}
	return string(b)
}
