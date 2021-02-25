package device

import (
	"math/rand"
	"strings"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Device represents a pseudo Apple device for MDM interactions
type Device struct {
	UDID         string
	Serial       string
	ComputerName string

	MDMIdentityKeychainUUID string
	MDMProfileIdentifier    string

	boltDB *bolt.DB

	sysKeychain *Keychain
}

// New creates a new device with a random serial number and UDID
func New(name string, db *bolt.DB) *Device {
	device := &Device{
		ComputerName: name,
		Serial:       randSerial(),
		UDID:         strings.ToUpper(uuid.NewString()),
		boltDB:       db,
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
