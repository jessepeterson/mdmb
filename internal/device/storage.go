package device

import (
	"errors"

	"github.com/jessepeterson/mdmb/internal/boltprim"
	bolt "go.etcd.io/bbolt"
)

func (device *Device) validDevice() bool {
	return device.UDID != ""
}

// Save device to bolt DB storage
func (device *Device) Save(db *bolt.DB) error {
	if !device.validDevice() {
		return errors.New("invalid device")
	}
	return db.Update(func(tx *bolt.Tx) error {
		err := boltprim.BucketPutOrDeleteString(tx, "device_serial", device.UDID, device.Serial)
		if err != nil {
			return err
		}
		err = boltprim.BucketPutOrDeleteString(tx, "device_computer_name", device.UDID, device.ComputerName)
		if err != nil {
			return err
		}
		err = boltprim.BucketPutOrDeleteString(tx, "device_mdm_identity_keychain_uuid", device.UDID, device.MDMIdentityKeychainUUID)
		if err != nil {
			return err
		}
		return boltprim.BucketPutOrDeleteString(tx, "device_mdm_profile_id", device.UDID, device.MDMProfileIdentifier)
	})
}

// Load a device from bolt DB storage
func Load(udid string, db *bolt.DB) (device *Device, err error) {
	device = &Device{UDID: udid}
	err = db.View(func(tx *bolt.Tx) error {
		device.Serial = boltprim.BucketGetString(tx, "device_serial", udid)
		if device.Serial == "" {
			return errors.New("device not found (serial not found)")
		}
		device.ComputerName = boltprim.BucketGetString(tx, "device_computer_name", udid)
		device.MDMIdentityKeychainUUID = boltprim.BucketGetString(tx, "device_mdm_identity_keychain_uuid", udid)
		device.MDMProfileIdentifier = boltprim.BucketGetString(tx, "device_mdm_profile_id", udid)
		return nil
	})
	return
}

// List devices in bolt DB storage
func List(db *bolt.DB) (udids []string, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("device_serial"))
		if b == nil {
			return nil
		}
		b.ForEach(func(k, _ []byte) error {
			udids = append(udids, string(k))
			return nil
		})
		return nil
	})
	if len(udids) == 0 {
		err = errors.New("no devices in database")
	}
	return
}
