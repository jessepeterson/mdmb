package device

import (
	"errors"

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
		b := tx.Bucket([]byte("device"))
		err := b.Put([]byte(device.UDID+"_serial"), []byte(device.Serial))
		return err
	})
}
