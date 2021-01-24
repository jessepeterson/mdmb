package device

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

func (device *Device) validDevice() bool {
	return device.UDID != ""
}

func putOrDelete(b *bolt.Bucket, uuid, extn string, value []byte) error {
	key := []byte(uuid + "_" + extn)
	if value == nil || len(value) == 0 {
		return b.Delete(key)
	}
	return b.Put(key, value)
}

// Save device to bolt DB storage
func (device *Device) Save(db *bolt.DB) error {
	if !device.validDevice() {
		return errors.New("invalid device")
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("device"))
		err := putOrDelete(b, device.UDID, "udid", []byte(device.UDID))
		if err != nil {
			return err
		}
		err = putOrDelete(b, device.UDID, "serial", []byte(device.Serial))
		if err != nil {
			return err
		}
		err = putOrDelete(b, device.UDID, "computer_name", []byte(device.ComputerName))
		if err != nil {
			return err
		}
		// TODO: move this into some sort of pseudo-keychain
		var cert []byte
		if device.IdentityCertificate != nil {
			cert = make([]byte, len(device.IdentityCertificate.Raw))
			copy(cert, device.IdentityCertificate.Raw)
			fmt.Println(cert)
		}
		err = putOrDelete(b, device.UDID, "mdm_cert", cert)
		if err != nil {
			return err
		}
		return nil
	})
}
