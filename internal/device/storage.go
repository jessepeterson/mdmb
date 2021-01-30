package device

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

func (device *Device) validDevice() bool {
	return device.UDID != ""
}

func putOrDeleteBucketRow(tx *bolt.Tx, bucket, key string, value []byte) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	keyBytes := []byte(key)
	if len(value) == 0 {
		return b.Delete(keyBytes)
	}
	return b.Put(keyBytes, value)
}

// Save device to bolt DB storage
func (device *Device) Save(db *bolt.DB) error {
	if !device.validDevice() {
		return errors.New("invalid device")
	}
	return db.Update(func(tx *bolt.Tx) error {
		err := putOrDeleteBucketRow(tx, "device_serial", device.UDID, []byte(device.Serial))
		if err != nil {
			return err
		}
		err = putOrDeleteBucketRow(tx, "device_computer_name", device.UDID, []byte(device.ComputerName))
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
		err = putOrDeleteBucketRow(tx, "device_mdm_cert", device.UDID, cert)
		if err != nil {
			return err
		}
		return nil
	})
}
