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

func getBucketRow(tx *bolt.Tx, bucket, key string) []byte {
	b := tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.Get([]byte(key))
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

// Load a device from bolt DB storage
func Load(udid string, db *bolt.DB) (device *Device, err error) {
	device = &Device{UDID: udid}
	err = db.View(func(tx *bolt.Tx) error {
		device.Serial = string(getBucketRow(tx, "device_serial", udid))
		if device.Serial == "" {
			return errors.New("device not found (serial not found)")
		}
		device.ComputerName = string(getBucketRow(tx, "device_computer_name", udid))
		return nil
	})
	return
}

// List devices in bolt DB storage
func List(db *bolt.DB) (udids []string, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("device_serial"))
		if b == nil {
			return errors.New("no devices in database")
		}
		b.ForEach(func(k, _ []byte) error {
			udids = append(udids, string(k))
			return nil
		})
		return nil
	})
	return
}
