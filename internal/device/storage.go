package device

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

func (device *Device) Save(_ *bolt.DB) error {

	// 	db, err := bolt.Open("devices.db", 0644, nil)
	// 	if err != nil {
	// 	  return err
	// 	}
	// 	defer db.Close()
	fmt.Println("hi!")
	return nil
}
