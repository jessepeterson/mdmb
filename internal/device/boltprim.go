package device

import (
	"bytes"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

// BucketPutOrDelete Puts a value to a BoltDB bucket. If the value is empty the key is Deleted.
func BucketPutOrDelete(tx *bolt.Tx, bucket, key string, value []byte) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return b.Delete([]byte(key))
	}
	return b.Put([]byte(key), value)
}

// BucketGet retrieves a value from a bucket or returns nil.
func BucketGet(tx *bolt.Tx, bucket, key string) []byte {
	b := tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.Get([]byte(key))
}

// BucketPutOrDeleteString Puts a value to a BoltDB bucket. If the value is empty the key is Deleted.
func BucketPutOrDeleteString(tx *bolt.Tx, bucket, key, value string) error {
	return BucketPutOrDelete(tx, bucket, key, []byte(value))
}

// BucketGetString retrieves a value from a bucket or returns "".
func BucketGetString(tx *bolt.Tx, bucket, key string) string {
	return string(BucketGet(tx, bucket, key))
}

// BucketPutOrDeleteInt Puts a value to a BoltDB bucket. If the value is 0 the key is Deleted.
func BucketPutOrDeleteInt(tx *bolt.Tx, bucket, key string, value int) error {
	var byteValue []byte
	if value != 0 {
		byteValue = []byte(strconv.Itoa(value))
	}
	return BucketPutOrDelete(tx, bucket, key, byteValue)
}

// BucketGetInt retrieves a value from a bucket or returns 0.
func BucketGetInt(tx *bolt.Tx, bucket, key string) int {
	i, _ := strconv.Atoi(string(BucketGet(tx, bucket, key)))
	return i

}

// BucketGetKeysWithPrefix retrieves a list of keys with a prefix in a bucket
func BucketGetKeysWithPrefix(tx *bolt.Tx, bucket string, prefix string, stripPrefix bool) []string {
	b := tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	c := b.Cursor()
	var results []string
	prefixBytes := []byte(prefix)
	for k, _ := c.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, _ = c.Next() {
		if stripPrefix {
			k = k[len(prefix):]
		}
		results = append(results, string(k))
	}
	return results
}
