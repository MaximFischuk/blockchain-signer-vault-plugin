package storage

import "fmt"

const (
	PrivateKeysStoragePrefix = "private-keys"
)

func PrivateKeysStorageKey(id string) string {
	return fmt.Sprintf("%s/%s", PrivateKeysStoragePrefix, id)
}
