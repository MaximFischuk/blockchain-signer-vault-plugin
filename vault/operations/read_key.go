package operations

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
)

type readKeyOperation struct {
	storage logical.Storage
}

func NewReadKeyOperation() ReadKeyOperation {
	return &readKeyOperation{}
}

// WithStorage returns a shallow copy of the operation with the storage backend
// set. The copy semantics (value receiver) mirror CreateKeyOperation so that
// each request gets its own isolated instance and the shared prototype stored
// in keysOperations is never mutated.
func (o readKeyOperation) WithStorage(s logical.Storage) ReadKeyOperation {
	o.storage = s
	return &o
}

// Execute loads the persisted PrivateKey entry identified by id.
// It returns the full entity (including the encrypted private-key material
// that Vault keeps in seal-wrapped storage); callers in the HTTP layer are
// responsible for omitting the private key from any outbound response.
//
// Errors:
//   - storage.StorageEntryNotFoundCode — no key exists for the given id
//   - storage.StorageErrorCode         — underlying Vault storage failure
func (o *readKeyOperation) Execute(ctx context.Context, id string) (*entities.PrivateKey, error) {
	var key entities.PrivateKey
	if err := storage.ReadJSON(ctx, o.storage, storage.PrivateKeysStorageKey(id), &key); err != nil {
		return nil, err
	}
	return &key, nil
}
