package operations

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
)

type existsKeyOperation struct {
	storage logical.Storage
}

func NewExistsKeyOperation() ExistsKeyOperation {
	return &existsKeyOperation{}
}

// WithStorage returns a shallow copy of the operation with the storage backend
// set. The copy semantics (value receiver) mirror CreateKeyOperation so that
// each request gets its own isolated instance and the shared prototype stored
// in keysOperations is never mutated.
func (o existsKeyOperation) WithStorage(s logical.Storage) ExistsKeyOperation {
	o.storage = s
	return &o
}

func (o *existsKeyOperation) Execute(ctx context.Context, id string) (bool, error) {
	key := storage.PrivateKeysStorageKey(id)
	logger := log.FromContext(ctx).With("key", key)

	entry, err := o.storage.Get(ctx, key)
	if err != nil {
		errMessage := "failed to read entry"
		logger.With("error", err).Error(errMessage)
		return false, errors.StorageError(errMessage)
	}

	if entry == nil {
		logger.Debug("entry not found")
		return false, nil
	}

	return true, nil
}
