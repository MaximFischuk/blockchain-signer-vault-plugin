package keys

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
)

type deleteKeyOperation struct {
	storage logical.Storage
}

func NewDeleteKeyOperation() DeleteKeyOperation {
	return &deleteKeyOperation{}
}

// WithStorage returns a shallow copy of the operation with the storage backend
// set. The copy semantics (value receiver) mirror CreateKeyOperation so that
// each request gets its own isolated instance and the shared prototype stored
// in keysOperations is never mutated.
func (o deleteKeyOperation) WithStorage(s logical.Storage) DeleteKeyOperation {
	o.storage = s
	return &o
}

func (o *deleteKeyOperation) Execute(ctx context.Context, id string) error {
	key := storage.PrivateKeysStorageKey(id)
	logger := log.FromContext(ctx).With("key", key)

	entry, err := o.storage.Get(ctx, key)
	if err != nil {
		errMessage := "failed to read entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	if entry == nil {
		logger.Debug("entry not found")
		return nil
	}

	err = o.storage.Delete(ctx, key)

	if err != nil {
		errMessage := "failed to delete entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	return nil
}
