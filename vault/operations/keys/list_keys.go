package keys

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
)

type listKeysOperation struct {
	storage logical.Storage
}

func NewListKeysOperation() ListKeysOperation {
	return &listKeysOperation{}
}

// WithStorage returns a shallow copy of the operation with the storage backend
// set. The copy semantics (value receiver) mirror CreateKeyOperation so that
// each request gets its own isolated instance and the shared prototype stored
// in keysOperations is never mutated.
func (o listKeysOperation) WithStorage(s logical.Storage) ListKeysOperation {
	o.storage = s
	return &o
}

func (o *listKeysOperation) Execute(ctx context.Context) ([]string, error) {
	keys, err := o.storage.List(ctx, storage.PrivateKeysStorageKey(""))
	if err != nil {
		errMessage := "failed to list keys"
		log.FromContext(ctx).With("error", err).Error(errMessage)
		return nil, errors.StorageError(errMessage)
	}
	return keys, nil
}
