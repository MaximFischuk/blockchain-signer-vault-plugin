package storage

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
)

func SaveJSON(ctx context.Context, storage logical.Storage, key string, data any) error {
	logger := log.FromContext(ctx).With("key", key)

	entry, err := logical.StorageEntryJSON(key, data)
	if err != nil {
		errMessage := "failed to create JSON entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	err = storage.Put(ctx, entry)
	if err != nil {
		errMessage := "failed to store entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	return nil
}

func ReadJSON(ctx context.Context, storage logical.Storage, key string, dest any) error {
	logger := log.FromContext(ctx).With("key", key)

	entry, err := storage.Get(ctx, key)
	if err != nil {
		errMessage := "failed to read entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	if entry == nil {
		errMessage := "entry not found"
		logger.Error(errMessage)
		return errors.EntryNotFoundError(errMessage)
	}

	err = entry.DecodeJSON(dest)
	if err != nil {
		errMessage := "failed to decode JSON entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	return nil
}

func Delete(ctx context.Context, storage logical.Storage, key string) error {
	logger := log.FromContext(ctx).With("key", key)

	err := storage.Delete(ctx, key)
	if err != nil {
		errMessage := "failed to delete entry"
		logger.With("error", err).Error(errMessage)
		return errors.StorageError(errMessage)
	}

	return nil
}
