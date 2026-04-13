package operations

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
)

//go:generate mockgen -source=keys.go -destination=mocks/keys.go -package=mocks

type KeysOperations interface {
	CreateKey() CreateKeyOperation
	ReadKey() ReadKeyOperation
	ExistsKey() ExistsKeyOperation
	// DeleteKey() DeleteKeyOperation
	// UpdateKey() UpdateKeyOperation
	ListKeys() ListKeysOperation
	// ImportKey() ImportKeyOperation
	// SignPayload() SignPayloadOperation
	// SignHash() SignHashOperation
}

type CreateKeyOperation interface {
	Execute(ctx context.Context, id, curve string, metadata map[string]string) (*entities.PrivateKey, error)
	WithStorage(storage logical.Storage) CreateKeyOperation
}

type ReadKeyOperation interface {
	Execute(ctx context.Context, id string) (*entities.PrivateKey, error)
	WithStorage(storage logical.Storage) ReadKeyOperation
}

type ExistsKeyOperation interface {
	Execute(ctx context.Context, id string) (bool, error)
	WithStorage(storage logical.Storage) ExistsKeyOperation
}

type DeleteKeyOperation interface {
	Execute(ctx context.Context, id string) error
	WithStorage(storage logical.Storage) DeleteKeyOperation
}

type UpdateKeyOperation interface {
	Execute(ctx context.Context, id string) error
	WithStorage(storage logical.Storage) UpdateKeyOperation
}

type ListKeysOperation interface {
	Execute(ctx context.Context) ([]string, error)
	WithStorage(storage logical.Storage) ListKeysOperation
}

type ImportKeyOperation interface {
	Execute(ctx context.Context, key *entities.PrivateKey) error
	WithStorage(storage logical.Storage) ImportKeyOperation
}

type SignPayloadOperation interface {
	Execute(ctx context.Context, id string, payload []byte) ([]byte, error)
	WithStorage(storage logical.Storage) SignPayloadOperation
}

type SignHashOperation interface {
	Execute(ctx context.Context, id string, hash []byte) ([]byte, error)
	WithStorage(storage logical.Storage) SignHashOperation
}
