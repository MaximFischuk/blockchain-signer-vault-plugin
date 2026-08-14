package sign

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

// HashFunction identifies the hash algorithm used to pre-hash a message before signing.
type HashFunction string

const (
	HashFunctionSHA256    HashFunction = "sha256"
	HashFunctionKeccak256 HashFunction = "keccak256"
	HashFunctionSHA512    HashFunction = "sha512"
	HashFunctionSHA3256   HashFunction = "sha3-256"
)

// UnsupportedHashFunctionError is returned when an unknown hash function is requested.
type UnsupportedHashFunctionError string

func (e UnsupportedHashFunctionError) Error() string {
	return fmt.Sprintf("unsupported hash function: %q", string(e))
}

// SignHashOperation signs a pre-computed hash (provided as hex) with the key identified by id.
type SignHashOperation interface {
	Execute(ctx context.Context, id string, hashHex string) (string, error)
	WithStorage(storage logical.Storage) SignHashOperation
}

type signHashOperation struct {
	storage logical.Storage
}

func NewSignHashOperation() SignHashOperation {
	return &signHashOperation{}
}

func (o signHashOperation) WithStorage(s logical.Storage) SignHashOperation {
	o.storage = s
	return &o
}

func (o *signHashOperation) Execute(ctx context.Context, id string, hashHex string) (string, error) {
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("invalid hex hash: %w", err)
	}

	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}

	return signHash(key, hashBytes)
}

// SignMessageOperation hashes the message with the given hash function then signs the digest.
type SignMessageOperation interface {
	Execute(ctx context.Context, id string, message []byte, hashFn HashFunction) (string, error)
	WithStorage(storage logical.Storage) SignMessageOperation
}

type signMessageOperation struct {
	storage logical.Storage
}

func NewSignMessageOperation() SignMessageOperation {
	return &signMessageOperation{}
}

func (o signMessageOperation) WithStorage(s logical.Storage) SignMessageOperation {
	o.storage = s
	return &o
}

func (o *signMessageOperation) Execute(ctx context.Context, id string, message []byte, hashFn HashFunction) (string, error) {
	digest, err := hashMessage(message, hashFn)
	if err != nil {
		return "", err
	}

	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}

	return signHash(key, digest)
}

// SignBatchHashesOperation signs a list of pre-computed hashes (each in hex) and returns
// signatures in the same order as the input.
type SignBatchHashesOperation interface {
	Execute(ctx context.Context, id string, hashHexList []string) ([]string, error)
	WithStorage(storage logical.Storage) SignBatchHashesOperation
}

type signBatchHashesOperation struct {
	storage logical.Storage
}

func NewSignBatchHashesOperation() SignBatchHashesOperation {
	return &signBatchHashesOperation{}
}

func (o signBatchHashesOperation) WithStorage(s logical.Storage) SignBatchHashesOperation {
	o.storage = s
	return &o
}

func (o *signBatchHashesOperation) Execute(ctx context.Context, id string, hashHexList []string) ([]string, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return nil, err
	}

	signatures := make([]string, len(hashHexList))
	for i, hashHex := range hashHexList {
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex hash at index %d: %w", i, err)
		}
		sig, err := signHash(key, hashBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to sign hash at index %d: %w", i, err)
		}
		signatures[i] = sig
	}

	return signatures, nil
}
