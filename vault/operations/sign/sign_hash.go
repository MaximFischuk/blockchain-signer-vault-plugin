package sign

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mr-tron/base58"
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

// MessageEncoding identifies the encoding used for a pre-computed hash.
type MessageEncoding string

const (
	MessageEncodingHex       MessageEncoding = "hex"
	MessageEncodingBase32    MessageEncoding = "base32"
	MessageEncodingBase58    MessageEncoding = "base58"
	MessageEncodingBase64URL MessageEncoding = "base64url"
	MessageEncodingText      MessageEncoding = "text"
)

// UnsupportedHashEncodingError is returned when an unknown hash encoding is requested.
type UnsupportedHashEncodingError string

func (e UnsupportedHashEncodingError) Error() string {
	return fmt.Sprintf("unsupported hash encoding: %q", string(e))
}

// SignHashOperation signs a pre-computed hash with the key identified by id.
type SignHashOperation interface {
	Execute(ctx context.Context, id, hash string, encoding MessageEncoding) (string, error)
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

func (o *signHashOperation) Execute(ctx context.Context, id, hash string, encoding MessageEncoding) (string, error) {
	hashBytes, err := decodeHash(hash, encoding)
	if err != nil {
		return "", err
	}

	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}

	return signHash(key, hashBytes)
}

func decodeHash(hash string, encoding MessageEncoding) ([]byte, error) {
	switch encoding {
	case "", MessageEncodingHex:
		value, err := hex.DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid hex hash: %w", err)
		}
		return value, nil
	case MessageEncodingBase32:
		value, err := base32.StdEncoding.DecodeString(hash)
		if err == nil {
			return value, nil
		}
		value, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid base32 hash: %w", err)
		}
		return value, nil
	case MessageEncodingBase58:
		value, err := base58.Decode(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid base58 hash: %w", err)
		}
		return value, nil
	case MessageEncodingBase64URL:
		value, err := base64.URLEncoding.DecodeString(hash)
		if err == nil {
			return value, nil
		}
		value, err = base64.RawURLEncoding.DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid base64url hash: %w", err)
		}
		return value, nil
	default:
		return nil, UnsupportedHashEncodingError(encoding)
	}
}

func decodeMessage(message string, encoding MessageEncoding) ([]byte, error) {
	switch encoding {
	case "", MessageEncodingText:
		return []byte(message), nil
	default:
		return decodeHash(message, encoding)
	}
}

// SignMessageOperation hashes the message with the given hash function then signs the digest.
type SignMessageOperation interface {
	Execute(ctx context.Context, id, message string, encoding MessageEncoding, hashFn HashFunction) (string, error)
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

func (o *signMessageOperation) Execute(ctx context.Context, id, message string, encoding MessageEncoding, hashFn HashFunction) (string, error) {
	messageBytes, err := decodeMessage(message, encoding)
	if err != nil {
		return "", err
	}

	digest, err := hashMessage(messageBytes, hashFn)
	if err != nil {
		return "", err
	}

	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}

	return signHash(key, digest)
}

// SignBatchHashesOperation signs a list of pre-computed hashes and returns signatures in
// the same order as the input.
type SignBatchHashesOperation interface {
	Execute(ctx context.Context, id string, hashes []string, encoding MessageEncoding) ([]string, error)
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

func (o *signBatchHashesOperation) Execute(ctx context.Context, id string, hashes []string, encoding MessageEncoding) ([]string, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return nil, err
	}

	signatures := make([]string, len(hashes))
	for i, hash := range hashes {
		hashBytes, err := decodeHash(hash, encoding)
		if err != nil {
			return nil, fmt.Errorf("invalid hash at index %d: %w", i, err)
		}
		sig, err := signHash(key, hashBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to sign hash at index %d: %w", i, err)
		}
		signatures[i] = sig
	}

	return signatures, nil
}
