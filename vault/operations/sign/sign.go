package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
	"golang.org/x/crypto/sha3"
)

type SignOperations interface {
	SignHash() SignHashOperation
	SignMessage() SignMessageOperation
	SignBatchHashes() SignBatchHashesOperation
}

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

// UnsupportedCurveForSigningError is returned when a curve does not support signing.
type UnsupportedCurveForSigningError string

func (e UnsupportedCurveForSigningError) Error() string {
	return fmt.Sprintf("curve %q does not support signing", string(e))
}

// SignHashOperation signs a pre-computed hash (provided as hex) with the key identified by id.
type SignHashOperation interface {
	Execute(ctx context.Context, id string, hashHex string) (string, error)
	WithStorage(storage logical.Storage) SignHashOperation
}

// SignMessageOperation hashes the message with the given hash function then signs the digest.
type SignMessageOperation interface {
	Execute(ctx context.Context, id string, message []byte, hashFn HashFunction) (string, error)
	WithStorage(storage logical.Storage) SignMessageOperation
}

// SignBatchHashesOperation signs a list of pre-computed hashes (each in hex) and returns
// signatures in the same order as the input.
type SignBatchHashesOperation interface {
	Execute(ctx context.Context, id string, hashHexList []string) ([]string, error)
	WithStorage(storage logical.Storage) SignBatchHashesOperation
}

// --- SignHashOperation implementation ---

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

// --- SignMessageOperation implementation ---

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

// --- SignBatchHashesOperation implementation ---

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

// --- helpers ---

func loadKey(ctx context.Context, s logical.Storage, id string) (*entities.PrivateKey, error) {
	var key entities.PrivateKey
	if err := storage.ReadJSON(ctx, s, storage.PrivateKeysStorageKey(id), &key); err != nil {
		var coreErr *coreErrors.Error
		if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
			return nil, coreErr
		}
		return nil, err
	}
	return &key, nil
}

func hashMessage(message []byte, hashFn HashFunction) ([]byte, error) {
	switch hashFn {
	case HashFunctionSHA256:
		digest := sha256.Sum256(message)
		return digest[:], nil
	case HashFunctionKeccak256:
		h := sha3.NewLegacyKeccak256()
		h.Write(message)
		return h.Sum(nil), nil
	case HashFunctionSHA512:
		digest := sha512.Sum512(message)
		return digest[:], nil
	case HashFunctionSHA3256:
		h := sha3.New256()
		h.Write(message)
		return h.Sum(nil), nil
	default:
		return nil, UnsupportedHashFunctionError(hashFn)
	}
}

func signHash(key *entities.PrivateKey, hash []byte) (string, error) {
	switch key.Curve {
	case crypto.Secp256k1:
		return signSecp256k1(key.PrivateKey, hash)
	case crypto.Ed25519:
		return signEd25519(key.PrivateKey, hash)
	case crypto.P256:
		return signP256(key.PrivateKey, hash)
	case crypto.X25519:
		return "", UnsupportedCurveForSigningError(key.Curve)
	default:
		return "", crypto.UnsupportedCurveError(key.Curve)
	}
}

func signSecp256k1(privKeyHex string, hash []byte) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode secp256k1 private key: %w", err)
	}

	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	sig := secp256k1ecdsa.Sign(privKey, hash)
	return hex.EncodeToString(sig.Serialize()), nil
}

func signEd25519(privKeyHex string, hash []byte) (string, error) {
	seedBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode ed25519 private key: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(seedBytes)
	sig := ed25519.Sign(privKey, hash)
	return hex.EncodeToString(sig), nil
}

func signP256(privKeyHex string, hash []byte) (string, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode P-256 private key: %w", err)
	}

	curve := elliptic.P256()
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         new(big.Int).SetBytes(privKeyBytes),
	}
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(privKeyBytes)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign with P-256: %w", err)
	}

	// Encode as r || s, each zero-padded to 32 bytes (fixed-size DER-free format).
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return hex.EncodeToString(sig), nil
}
