package operations

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
	"golang.org/x/crypto/curve25519"
)

type createKeyOperation struct {
	storage logical.Storage
}

func NewCreateKeyOperation() CreateKeyOperation {
	return &createKeyOperation{}
}

func (o createKeyOperation) WithStorage(storage logical.Storage) CreateKeyOperation {
	o.storage = storage
	return &o
}

func (o *createKeyOperation) Execute(ctx context.Context, id, curve string, metadata map[string]string) (*entities.PrivateKey, error) {
	var key *entities.PrivateKey
	var err error
	switch curve {
	case crypto.Secp256k1:
		key, err = o.createSecp256k1Key(id, metadata)
	case crypto.Ed25519:
		key, err = o.createEd25519Key(id, metadata)
	case crypto.P256:
		key, err = o.createP256Key(id, metadata)
	case crypto.X25519:
		key, err = o.createX25519Key(id, metadata)
	default:
		key, err = nil, crypto.UnsupportedCurveError(curve)
	}

	if err != nil {
		return nil, err
	}

	err = storage.SaveJSON(ctx, o.storage, storage.PrivateKeysStorageKey(id), key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// createSecp256k1Key generates a secp256k1 key pair using
// github.com/decred/dcrd/dcrec/secp256k1/v4, which sources entropy from
// crypto/rand internally. The private key is the 32-byte big-endian scalar;
// the public key is the 33-byte compressed point — both hex-encoded.
func (o *createKeyOperation) createSecp256k1Key(id string, metadata map[string]string) (*entities.PrivateKey, error) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	privKeyHex := hex.EncodeToString(privKey.Serialize())
	pubKeyHex := hex.EncodeToString(privKey.PubKey().SerializeCompressed())

	now := time.Now().UTC()
	return &entities.PrivateKey{
		ID:         id,
		KeyType:    crypto.KeyTypeEC,
		Curve:      crypto.Secp256k1,
		PrivateKey: privKeyHex,
		PublicKey:  pubKeyHex,
		Metadata:   metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// createEd25519Key generates an Ed25519 key pair using the Go standard library
// crypto/ed25519 with crypto/rand as the entropy source.
// Only the 32-byte seed is stored as the private key (not the 64-byte Go
// representation), making it portable across implementations.
// The public key is the canonical 32-byte Edwards point, both hex-encoded.
func (o *createKeyOperation) createEd25519Key(id string, metadata map[string]string) (*entities.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// ed25519.PrivateKey in Go is seed || public_key (64 bytes).
	// Store only the 32-byte seed so the key material is interoperable
	// with other Ed25519 implementations.
	privKeyHex := hex.EncodeToString(privKey.Seed())
	pubKeyHex := hex.EncodeToString(pubKey)

	now := time.Now().UTC()
	return &entities.PrivateKey{
		ID:         id,
		KeyType:    crypto.KeyTypeOKP,
		Curve:      crypto.Ed25519,
		PrivateKey: privKeyHex,
		PublicKey:  pubKeyHex,
		Metadata:   metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// createP256Key generates a NIST P-256 (prime256v1) ECDSA key pair using the
// Go standard library crypto/ecdsa with crypto/rand as the entropy source.
// The private key is the 32-byte big-endian D scalar; the public key is the
// 33-byte compressed point — both hex-encoded.
func (o *createKeyOperation) createP256Key(id string, metadata map[string]string) (*entities.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Pad D to exactly 32 bytes to guard against leading-zero stripping.
	dBytes := make([]byte, 32)
	privKey.D.FillBytes(dBytes)

	privKeyHex := hex.EncodeToString(dBytes)
	pubKeyHex := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y))

	now := time.Now().UTC()
	return &entities.PrivateKey{
		ID:         id,
		KeyType:    crypto.KeyTypeEC,
		Curve:      crypto.P256,
		PrivateKey: privKeyHex,
		PublicKey:  pubKeyHex,
		Metadata:   metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// createX25519Key generates an X25519 (Diffie-Hellman on Curve25519) key pair.
// 32 cryptographically random bytes are read from crypto/rand, clamped per
// RFC 7748 §5, then multiplied by the Curve25519 base point to derive the
// public key. Both values are hex-encoded.
func (o *createKeyOperation) createX25519Key(id string, metadata map[string]string) (*entities.PrivateKey, error) {
	scalar := make([]byte, curve25519.ScalarSize) // 32 bytes
	if _, err := rand.Read(scalar); err != nil {
		return nil, err
	}

	// RFC 7748 §5 clamping for X25519 scalar.
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	pubKey, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	privKeyHex := hex.EncodeToString(scalar)
	pubKeyHex := hex.EncodeToString(pubKey)

	now := time.Now().UTC()
	return &entities.PrivateKey{
		ID:         id,
		KeyType:    crypto.KeyTypeOKP,
		Curve:      crypto.X25519,
		PrivateKey: privKeyHex,
		PublicKey:  pubKeyHex,
		Metadata:   metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}
