package sign_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault/sdk/logical"
	keys "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/keys"
	sign "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newInMemoryStorage returns a fresh in-memory Vault logical storage backend.
func newInMemoryStorage() logical.Storage {
	return &logical.InmemStorage{}
}

// seedSecp256k1Key creates a secp256k1 key in storage and returns its hex private key.
func seedSecp256k1Key(t *testing.T, ctx context.Context, storage logical.Storage, id string) string {
	t.Helper()
	key, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, "secp256k1", nil)
	require.NoError(t, err)
	return key.PrivateKey
}

// seedEd25519Key creates an ed25519 key in storage.
func seedEd25519Key(t *testing.T, ctx context.Context, storage logical.Storage, id string) {
	t.Helper()
	_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, "ed25519", nil)
	require.NoError(t, err)
}

// seedP256Key creates a P-256 key in storage.
func seedP256Key(t *testing.T, ctx context.Context, storage logical.Storage, id string) {
	t.Helper()
	_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, "p256", nil)
	require.NoError(t, err)
}

// --- SignHashOperation tests ---

func TestSignHashOperation_Secp256k1(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	privKeyHex := seedSecp256k1Key(t, ctx, s, "key1")

	hash := sha256.Sum256([]byte("hello world"))
	hashHex := hex.EncodeToString(hash[:])

	op := sign.NewSignHashOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", hashHex, sign.MessageEncodingHex)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)

	// Verify the signature using secp256k1
	privKeyBytes, _ := hex.DecodeString(privKeyHex)
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	sigBytes, err := hex.DecodeString(sigHex)
	require.NoError(t, err)
	sig, err := secp256k1ecdsa.ParseDERSignature(sigBytes)
	require.NoError(t, err)
	assert.True(t, sig.Verify(hash[:], privKey.PubKey()), "signature verification failed")
}

func TestSignHashOperation_Ed25519(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedEd25519Key(t, ctx, s, "key1")

	key, err := keys.NewReadKeyOperation().WithStorage(s).Execute(ctx, "key1")
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("hello world"))
	hashHex := hex.EncodeToString(hash[:])

	op := sign.NewSignHashOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", hashHex, sign.MessageEncodingHex)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)

	// Verify using ed25519
	pubKeyBytes, _ := hex.DecodeString(key.PublicKey)
	sigBytes, _ := hex.DecodeString(sigHex)
	assert.True(t, ed25519.Verify(pubKeyBytes, hash[:], sigBytes), "ed25519 signature verification failed")
}

func TestSignHashOperation_P256(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedP256Key(t, ctx, s, "key1")

	key, err := keys.NewReadKeyOperation().WithStorage(s).Execute(ctx, "key1")
	require.NoError(t, err)

	hash := sha256.Sum256([]byte("hello world"))
	hashHex := hex.EncodeToString(hash[:])

	op := sign.NewSignHashOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", hashHex, sign.MessageEncodingHex)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)

	// Verify using P-256: reconstruct public key from compressed point
	pubKeyBytes, _ := hex.DecodeString(key.PublicKey)
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
	require.NotNil(t, x, "failed to unmarshal compressed P-256 public key")
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	sigBytes, _ := hex.DecodeString(sigHex)
	r := new(big.Int).SetBytes(sigBytes[:32])
	s2 := new(big.Int).SetBytes(sigBytes[32:])
	assert.True(t, ecdsa.Verify(pubKey, hash[:], r, s2), "P-256 signature verification failed")
}

func TestSignHashOperation_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()

	hash := sha256.Sum256([]byte("hello world"))
	hashHex := hex.EncodeToString(hash[:])

	op := sign.NewSignHashOperation().WithStorage(s)
	_, err := op.Execute(ctx, "nonexistent", hashHex, sign.MessageEncodingHex)
	assert.Error(t, err)
}

func TestSignHashOperation_InvalidHex(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	op := sign.NewSignHashOperation().WithStorage(s)
	_, err := op.Execute(ctx, "key1", "not-valid-hex!!", sign.MessageEncodingHex)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex hash")
}

func TestSignHashOperation_EncodingsProduceEqualSignatures(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, storage, "key1")

	message := []byte("hello world")
	cases := []struct {
		encoding sign.MessageEncoding
		hash     string
	}{
		{sign.MessageEncodingHex, hex.EncodeToString(message)},
		{sign.MessageEncodingBase32, base32.StdEncoding.EncodeToString(message)},
		{sign.MessageEncodingBase58, base58.Encode(message)},
		{sign.MessageEncodingBase64URL, base64.RawURLEncoding.EncodeToString(message)},
	}

	op := sign.NewSignHashOperation().WithStorage(storage)
	var expectedSignature string
	for _, testCase := range cases {
		signature, err := op.Execute(ctx, "key1", testCase.hash, testCase.encoding)
		require.NoError(t, err)
		if expectedSignature == "" {
			expectedSignature = signature
			continue
		}
		assert.Equal(t, expectedSignature, signature)
	}
}

// --- SignMessageOperation tests ---

func TestSignMessageOperation_SHA256(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	message := []byte("hello world")
	op := sign.NewSignMessageOperation().WithStorage(s)
	encodings := []struct {
		encoding sign.MessageEncoding
		message  string
	}{
		{sign.MessageEncodingHex, hex.EncodeToString(message)},
		{sign.MessageEncodingBase32, base32.StdEncoding.EncodeToString(message)},
		{sign.MessageEncodingBase58, base58.Encode(message)},
		{sign.MessageEncodingBase64URL, base64.RawURLEncoding.EncodeToString(message)},
		{sign.MessageEncodingText, string(message)},
	}

	var expectedSignature string
	for _, testCase := range encodings {
		signature, err := op.Execute(ctx, "key1", testCase.message, testCase.encoding, sign.HashFunctionSHA256)
		require.NoError(t, err)
		if expectedSignature == "" {
			expectedSignature = signature
			continue
		}
		assert.Equal(t, expectedSignature, signature)
	}
}

func TestSignMessageOperation_Keccak256(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	message := hex.EncodeToString([]byte("hello world"))
	op := sign.NewSignMessageOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", message, sign.MessageEncodingHex, sign.HashFunctionKeccak256)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)
}

func TestSignMessageOperation_SHA512(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedEd25519Key(t, ctx, s, "key1")

	message := hex.EncodeToString([]byte("hello world"))
	op := sign.NewSignMessageOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", message, sign.MessageEncodingHex, sign.HashFunctionSHA512)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)
}

func TestSignMessageOperation_SHA3_256(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedP256Key(t, ctx, s, "key1")

	message := hex.EncodeToString([]byte("hello world"))
	op := sign.NewSignMessageOperation().WithStorage(s)
	sigHex, err := op.Execute(ctx, "key1", message, sign.MessageEncodingHex, sign.HashFunctionSHA3256)
	require.NoError(t, err)
	assert.NotEmpty(t, sigHex)
}

func TestSignMessageOperation_UnsupportedHashFunction(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	op := sign.NewSignMessageOperation().WithStorage(s)
	_, err := op.Execute(ctx, "key1", hex.EncodeToString([]byte("hello")), sign.MessageEncodingHex, "md5")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported hash function")
}

// --- SignBatchHashesOperation tests ---

func TestSignBatchHashesOperation_ReturnsInOrder(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	hashes := []string{
		hex.EncodeToString(sha256.New().Sum([]byte("first"))),
		hex.EncodeToString(sha256.New().Sum([]byte("second"))),
		hex.EncodeToString(sha256.New().Sum([]byte("third"))),
	}

	op := sign.NewSignBatchHashesOperation().WithStorage(s)
	signatures, err := op.Execute(ctx, "key1", hashes, sign.MessageEncodingHex)
	require.NoError(t, err)
	assert.Len(t, signatures, len(hashes))
	for i, sig := range signatures {
		assert.NotEmpty(t, sig, "signature at index %d should not be empty", i)
	}
}

func TestSignBatchHashesOperation_EmptyBatch(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	op := sign.NewSignBatchHashesOperation().WithStorage(s)
	signatures, err := op.Execute(ctx, "key1", []string{}, sign.MessageEncodingHex)
	require.NoError(t, err)
	assert.Empty(t, signatures)
}

func TestSignBatchHashesOperation_InvalidHexInBatch(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()
	seedSecp256k1Key(t, ctx, s, "key1")

	hashes := []string{
		hex.EncodeToString(sha256.New().Sum([]byte("valid"))),
		"not-valid-hex!!",
	}

	op := sign.NewSignBatchHashesOperation().WithStorage(s)
	_, err := op.Execute(ctx, "key1", hashes, sign.MessageEncodingHex)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "index 1")
}

func TestSignBatchHashesOperation_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	s := newInMemoryStorage()

	op := sign.NewSignBatchHashesOperation().WithStorage(s)
	_, err := op.Execute(ctx, "nonexistent", []string{hex.EncodeToString(make([]byte, 32))}, sign.MessageEncodingHex)
	assert.Error(t, err)
}
