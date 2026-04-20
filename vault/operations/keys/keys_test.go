package keys_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/keys"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/keys/mocks"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newInMemoryStorage returns a fresh in-memory Vault logical storage backend.
func newInMemoryStorage() logical.Storage {
	return &logical.InmemStorage{}
}

// seedKey creates a key in storage for testing purposes.
func seedKey(t *testing.T, ctx context.Context, storage logical.Storage, id, curve string) *entities.PrivateKey {
	t.Helper()
	key, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, curve, nil)
	require.NoError(t, err)
	return key
}

// TestCreateKeyOperation_HappyPath tests the happy path for creating keys with all supported curves.
func TestCreateKeyOperation_HappyPath(t *testing.T) {
	tests := []struct {
		name    string
		curve   string
		keyType string
	}{
		{
			name:    "secp256k1",
			curve:   crypto.Secp256k1,
			keyType: crypto.KeyTypeEC,
		},
		{
			name:    "ed25519",
			curve:   crypto.Ed25519,
			keyType: crypto.KeyTypeOKP,
		},
		{
			name:    "p256",
			curve:   crypto.P256,
			keyType: crypto.KeyTypeEC,
		},
		{
			name:    "x25519",
			curve:   crypto.X25519,
			keyType: crypto.KeyTypeOKP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			storage := newInMemoryStorage()
			id := "test-key-" + tt.name

			result, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, tt.curve, nil)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, id, result.ID)
			assert.Equal(t, tt.keyType, result.KeyType)
			assert.Equal(t, tt.curve, result.Curve)
			assert.NotEmpty(t, result.PrivateKey)
			assert.NotEmpty(t, result.PublicKey)
			assert.True(t, result.CreatedAt.IsZero() == false, "CreatedAt should not be zero")
			assert.True(t, result.UpdatedAt.IsZero() == false, "UpdatedAt should not be zero")
		})
	}
}

// TestCreateKeyOperation_HappyPathWithMetadata tests creating a key with metadata.
func TestCreateKeyOperation_HappyPathWithMetadata(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "test-key-with-metadata"
	metadata := map[string]string{
		"environment": "test",
		"purpose":     "testing",
	}

	result, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, crypto.Secp256k1, metadata)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, metadata, result.Metadata)
}

// TestCreateKeyOperation_AlreadyExists tests that creating a key with an existing ID returns an error.
func TestCreateKeyOperation_AlreadyExists(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "existing-key"

	// Create the key first
	_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, crypto.Secp256k1, nil)
	require.NoError(t, err)

	// Try to create it again
	_, err = keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, crypto.Secp256k1, nil)
	require.Error(t, err)

	var coreErr *coreErrors.Error
	require.True(t, errors.As(err, &coreErr), "error should be of type *coreErrors.Error")
	assert.Equal(t, uint64(coreErrors.AlreadyExistsCode), coreErr.Code)
	assert.Contains(t, err.Error(), id)
}

// TestCreateKeyOperation_UnsupportedCurve tests that creating a key with an unsupported curve returns an error.
func TestCreateKeyOperation_UnsupportedCurve(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "test-key-unsupported"

	_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, "unsupported-curve", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported curve")
}

// TestCreateKeyOperation_WithMock tests CreateKeyOperation using mocks to verify behavior.
func TestCreateKeyOperation_WithMock(t *testing.T) {
	t.Run("successful creation stores the key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storage := newInMemoryStorage()
		ctx := context.Background()
		id := "mock-test-key"

		// Create the key using real operation to populate storage
		seedKey(t, ctx, storage, id, crypto.Secp256k1)

		// Now verify we can read it back
		readOp := keys.NewReadKeyOperation().WithStorage(storage)
		result, err := readOp.Execute(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, id, result.ID)
	})

	t.Run("storage error is propagated", func(t *testing.T) {
		ctx := context.Background()
		// Use a storage that returns errors on Put
		mockStorage := &mockStorageWithError{
			putErr: errors.New("storage put failed"),
		}

		// First, ensure the key doesn't exist (Get returns nil)
		// Then Put will fail
		_, err := keys.NewCreateKeyOperation().WithStorage(mockStorage).Execute(ctx, "new-key", crypto.Secp256k1, nil)
		require.Error(t, err)
		var coreErr *coreErrors.Error
		require.True(t, errors.As(err, &coreErr), "error should be of type *coreErrors.Error")
		assert.Equal(t, uint64(coreErrors.StorageErrorCode), coreErr.Code)
	})
}

// TestReadKeyOperation_HappyPath tests reading an existing key.
func TestReadKeyOperation_HappyPath(t *testing.T) {
	tests := []struct {
		name  string
		curve string
	}{
		{"secp256k1", crypto.Secp256k1},
		{"ed25519", crypto.Ed25519},
		{"p256", crypto.P256},
		{"x25519", crypto.X25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			storage := newInMemoryStorage()
			id := "read-test-" + tt.name

			// Seed the key
			seedKey(t, ctx, storage, id, tt.curve)

			// Read the key
			readOp := keys.NewReadKeyOperation().WithStorage(storage)
			result, err := readOp.Execute(ctx, id)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, id, result.ID)
			assert.Equal(t, tt.curve, result.Curve)
			assert.NotEmpty(t, result.PrivateKey)
			assert.NotEmpty(t, result.PublicKey)
		})
	}
}

// TestReadKeyOperation_KeyNotFound tests reading a non-existent key.
func TestReadKeyOperation_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()

	readOp := keys.NewReadKeyOperation().WithStorage(storage)
	result, err := readOp.Execute(ctx, "non-existent-key")
	require.Error(t, err)
	require.Nil(t, result)

	var coreErr *coreErrors.Error
	require.True(t, errors.As(err, &coreErr), "error should be of type *coreErrors.Error")
	assert.Equal(t, uint64(coreErrors.StorageEntryNotFoundCode), coreErr.Code)
}

// TestReadKeyOperation_WithMock tests ReadKeyOperation using mocks.
func TestReadKeyOperation_WithMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "mock-read-key"

	// Seed a key
	seedKey(t, ctx, storage, id, crypto.Secp256k1)

	// Verify the mock can be used to intercept calls
	mockReadKey := mocks.NewMockReadKeyOperation(ctrl)

	// Set up expectations
	mockReadKey.EXPECT().
		Execute(gomock.Any(), id).
		Return(nil, coreErrors.EntryNotFoundError("not found"))

	// The mock will return the expected error
	_, err := mockReadKey.Execute(ctx, id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestExistsKeyOperation_HappyPath tests the exists check for existing and non-existing keys.
func TestExistsKeyOperation_HappyPath(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "exists-test-key"

	// Seed a key
	seedKey(t, ctx, storage, id, crypto.Secp256k1)

	// Check if the key exists
	existsOp := keys.NewExistsKeyOperation().WithStorage(storage)
	exists, err := existsOp.Execute(ctx, id)
	require.NoError(t, err)
	assert.True(t, exists)

	// Check for non-existing key
	exists, err = existsOp.Execute(ctx, "non-existent-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestExistsKeyOperation_WithMock tests ExistsKeyOperation using mocks.
func TestExistsKeyOperation_WithMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	mockExistsKey := mocks.NewMockExistsKeyOperation(ctrl)

	// Test exists = true
	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "existing-key").
		Return(true, nil)

	exists, err := mockExistsKey.Execute(ctx, "existing-key")
	require.NoError(t, err)
	assert.True(t, exists)

	// Test exists = false
	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "non-existent-key").
		Return(false, nil)

	exists, err = mockExistsKey.Execute(ctx, "non-existent-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestListKeysOperation_HappyPath tests listing keys.
func TestListKeysOperation_HappyPath(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()

	// Seed multiple keys
	seedKey(t, ctx, storage, "key-1", crypto.Secp256k1)
	seedKey(t, ctx, storage, "key-2", crypto.Ed25519)
	seedKey(t, ctx, storage, "key-3", crypto.P256)

	// List keys
	listOp := keys.NewListKeysOperation().WithStorage(storage)
	keys, err := listOp.Execute(ctx)
	require.NoError(t, err)
	require.NotNil(t, keys)
	assert.Len(t, keys, 3)

	// Verify all keys are present
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}
	assert.True(t, keyMap["key-1"])
	assert.True(t, keyMap["key-2"])
	assert.True(t, keyMap["key-3"])
}

// TestListKeysOperation_EmptyList tests listing when no keys exist.
func TestListKeysOperation_EmptyList(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()

	listOp := keys.NewListKeysOperation().WithStorage(storage)
	keys, err := listOp.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestListKeysOperation_WithMock tests ListKeysOperation using mocks.
func TestListKeysOperation_WithMock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	mockListKeys := mocks.NewMockListKeysOperation(ctrl)

	// Test with some keys
	expectedKeys := []string{"key-1", "key-2"}
	mockListKeys.EXPECT().
		Execute(gomock.Any()).
		Return(expectedKeys, nil)

	keys, err := mockListKeys.Execute(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedKeys, keys)

	// Test with empty list
	mockListKeys.EXPECT().
		Execute(gomock.Any()).
		Return([]string{}, nil)

	keys, err = mockListKeys.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestKeysOperationsInterface tests that the KeysOperations interface works correctly.
func TestKeysOperationsInterface(t *testing.T) {
	ctx := context.Background()

	// Create a mock KeysOperations
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)

	// Set up CreateKey mock
	mockCreateKey := mocks.NewMockCreateKeyOperation(ctrl)
	mockCreateKey.EXPECT().
		Execute(gomock.Any(), "mock-key", crypto.Secp256k1, nil).
		Return(&entities.PrivateKey{
			ID:      "mock-key",
			Curve:   crypto.Secp256k1,
			KeyType: crypto.KeyTypeEC,
		}, nil)

	mockKeysOps.EXPECT().
		CreateKey().
		Return(mockCreateKey)

	// Use the interface
	createdKey := mockKeysOps.CreateKey()
	result, err := createdKey.Execute(ctx, "mock-key", crypto.Secp256k1, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "mock-key", result.ID)
}

// TestWithStorage_CopySemantics tests that WithStorage returns a copy and doesn't mutate the original.
func TestWithStorage_CopySemantics(t *testing.T) {
	t.Run("CreateKeyOperation", func(t *testing.T) {
		storage := newInMemoryStorage()
		storage1 := newInMemoryStorage()

		// Create key in storage1
		_, err := keys.NewCreateKeyOperation().WithStorage(storage1).Execute(context.Background(), "key-1", crypto.Secp256k1, nil)
		require.NoError(t, err)

		// key-1 should NOT exist in storage
		existsOp := keys.NewExistsKeyOperation().WithStorage(storage)
		exists, err := existsOp.Execute(context.Background(), "key-1")
		require.NoError(t, err)
		assert.False(t, exists)

		// key-1 should exist in storage1
		existsOp2 := keys.NewExistsKeyOperation().WithStorage(storage1)
		exists, err = existsOp2.Execute(context.Background(), "key-1")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("ReadKeyOperation", func(t *testing.T) {
		storage1 := newInMemoryStorage()
		storage2 := newInMemoryStorage()

		// Create a key in storage1
		seedKey(t, context.Background(), storage1, "test-key", crypto.Secp256k1)

		// Create read operations with different storages
		readOp1 := keys.NewReadKeyOperation().WithStorage(storage1)
		_ = keys.NewReadKeyOperation().WithStorage(storage2)

		// Read from storage1 should succeed
		result1, err := readOp1.Execute(context.Background(), "test-key")
		require.NoError(t, err)
		require.NotNil(t, result1)

		// Read from storage2 should fail
		result2, err := keys.NewReadKeyOperation().WithStorage(storage2).Execute(context.Background(), "test-key")
		require.Error(t, err)
		assert.Nil(t, result2)
	})

	t.Run("ExistsKeyOperation", func(t *testing.T) {
		storage1 := newInMemoryStorage()
		storage2 := newInMemoryStorage()

		// Create a key in storage1
		seedKey(t, context.Background(), storage1, "test-key", crypto.Secp256k1)

		// Create exists operations with different storages
		existsOp1 := keys.NewExistsKeyOperation().WithStorage(storage1)
		existsOp2 := keys.NewExistsKeyOperation().WithStorage(storage2)

		// Check in storage1
		exists1, err := existsOp1.Execute(context.Background(), "test-key")
		require.NoError(t, err)
		assert.True(t, exists1)

		// Check in storage2
		exists2, err := existsOp2.Execute(context.Background(), "test-key")
		require.NoError(t, err)
		assert.False(t, exists2)
	})

	t.Run("ListKeysOperation", func(t *testing.T) {
		storage1 := newInMemoryStorage()
		storage2 := newInMemoryStorage()

		// Create a key in storage1
		seedKey(t, context.Background(), storage1, "test-key", crypto.Secp256k1)

		// Create list operations with different storages
		listOp1 := keys.NewListKeysOperation().WithStorage(storage1)
		listOp2 := keys.NewListKeysOperation().WithStorage(storage2)

		// List from storage1
		keys1, err := listOp1.Execute(context.Background())
		require.NoError(t, err)
		assert.Len(t, keys1, 1)

		// List from storage2
		keys2, err := listOp2.Execute(context.Background())
		require.NoError(t, err)
		assert.Empty(t, keys2)
	})
}

// TestIntegration_CreateReadExistsList tests the full CRUD flow for keys.
func TestIntegration_CreateReadExistsList(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()

	// 1. Create keys
	createdKeys := make([]*entities.PrivateKey, 0, 3)
	curves := []string{crypto.Secp256k1, crypto.Ed25519, crypto.P256}

	for i, curve := range curves {
		id := "integration-key-" + string(rune('a'+i))
		key, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, curve, nil)
		require.NoError(t, err)
		require.NotNil(t, key)
		createdKeys = append(createdKeys, key)
	}

	// 2. Verify all keys exist
	existsOp := keys.NewExistsKeyOperation().WithStorage(storage)
	for _, key := range createdKeys {
		exists, err := existsOp.Execute(ctx, key.ID)
		require.NoError(t, err)
		assert.True(t, exists, "key %s should exist", key.ID)
	}

	// 3. Read all keys and verify
	readOp := keys.NewReadKeyOperation().WithStorage(storage)
	for _, expectedKey := range createdKeys {
		readKey, err := readOp.Execute(ctx, expectedKey.ID)
		require.NoError(t, err)
		require.NotNil(t, readKey)

		assert.Equal(t, expectedKey.ID, readKey.ID)
		assert.Equal(t, expectedKey.Curve, readKey.Curve)
		assert.Equal(t, expectedKey.KeyType, readKey.KeyType)
		assert.Equal(t, expectedKey.PublicKey, readKey.PublicKey)
		assert.Equal(t, expectedKey.PrivateKey, readKey.PrivateKey)
	}

	// 4. List all keys
	listOp := keys.NewListKeysOperation().WithStorage(storage)
	listedKeys, err := listOp.Execute(ctx)
	require.NoError(t, err)
	assert.Len(t, listedKeys, len(createdKeys))

	// Verify all created keys are in the list
	keyMap := make(map[string]bool)
	for _, key := range createdKeys {
		keyMap[key.ID] = true
	}
	for _, listedKey := range listedKeys {
		assert.True(t, keyMap[listedKey], "listed key %s should be in created keys", listedKey)
	}
}

// TestIntegration_KeyCreationPreservesData tests that key data is preserved correctly.
func TestIntegration_KeyCreationPreservesData(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "data-preservation-key"
	metadata := map[string]string{
		"owner":      "test-user",
		"department": "engineering",
	}

	// Create key with metadata
	createdKey, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, crypto.Secp256k1, metadata)
	require.NoError(t, err)
	require.NotNil(t, createdKey)

	// Read it back
	readOp := keys.NewReadKeyOperation().WithStorage(storage)
	readKey, err := readOp.Execute(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, readKey)

	// Verify all fields match
	assert.Equal(t, createdKey.ID, readKey.ID)
	assert.Equal(t, createdKey.Curve, readKey.Curve)
	assert.Equal(t, createdKey.KeyType, readKey.KeyType)
	assert.Equal(t, createdKey.PrivateKey, readKey.PrivateKey)
	assert.Equal(t, createdKey.PublicKey, readKey.PublicKey)
	assert.Equal(t, createdKey.Metadata, readKey.Metadata)
	assert.True(t, createdKey.CreatedAt.Equal(readKey.CreatedAt))
	assert.True(t, createdKey.UpdatedAt.Equal(readKey.UpdatedAt))
}

// TestStorageKeyBuilding tests that storage keys are built correctly.
func TestStorageKeyBuilding(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "simple id",
			id:       "key-1",
			expected: "private-keys/key-1",
		},
		{
			name:     "uuid id",
			id:       "550e8400-e29b-41d4-a716-446655440000",
			expected: "private-keys/550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "empty id",
			id:       "",
			expected: "private-keys/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := storage.PrivateKeysStorageKey(tt.id)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// TestErrorHandling tests error handling for various scenarios.
func TestErrorHandling(t *testing.T) {
	t.Run("create key with empty id", func(t *testing.T) {
		ctx := context.Background()
		storage := newInMemoryStorage()

		_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, "", crypto.Secp256k1, nil)
		// This should succeed but create a key with empty ID
		require.NoError(t, err)

		// Verify the key was created
		existsOp := keys.NewExistsKeyOperation().WithStorage(storage)
		exists, err := existsOp.Execute(ctx, "")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("read key with empty id", func(t *testing.T) {
		ctx := context.Background()
		storage := newInMemoryStorage()

		// First create a key with empty ID
		_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, "", crypto.Secp256k1, nil)
		require.NoError(t, err)

		// Then read it
		readOp := keys.NewReadKeyOperation().WithStorage(storage)
		result, err := readOp.Execute(ctx, "")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.ID)
	})

	t.Run("exists key with empty id", func(t *testing.T) {
		ctx := context.Background()
		storage := newInMemoryStorage()

		existsOp := keys.NewExistsKeyOperation().WithStorage(storage)
		exists, err := existsOp.Execute(ctx, "")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// mockStorageWithError is a mock storage that returns errors on Put.
type mockStorageWithError struct {
	logical.InmemStorage
	putErr error
}

func (m *mockStorageWithError) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if m.putErr != nil {
		return m.putErr
	}
	return m.InmemStorage.Put(ctx, entry)
}

// TestCreateKeyOperation_StorageError tests that storage errors are properly handled.
func TestCreateKeyOperation_StorageError(t *testing.T) {
	ctx := context.Background()
	mockStorage := &mockStorageWithError{
		putErr: errors.New("simulated storage error"),
	}

	_, err := keys.NewCreateKeyOperation().WithStorage(mockStorage).Execute(ctx, "test-key", crypto.Secp256k1, nil)
	require.Error(t, err)
	var coreErr *coreErrors.Error
	require.True(t, errors.As(err, &coreErr), "error should be of type *coreErrors.Error")
	assert.Equal(t, uint64(coreErrors.StorageErrorCode), coreErr.Code)
}

// TestMockKeysOperations_CreateKey tests the MockKeysOperations interface.
func TestMockKeysOperations_CreateKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockCreateKey := mocks.NewMockCreateKeyOperation(ctrl)

	// Set up expectations
	mockCreateKey.EXPECT().
		Execute(gomock.Any(), "test-id", crypto.Secp256k1, gomock.Any()).
		Return(&entities.PrivateKey{
			ID:        "test-id",
			Curve:     crypto.Secp256k1,
			KeyType:   crypto.KeyTypeEC,
			PublicKey: "test-public-key",
		}, nil)

	mockKeysOps.EXPECT().
		CreateKey().
		Return(mockCreateKey)

	// Execute through the interface
	createdKey := mockKeysOps.CreateKey()
	result, err := createdKey.Execute(context.Background(), "test-id", crypto.Secp256k1, map[string]string{"key": "value"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "test-public-key", result.PublicKey)
}

// TestMockKeysOperations_CreateKeyWithStorage tests the MockKeysOperations interface
// when WithStorage is called through the mock chain.
func TestMockKeysOperations_CreateKeyWithStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockCreateKey := mocks.NewMockCreateKeyOperation(ctrl)
	mockStorage := newInMemoryStorage()

	// Set up expectations for the full chain
	mockKeysOps.EXPECT().
		CreateKey().
		Return(mockCreateKey)

	mockCreateKey.EXPECT().
		WithStorage(gomock.Any()).
		Return(mockCreateKey)

	mockCreateKey.EXPECT().
		Execute(gomock.Any(), "test-id", crypto.Secp256k1, gomock.Any()).
		Return(&entities.PrivateKey{
			ID:        "test-id",
			Curve:     crypto.Secp256k1,
			KeyType:   crypto.KeyTypeEC,
			PublicKey: "test-public-key",
		}, nil)

	// Execute through the interface with WithStorage
	createdKey := mockKeysOps.CreateKey()
	result, err := createdKey.WithStorage(mockStorage).Execute(context.Background(), "test-id", crypto.Secp256k1, map[string]string{"key": "value"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "test-public-key", result.PublicKey)
}

// TestMockKeysOperations_ReadKey tests the MockKeysOperations interface for ReadKey.
func TestMockKeysOperations_ReadKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockReadKey := mocks.NewMockReadKeyOperation(ctrl)

	// Set up expectations
	mockReadKey.EXPECT().
		Execute(gomock.Any(), "test-id").
		Return(&entities.PrivateKey{
			ID:      "test-id",
			Curve:   crypto.Ed25519,
			KeyType: crypto.KeyTypeOKP,
		}, nil)

	mockKeysOps.EXPECT().
		ReadKey().
		Return(mockReadKey)

	// Execute through the interface
	readKey := mockKeysOps.ReadKey()
	result, err := readKey.Execute(context.Background(), "test-id")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, crypto.Ed25519, result.Curve)
}

// TestMockKeysOperations_ReadKeyWithStorage tests the MockKeysOperations interface
// when WithStorage is called through the mock chain.
func TestMockKeysOperations_ReadKeyWithStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockReadKey := mocks.NewMockReadKeyOperation(ctrl)
	mockStorage := newInMemoryStorage()

	// Set up expectations for the full chain
	mockKeysOps.EXPECT().
		ReadKey().
		Return(mockReadKey)

	mockReadKey.EXPECT().
		WithStorage(gomock.Any()).
		Return(mockReadKey)

	mockReadKey.EXPECT().
		Execute(gomock.Any(), "test-id").
		Return(&entities.PrivateKey{
			ID:      "test-id",
			Curve:   crypto.Ed25519,
			KeyType: crypto.KeyTypeOKP,
		}, nil)

	// Execute through the interface with WithStorage
	readKey := mockKeysOps.ReadKey()
	result, err := readKey.WithStorage(mockStorage).Execute(context.Background(), "test-id")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, crypto.Ed25519, result.Curve)
}

// TestMockKeysOperations_ExistsKey tests the MockKeysOperations interface for ExistsKey.
func TestMockKeysOperations_ExistsKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockExistsKey := mocks.NewMockExistsKeyOperation(ctrl)

	// Set up expectations
	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "existing-key").
		Return(true, nil)

	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "non-existent-key").
		Return(false, nil)

	mockKeysOps.EXPECT().
		ExistsKey().
		Return(mockExistsKey)

	// Execute through the interface
	existsKey := mockKeysOps.ExistsKey()

	exists, err := existsKey.Execute(context.Background(), "existing-key")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = existsKey.Execute(context.Background(), "non-existent-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestMockKeysOperations_ExistsKeyWithStorage tests the MockKeysOperations interface
// when WithStorage is called through the mock chain.
func TestMockKeysOperations_ExistsKeyWithStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockExistsKey := mocks.NewMockExistsKeyOperation(ctrl)
	mockStorage := newInMemoryStorage()

	// Set up expectations for the full chain
	mockKeysOps.EXPECT().
		ExistsKey().
		Return(mockExistsKey)

	// WithStorage may be called multiple times (once per Execute call), so use AnyTimes
	mockExistsKey.EXPECT().
		WithStorage(gomock.Any()).
		Return(mockExistsKey).
		Times(2)

	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "existing-key").
		Return(true, nil)

	mockExistsKey.EXPECT().
		Execute(gomock.Any(), "non-existent-key").
		Return(false, nil)

	// Execute through the interface with WithStorage
	existsKey := mockKeysOps.ExistsKey()

	exists, err := existsKey.WithStorage(mockStorage).Execute(context.Background(), "existing-key")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = existsKey.WithStorage(mockStorage).Execute(context.Background(), "non-existent-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestMockKeysOperations_ListKeys tests the MockKeysOperations interface for ListKeys.
func TestMockKeysOperations_ListKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockListKeys := mocks.NewMockListKeysOperation(ctrl)

	// Set up expectations
	expectedKeys := []string{"key-1", "key-2", "key-3"}
	mockListKeys.EXPECT().
		Execute(gomock.Any()).
		Return(expectedKeys, nil)

	mockKeysOps.EXPECT().
		ListKeys().
		Return(mockListKeys)

	// Execute through the interface
	listKeys := mockKeysOps.ListKeys()
	keys, err := listKeys.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expectedKeys, keys)
}

// TestMockKeysOperations_ListKeysWithStorage tests the MockKeysOperations interface
// when WithStorage is called through the mock chain.
func TestMockKeysOperations_ListKeysWithStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockKeysOps := mocks.NewMockKeysOperations(ctrl)
	mockListKeys := mocks.NewMockListKeysOperation(ctrl)
	mockStorage := newInMemoryStorage()

	// Set up expectations for the full chain
	mockKeysOps.EXPECT().
		ListKeys().
		Return(mockListKeys)

	mockListKeys.EXPECT().
		WithStorage(gomock.Any()).
		Return(mockListKeys)

	expectedKeys := []string{"key-1", "key-2", "key-3"}
	mockListKeys.EXPECT().
		Execute(gomock.Any()).
		Return(expectedKeys, nil)

	// Execute through the interface with WithStorage
	listKeys := mockKeysOps.ListKeys()
	keys, err := listKeys.WithStorage(mockStorage).Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expectedKeys, keys)
}

// TestAllCurves_CreateAndRead tests creating and reading keys for all supported curves.
func TestAllCurves_CreateAndRead(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()

	curves := map[string]string{
		crypto.Secp256k1: crypto.KeyTypeEC,
		crypto.Ed25519:   crypto.KeyTypeOKP,
		crypto.P256:      crypto.KeyTypeEC,
		crypto.X25519:    crypto.KeyTypeOKP,
	}

	for curve, expectedKeyType := range curves {
		t.Run(curve, func(t *testing.T) {
			keyID := "key-" + curve

			// Create key
			createdKey, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, keyID, curve, nil)
			require.NoError(t, err)
			require.NotNil(t, createdKey)
			assert.Equal(t, keyID, createdKey.ID)
			assert.Equal(t, curve, createdKey.Curve)
			assert.Equal(t, expectedKeyType, createdKey.KeyType)
			assert.NotEmpty(t, createdKey.PrivateKey)
			assert.NotEmpty(t, createdKey.PublicKey)

			// Read key
			readKey, err := keys.NewReadKeyOperation().WithStorage(storage).Execute(ctx, keyID)
			require.NoError(t, err)
			require.NotNil(t, readKey)
			assert.Equal(t, createdKey.ID, readKey.ID)
			assert.Equal(t, createdKey.Curve, readKey.Curve)
			assert.Equal(t, createdKey.KeyType, readKey.KeyType)
			assert.Equal(t, createdKey.PrivateKey, readKey.PrivateKey)
			assert.Equal(t, createdKey.PublicKey, readKey.PublicKey)
		})
	}
}

// TestConcurrentKeyCreation tests that keys can be created concurrently without conflicts.
func TestConcurrentKeyCreation(t *testing.T) {
	t.Run("Concurrent key creation", func(t *testing.T) {
		t.Skip("Skipping concurrent test - InmemStorage may not support concurrent access")

		ctx := context.Background()
		storage := newInMemoryStorage()
		numKeys := 10

		done := make(chan bool, numKeys)
		for i := 0; i < numKeys; i++ {
			go func(idx int) {
				keyID := fmt.Sprintf("concurrent-key-%d", idx)
				_, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, keyID, crypto.Secp256k1, nil)
				if err != nil {
					t.Errorf("failed to create key %s: %v", keyID, err)
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numKeys; i++ {
			<-done
		}

		// Verify all keys were created
		listOp := keys.NewListKeysOperation().WithStorage(storage)
		keyList, err := listOp.Execute(ctx)
		require.NoError(t, err)
		assert.Len(t, keyList, numKeys)
	})
}

// TestMetadataPreservation tests that metadata is correctly preserved.
func TestMetadataPreservation(t *testing.T) {
	ctx := context.Background()
	storage := newInMemoryStorage()
	id := "metadata-test-key"

	metadata := map[string]string{
		"environment": "production",
		"region":      "us-west-2",
		"team":        "security",
		"cost-center": "12345",
		"project":     "blockchain-signer",
	}

	// Create key with metadata
	createdKey, err := keys.NewCreateKeyOperation().WithStorage(storage).Execute(ctx, id, crypto.Secp256k1, metadata)
	require.NoError(t, err)
	require.NotNil(t, createdKey)

	// Verify metadata was set
	assert.Equal(t, metadata, createdKey.Metadata)

	// Read key back
	readKey, err := keys.NewReadKeyOperation().WithStorage(storage).Execute(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, readKey)

	// Verify metadata is preserved
	assert.Equal(t, metadata, readKey.Metadata)
	assert.Len(t, readKey.Metadata, len(metadata))

	// Verify each key-value pair
	for k, v := range metadata {
		assert.Equal(t, v, readKey.Metadata[k], "metadata key %s should match", k)
	}
}
