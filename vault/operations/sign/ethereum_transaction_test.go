package sign_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/erc4337"
	sign "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignEthereumTransactionOperation_Legacy(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	privateKeyHex := seedSecp256k1Key(t, ctx, storage, "key1")

	signed := signEthereumTransaction(t, ctx, storage, sign.EthereumTransaction{
		Type:     sign.EthereumLegacyTransaction,
		Nonce:    "0x7",
		To:       "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value:    "0xde0b6b3a7640000",
		GasLimit: "0x5208",
		GasPrice: "0x4a817c800",
		ChainID:  "0x1",
	})

	transaction := decodeSignedEthereumTransaction(t, signed.RawTransaction)
	assert.Equal(t, uint8(types.LegacyTxType), transaction.Type())
	assert.Equal(t, uint64(7), transaction.Nonce())
	assert.Equal(t, "1000000000000000000", transaction.Value().String())
	assert.Equal(t, signed.TransactionHash, transaction.Hash().Hex())
	assertSignedBy(t, transaction, privateKeyHex)
}

func TestSignEthereumTransactionOperation_EIP1559(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	privateKeyHex := seedSecp256k1Key(t, ctx, storage, "key1")

	signed := signEthereumTransaction(t, ctx, storage, sign.EthereumTransaction{
		Type:                 sign.EthereumEIP1559Transaction,
		Nonce:                "0x7",
		To:                   "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value:                "0xde0b6b3a7640000",
		GasLimit:             "0x5208",
		MaxPriorityFeePerGas: "0x3b9aca00",
		MaxFeePerGas:         "0x4a817c800",
		ChainID:              "0x1",
		Data:                 "0xdeadbeef",
	})

	transaction := decodeSignedEthereumTransaction(t, signed.RawTransaction)
	assert.Equal(t, uint8(types.DynamicFeeTxType), transaction.Type())
	assert.Equal(t, "1000000000", transaction.GasTipCap().String())
	assert.Equal(t, "20000000000", transaction.GasFeeCap().String())
	assert.Equal(t, "deadbeef", hex.EncodeToString(transaction.Data()))
	assertSignedBy(t, transaction, privateKeyHex)
}

func TestSignEthereumTransactionOperation_KeyNotFound(t *testing.T) {
	_, err := sign.NewSignEthereumTransactionOperation().WithStorage(&logical.InmemStorage{}).Execute(context.Background(), "missing", validLegacyTransaction())
	require.Error(t, err)
}

func TestSignEthereumTransactionOperation_InvalidEIP1559Fees(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	seedSecp256k1Key(t, ctx, storage, "key1")

	transaction := validLegacyTransaction()
	transaction.Type = sign.EthereumEIP1559Transaction
	transaction.MaxPriorityFeePerGas = "0x4a817c800"
	transaction.MaxFeePerGas = "0x3b9aca00"

	_, err := sign.NewSignEthereumTransactionOperation().WithStorage(storage).Execute(ctx, "key1", transaction)
	require.ErrorAs(t, err, new(*sign.InvalidEthereumTransactionError))
	assert.Contains(t, err.Error(), "maxFeePerGas")
}

func TestSignEthereumTransactionOperation_RejectsDecimalQuantity(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	seedSecp256k1Key(t, ctx, storage, "key1")

	transaction := validLegacyTransaction()
	transaction.GasLimit = "21000"

	_, err := sign.NewSignEthereumTransactionOperation().WithStorage(storage).Execute(ctx, "key1", transaction)
	require.ErrorAs(t, err, new(*sign.InvalidEthereumTransactionError))
	assert.Contains(t, err.Error(), "gas")
}

func TestSignEthereumTypedDataOperation(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	privateKeyHex := seedSecp256k1Key(t, ctx, storage, "key1")

	signature, err := sign.NewSignEthereumTypedDataOperation().WithStorage(storage).Execute(ctx, "key1", standardTypedData(t))
	require.NoError(t, err)

	signatureBytes := common.FromHex(signature)
	require.Len(t, signatureBytes, 65)
	assert.Contains(t, []byte{27, 28}, signatureBytes[64])

	digest, _, err := apitypes.TypedDataAndHash(standardTypedData(t))
	require.NoError(t, err)
	signatureBytes[64] -= 27
	publicKey, err := ethereumCrypto.SigToPub(digest, signatureBytes)
	require.NoError(t, err)

	privateKey, err := ethereumCrypto.HexToECDSA(privateKeyHex)
	require.NoError(t, err)
	assert.Equal(t, ethereumCrypto.PubkeyToAddress(privateKey.PublicKey), ethereumCrypto.PubkeyToAddress(*publicKey))
}

func TestSignEthereumTypedDataOperation_KeyNotFound(t *testing.T) {
	_, err := sign.NewSignEthereumTypedDataOperation().WithStorage(&logical.InmemStorage{}).Execute(context.Background(), "missing", standardTypedData(t))
	require.Error(t, err)
}

func TestSignEthereumTypedDataOperation_InvalidTypedData(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	seedSecp256k1Key(t, ctx, storage, "key1")

	typedData := standardTypedData(t)
	typedData.PrimaryType = "Unknown"
	_, err := sign.NewSignEthereumTypedDataOperation().WithStorage(storage).Execute(ctx, "key1", typedData)
	require.ErrorAs(t, err, new(*sign.InvalidEthereumTypedDataError))
}

func TestSignEthereumUserOperationOperation(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	privateKeyHex := seedSecp256k1Key(t, ctx, storage, "key1")
	request := validUserOperation(t)
	entryPoint := "0x0000000071727De22E5E9d8bAF0edAc6f37da032"

	for _, version := range []sign.EntryPointVersion{
		sign.EntryPointVersion07,
		sign.EntryPointVersion08,
		sign.EntryPointVersion09,
	} {
		t.Run(string(version), func(t *testing.T) {
			signature, err := sign.NewSignEthereumUserOperationOperation().WithStorage(storage).Execute(ctx, "key1", request, entryPoint, version, "0x1")
			require.NoError(t, err)

			userOperation, err := request.ToUserOperation()
			require.NoError(t, err)
			chainID := big.NewInt(1)
			var digest common.Hash
			switch version {
			case sign.EntryPointVersion07:
				digest, err = erc4337.HashUserOperationV07(userOperation, common.HexToAddress(entryPoint), chainID)
			case sign.EntryPointVersion08:
				digest, err = erc4337.HashUserOperationV08(userOperation, common.HexToAddress(entryPoint), chainID)
			case sign.EntryPointVersion09:
				digest, err = erc4337.HashUserOperationV09(userOperation, common.HexToAddress(entryPoint), chainID)
			}
			require.NoError(t, err)

			signatureBytes := common.FromHex(signature)
			require.Len(t, signatureBytes, 65)
			signatureBytes[64] -= 27
			publicKey, err := ethereumCrypto.SigToPub(digest.Bytes(), signatureBytes)
			require.NoError(t, err)

			privateKey, err := ethereumCrypto.HexToECDSA(privateKeyHex)
			require.NoError(t, err)
			assert.Equal(t, ethereumCrypto.PubkeyToAddress(privateKey.PublicKey), ethereumCrypto.PubkeyToAddress(*publicKey))
		})
	}
}

func TestSignEthereumUserOperationOperation_UnsupportedEntryPointVersion(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	seedSecp256k1Key(t, ctx, storage, "key1")

	_, err := sign.NewSignEthereumUserOperationOperation().WithStorage(storage).Execute(
		ctx,
		"key1",
		validUserOperation(t),
		"0x0000000071727De22E5E9d8bAF0edAc6f37da032",
		"1.0",
		"0x1",
	)
	require.ErrorAs(t, err, new(*sign.InvalidEthereumUserOperationError))
	assert.Contains(t, err.Error(), "unsupported EntryPoint version")
}

func validLegacyTransaction() sign.EthereumTransaction {
	return sign.EthereumTransaction{
		Type:     sign.EthereumLegacyTransaction,
		Nonce:    "0x0",
		To:       "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value:    "0x0",
		GasLimit: "0x5208",
		GasPrice: "0x4a817c800",
		ChainID:  "0x1",
	}
}

func validUserOperation(t *testing.T) erc4337.RequestUserOperation {
	t.Helper()

	var request erc4337.RequestUserOperation
	require.NoError(t, json.Unmarshal([]byte(`{
		"sender": "0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD",
		"nonce": "0x7",
		"callData": "0xcafebabe",
		"callGasLimit": "0x249f0",
		"verificationGasLimit": "0x186a0",
		"preVerificationGas": "0xc350",
		"maxPriorityFeePerGas": "0x64",
		"maxFeePerGas": "0x3e8"
	}`), &request))
	return request
}

func signEthereumTransaction(t *testing.T, ctx context.Context, storage logical.Storage, transaction sign.EthereumTransaction) *sign.SignedEthereumTransaction {
	t.Helper()
	signed, err := sign.NewSignEthereumTransactionOperation().WithStorage(storage).Execute(ctx, "key1", transaction)
	require.NoError(t, err)
	return signed
}

func decodeSignedEthereumTransaction(t *testing.T, raw string) *types.Transaction {
	t.Helper()
	bytes := common.FromHex(raw)
	transaction := new(types.Transaction)
	require.NoError(t, transaction.UnmarshalBinary(bytes))
	return transaction
}

func assertSignedBy(t *testing.T, transaction *types.Transaction, privateKeyHex string) {
	t.Helper()
	privateKey, err := ethereumCrypto.HexToECDSA(privateKeyHex)
	require.NoError(t, err)

	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), transaction)
	require.NoError(t, err)
	assert.Equal(t, ethereumCrypto.PubkeyToAddress(privateKey.PublicKey), from)
}

func standardTypedData(t *testing.T) apitypes.TypedData {
	t.Helper()

	var typedData apitypes.TypedData
	require.NoError(t, json.Unmarshal([]byte(`{
		"types": {
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"Person": [
				{"name": "name", "type": "string"},
				{"name": "wallet", "type": "address"}
			],
			"Mail": [
				{"name": "from", "type": "Person"},
				{"name": "to", "type": "Person"},
				{"name": "contents", "type": "string"}
			]
		},
		"primaryType": "Mail",
		"domain": {
			"name": "Ether Mail",
			"version": "1",
			"chainId": 1,
			"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
		},
		"message": {
			"from": {
				"name": "Cow",
				"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
			},
			"to": {
				"name": "Bob",
				"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
			},
			"contents": "Hello, Bob!"
		}
	}`), &typedData))
	return typedData
}
