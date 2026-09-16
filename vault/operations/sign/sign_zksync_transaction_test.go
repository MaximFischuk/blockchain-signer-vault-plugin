package sign_test

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	sign "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignZkSyncTransactionOperation(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	privateKeyHex := seedSecp256k1Key(t, ctx, storage, "key1")
	transaction := validZkSyncEIP712Transaction()

	signature, err := sign.NewSignZkSyncTransactionOperation().WithStorage(storage).Execute(ctx, "key1", transaction)
	require.NoError(t, err)

	signatureBytes := common.FromHex(signature)
	require.Len(t, signatureBytes, 65)
	signatureBytes[64] -= 27
	publicKey, err := ethereumCrypto.SigToPub(expectedZkSyncEIP712Digest(t, transaction).Bytes(), signatureBytes)
	require.NoError(t, err)

	privateKey, err := ethereumCrypto.HexToECDSA(privateKeyHex)
	require.NoError(t, err)
	assert.Equal(t, ethereumCrypto.PubkeyToAddress(privateKey.PublicKey), ethereumCrypto.PubkeyToAddress(*publicKey))
}

func TestSignZkSyncTransactionOperation_KeyNotFound(t *testing.T) {
	_, err := sign.NewSignZkSyncTransactionOperation().WithStorage(&logical.InmemStorage{}).Execute(context.Background(), "missing", validZkSyncEIP712Transaction())
	require.Error(t, err)
}

func TestSignZkSyncTransactionOperation_InvalidFactoryDependency(t *testing.T) {
	ctx := context.Background()
	storage := logical.Storage(&logical.InmemStorage{})
	seedSecp256k1Key(t, ctx, storage, "key1")
	transaction := validZkSyncEIP712Transaction()
	transaction.FactoryDeps = []string{"0x1234"}

	_, err := sign.NewSignZkSyncTransactionOperation().WithStorage(storage).Execute(ctx, "key1", transaction)
	require.ErrorAs(t, err, new(*sign.InvalidZkSyncTransactionError))
}

func validZkSyncEIP712Transaction() sign.ZkSyncEIP712Transaction {
	return sign.ZkSyncEIP712Transaction{
		From:                   "0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD",
		To:                     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		GasLimit:               "0x249f0",
		GasPerPubdataByteLimit: "0xc350",
		MaxFeePerGas:           "0x3e8",
		MaxPriorityFeePerGas:   "0x64",
		Nonce:                  "0x7",
		Value:                  "0x0",
		Data:                   "0xcafebabe",
		FactoryDeps:            []string{"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		PaymasterInput:         "0xdeadbeef",
		ChainID:                "0x144",
	}
}

func expectedZkSyncEIP712Digest(t *testing.T, transaction sign.ZkSyncEIP712Transaction) common.Hash {
	t.Helper()
	transactionHash := ethereumCrypto.Keccak256Hash(bytes.Join([][]byte{
		ethereumCrypto.Keccak256([]byte("Transaction(uint256 txType,uint256 from,uint256 to,uint256 gasLimit,uint256 gasPerPubdataByteLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 paymaster,uint256 nonce,uint256 value,bytes data,bytes32[] factoryDeps,bytes paymasterInput)")),
		zkSyncUint256Word(t, "0x71"),
		zkSyncAddressWord(t, transaction.From),
		zkSyncAddressWord(t, transaction.To),
		zkSyncUint256Word(t, transaction.GasLimit),
		zkSyncUint256Word(t, transaction.GasPerPubdataByteLimit),
		zkSyncUint256Word(t, transaction.MaxFeePerGas),
		zkSyncUint256Word(t, transaction.MaxPriorityFeePerGas),
		make([]byte, common.HashLength),
		zkSyncUint256Word(t, transaction.Nonce),
		zkSyncUint256Word(t, transaction.Value),
		ethereumCrypto.Keccak256(common.FromHex(transaction.Data)),
		ethereumCrypto.Keccak256(common.FromHex(transaction.FactoryDeps[0])),
		ethereumCrypto.Keccak256(common.FromHex(transaction.PaymasterInput)),
	}, nil))
	domainHash := ethereumCrypto.Keccak256Hash(bytes.Join([][]byte{
		ethereumCrypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId)")),
		ethereumCrypto.Keccak256([]byte("zkSync")),
		ethereumCrypto.Keccak256([]byte("2")),
		zkSyncUint256Word(t, transaction.ChainID),
	}, nil))
	return ethereumCrypto.Keccak256Hash([]byte{0x19, 0x01}, domainHash.Bytes(), transactionHash.Bytes())
}

func zkSyncUint256Word(t *testing.T, value string) []byte {
	t.Helper()
	quantity, ok := new(big.Int).SetString(value, 0)
	require.True(t, ok)
	return common.LeftPadBytes(quantity.Bytes(), common.HashLength)
}

func zkSyncAddressWord(t *testing.T, value string) []byte {
	t.Helper()
	require.True(t, common.IsHexAddress(value))
	return common.LeftPadBytes(common.HexToAddress(value).Bytes(), common.HashLength)
}
