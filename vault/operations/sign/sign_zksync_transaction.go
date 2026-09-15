package sign

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
)

const zkSyncEIP712TransactionType = "Transaction(uint256 txType,uint256 from,uint256 to,uint256 gasLimit,uint256 gasPerPubdataByteLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 paymaster,uint256 nonce,uint256 value,bytes data,bytes32[] factoryDeps,bytes paymasterInput)"

// ZkSyncEIP712Transaction contains the caller-provided fields of a zkSync EIP-712 transaction.
// Quantities use JSON-RPC hexadecimal encoding.
type ZkSyncEIP712Transaction struct {
	From                   string
	To                     string
	GasLimit               string
	GasPerPubdataByteLimit string
	MaxFeePerGas           string
	MaxPriorityFeePerGas   string
	Paymaster              string
	Nonce                  string
	Value                  string
	Data                   string
	FactoryDeps            []string
	PaymasterInput         string
	ChainID                string
}

type InvalidZkSyncTransactionError struct {
	message string
}

func (e *InvalidZkSyncTransactionError) Error() string {
	return e.message
}

type SignZkSyncTransactionOperation interface {
	Execute(ctx context.Context, id string, transaction ZkSyncEIP712Transaction) (string, error)
	WithStorage(storage logical.Storage) SignZkSyncTransactionOperation
}

type signZkSyncTransactionOperation struct {
	storage logical.Storage
}

func NewSignZkSyncTransactionOperation() SignZkSyncTransactionOperation {
	return &signZkSyncTransactionOperation{}
}

func (o signZkSyncTransactionOperation) WithStorage(s logical.Storage) SignZkSyncTransactionOperation {
	o.storage = s
	return &o
}

func (o *signZkSyncTransactionOperation) Execute(ctx context.Context, id string, transaction ZkSyncEIP712Transaction) (string, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}
	if key.Curve != crypto.Secp256k1 {
		return "", &InvalidZkSyncTransactionError{message: fmt.Sprintf("zkSync EIP-712 transactions require a secp256k1 key, got %q", key.Curve)}
	}

	digest, err := hashZkSyncEIP712Transaction(transaction)
	if err != nil {
		return "", err
	}
	privateKey, err := ethereumCrypto.HexToECDSA(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode secp256k1 private key: %w", err)
	}
	signature, err := ethereumCrypto.Sign(digest.Bytes(), privateKey)
	if err != nil {
		return "", fmt.Errorf("sign zkSync EIP-712 transaction: %w", err)
	}
	signature[64] += 27

	return hexutil.Encode(signature), nil
}

func hashZkSyncEIP712Transaction(transaction ZkSyncEIP712Transaction) (common.Hash, error) {
	chainID, err := parseZkSyncQuantity("chainId", transaction.ChainID, false)
	if err != nil {
		return common.Hash{}, err
	}
	from, err := parseZkSyncAddress("from", transaction.From, false)
	if err != nil {
		return common.Hash{}, err
	}
	to, err := parseZkSyncAddress("to", transaction.To, false)
	if err != nil {
		return common.Hash{}, err
	}
	gasLimit, err := parseZkSyncQuantity("gas", transaction.GasLimit, false)
	if err != nil {
		return common.Hash{}, err
	}
	gasPerPubdataByteLimit, err := parseZkSyncQuantity("gasPerPubdataByteLimit", transaction.GasPerPubdataByteLimit, false)
	if err != nil {
		return common.Hash{}, err
	}
	maxFeePerGas, err := parseZkSyncQuantity("maxFeePerGas", transaction.MaxFeePerGas, false)
	if err != nil {
		return common.Hash{}, err
	}
	maxPriorityFeePerGas, err := parseZkSyncQuantity("maxPriorityFeePerGas", transaction.MaxPriorityFeePerGas, false)
	if err != nil {
		return common.Hash{}, err
	}
	paymaster, err := parseZkSyncAddress("paymaster", transaction.Paymaster, true)
	if err != nil {
		return common.Hash{}, err
	}
	nonce, err := parseZkSyncQuantity("nonce", transaction.Nonce, false)
	if err != nil {
		return common.Hash{}, err
	}
	value, err := parseZkSyncQuantity("value", transaction.Value, true)
	if err != nil {
		return common.Hash{}, err
	}
	data, err := parseZkSyncBytes("data", transaction.Data)
	if err != nil {
		return common.Hash{}, err
	}
	factoryDepsHash, err := hashZkSyncFactoryDeps(transaction.FactoryDeps)
	if err != nil {
		return common.Hash{}, err
	}
	paymasterInput, err := parseZkSyncBytes("paymasterInput", transaction.PaymasterInput)
	if err != nil {
		return common.Hash{}, err
	}

	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("create uint256 ABI type: %w", err)
	}
	bytes32Type, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return common.Hash{}, fmt.Errorf("create bytes32 ABI type: %w", err)
	}

	// Manual implementation of EIP-712 encoding to reduce redundant steps of go-ethereum's one due to static transaction structure.
	transactionArguments := abi.Arguments{
		{Type: bytes32Type},
		{Type: uint256Type}, {Type: uint256Type}, {Type: uint256Type}, {Type: uint256Type},
		{Type: uint256Type}, {Type: uint256Type}, {Type: uint256Type}, {Type: uint256Type},
		{Type: uint256Type}, {Type: uint256Type},
		{Type: bytes32Type}, {Type: bytes32Type}, {Type: bytes32Type},
	}
	structPayload, err := transactionArguments.Pack(
		ethereumCrypto.Keccak256Hash([]byte(zkSyncEIP712TransactionType)),
		big.NewInt(0x71), from, to, gasLimit, gasPerPubdataByteLimit, maxFeePerGas,
		maxPriorityFeePerGas, paymaster, nonce, value, ethereumCrypto.Keccak256Hash(data),
		factoryDepsHash, ethereumCrypto.Keccak256Hash(paymasterInput),
	)
	if err != nil {
		return common.Hash{}, &InvalidZkSyncTransactionError{message: fmt.Sprintf("encode zkSync EIP-712 transaction: %v", err)}
	}
	domainPayload, err := abi.Arguments{{Type: bytes32Type}, {Type: bytes32Type}, {Type: bytes32Type}, {Type: uint256Type}}.Pack(
		ethereumCrypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId)")),
		ethereumCrypto.Keccak256Hash([]byte("zkSync")),
		ethereumCrypto.Keccak256Hash([]byte("2")),
		chainID,
	)
	if err != nil {
		return common.Hash{}, fmt.Errorf("encode zkSync EIP-712 domain: %w", err)
	}

	return ethereumCrypto.Keccak256Hash([]byte{0x19, 0x01}, ethereumCrypto.Keccak256(domainPayload), ethereumCrypto.Keccak256(structPayload)), nil
}

func parseZkSyncQuantity(field, value string, allowEmpty bool) (*big.Int, error) {
	if value == "" && allowEmpty {
		return new(big.Int), nil
	}
	quantity, err := hexutil.DecodeBig(value)
	if err != nil || quantity.BitLen() > 256 {
		if err == nil {
			err = fmt.Errorf("exceeds uint256")
		}
		return nil, &InvalidZkSyncTransactionError{message: fmt.Sprintf("%s must be a uint256 hexadecimal quantity: %v", field, err)}
	}
	return quantity, nil
}

func parseZkSyncAddress(field, value string, allowEmpty bool) (*big.Int, error) {
	if value == "" && allowEmpty {
		return new(big.Int), nil
	}
	if !common.IsHexAddress(value) {
		return nil, &InvalidZkSyncTransactionError{message: fmt.Sprintf("%s must be a valid Ethereum address", field)}
	}
	return common.HexToAddress(value).Big(), nil
}

func parseZkSyncBytes(field, value string) ([]byte, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(value, "0X"), "0x"))
	if err != nil {
		return nil, &InvalidZkSyncTransactionError{message: fmt.Sprintf("%s must be hexadecimal: %v", field, err)}
	}
	return data, nil
}

func hashZkSyncFactoryDeps(factoryDeps []string) (common.Hash, error) {
	packed := make([]byte, 0, len(factoryDeps)*common.HashLength)
	for index, factoryDep := range factoryDeps {
		dependency, err := parseZkSyncBytes(fmt.Sprintf("factoryDeps[%d]", index), factoryDep)
		if err != nil {
			return common.Hash{}, err
		}
		if len(dependency) != common.HashLength {
			return common.Hash{}, &InvalidZkSyncTransactionError{message: fmt.Sprintf("factoryDeps[%d] must be 32 bytes", index)}
		}
		packed = append(packed, dependency...)
	}
	return ethereumCrypto.Keccak256Hash(packed), nil
}
