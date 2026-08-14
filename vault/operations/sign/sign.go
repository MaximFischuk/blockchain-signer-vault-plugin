package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/erc4337"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
	extraSha3 "golang.org/x/crypto/sha3"
)

type SignOperations interface {
	SignHash() SignHashOperation
	SignMessage() SignMessageOperation
	SignBatchHashes() SignBatchHashesOperation
	SignEthereumTransaction() SignEthereumTransactionOperation
	SignEthereumTypedData() SignEthereumTypedDataOperation
	SignEthereumUserOperation() SignEthereumUserOperationOperation
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

type EthereumTransactionType string

const (
	EthereumLegacyTransaction  EthereumTransactionType = "0x0"
	EthereumEIP1559Transaction EthereumTransactionType = "0x2"
)

// EthereumTransaction contains eth_signTransaction request fields. Quantities use
// JSON-RPC hexadecimal encoding.
type EthereumTransaction struct {
	Type                 EthereumTransactionType
	Nonce                string
	To                   string
	Value                string
	GasLimit             string
	ChainID              string
	Data                 string
	GasPrice             string
	MaxPriorityFeePerGas string
	MaxFeePerGas         string
}

// SignedEthereumTransaction is ready for submission through eth_sendRawTransaction.
type SignedEthereumTransaction struct {
	RawTransaction  string
	TransactionHash string
}

// InvalidEthereumTransactionError identifies caller-supplied transaction data that
// cannot be encoded or signed.
type InvalidEthereumTransactionError struct {
	message string
}

func (e *InvalidEthereumTransactionError) Error() string {
	return e.message
}

type SignEthereumTransactionOperation interface {
	Execute(ctx context.Context, id string, transaction EthereumTransaction) (*SignedEthereumTransaction, error)
	WithStorage(storage logical.Storage) SignEthereumTransactionOperation
}

// InvalidEthereumTypedDataError identifies caller-supplied typed data that
// cannot be encoded or signed.
type InvalidEthereumTypedDataError struct {
	message string
}

func (e *InvalidEthereumTypedDataError) Error() string {
	return e.message
}

type SignEthereumTypedDataOperation interface {
	Execute(ctx context.Context, id string, typedData apitypes.TypedData) (string, error)
	WithStorage(storage logical.Storage) SignEthereumTypedDataOperation
}

type EntryPointVersion string

const (
	EntryPointVersion07 EntryPointVersion = "0.7"
	EntryPointVersion08 EntryPointVersion = "0.8"
	EntryPointVersion09 EntryPointVersion = "0.9"
)

type InvalidEthereumUserOperationError struct {
	message string
}

func (e *InvalidEthereumUserOperationError) Error() string {
	return e.message
}

type SignEthereumUserOperationOperation interface {
	Execute(ctx context.Context, id string, userOperation erc4337.RequestUserOperation, entryPoint string, version EntryPointVersion, chainID string) (string, error)
	WithStorage(storage logical.Storage) SignEthereumUserOperationOperation
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

// --- SignEthereumTransactionOperation implementation ---

type signEthereumTransactionOperation struct {
	storage logical.Storage
}

func NewSignEthereumTransactionOperation() SignEthereumTransactionOperation {
	return &signEthereumTransactionOperation{}
}

func (o signEthereumTransactionOperation) WithStorage(s logical.Storage) SignEthereumTransactionOperation {
	o.storage = s
	return &o
}

func (o *signEthereumTransactionOperation) Execute(ctx context.Context, id string, transaction EthereumTransaction) (*SignedEthereumTransaction, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return nil, err
	}
	if key.Curve != crypto.Secp256k1 {
		return nil, &InvalidEthereumTransactionError{message: fmt.Sprintf("Ethereum transactions require a secp256k1 key, got %q", key.Curve)}
	}

	chainID, err := parseEthereumQuantity("chainId", transaction.ChainID, false)
	if err != nil {
		return nil, err
	}
	if chainID.Sign() <= 0 {
		return nil, &InvalidEthereumTransactionError{message: "chainId must be greater than zero"}
	}
	nonce, err := parseEthereumUint64("nonce", transaction.Nonce)
	if err != nil {
		return nil, err
	}
	gasLimit, err := parseEthereumUint64("gas", transaction.GasLimit)
	if err != nil {
		return nil, err
	}
	if gasLimit == 0 {
		return nil, &InvalidEthereumTransactionError{message: "gas must be greater than zero"}
	}
	to, err := parseEthereumAddress(transaction.To)
	if err != nil {
		return nil, err
	}
	value, err := parseEthereumQuantity("amount", transaction.Value, true)
	if err != nil {
		return nil, err
	}
	data, err := parseEthereumData(transaction.Data)
	if err != nil {
		return nil, err
	}

	unsigned, err := buildEthereumTransaction(transaction, chainID, nonce, gasLimit, to, value, data)
	if err != nil {
		return nil, err
	}
	privateKey, err := ethereumCrypto.HexToECDSA(key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode secp256k1 private key: %w", err)
	}
	signed, err := types.SignTx(unsigned, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign Ethereum transaction: %w", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encode signed Ethereum transaction: %w", err)
	}

	return &SignedEthereumTransaction{
		RawTransaction:  hexutil.Encode(raw),
		TransactionHash: signed.Hash().Hex(),
	}, nil
}

// --- SignEthereumTypedDataOperation implementation ---

type signEthereumTypedDataOperation struct {
	storage logical.Storage
}

func NewSignEthereumTypedDataOperation() SignEthereumTypedDataOperation {
	return &signEthereumTypedDataOperation{}
}

func (o signEthereumTypedDataOperation) WithStorage(s logical.Storage) SignEthereumTypedDataOperation {
	o.storage = s
	return &o
}

func (o *signEthereumTypedDataOperation) Execute(ctx context.Context, id string, typedData apitypes.TypedData) (string, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}
	if key.Curve != crypto.Secp256k1 {
		return "", &InvalidEthereumTypedDataError{message: fmt.Sprintf("EIP-712 messages require a secp256k1 key, got %q", key.Curve)}
	}

	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return "", &InvalidEthereumTypedDataError{message: fmt.Sprintf("invalid EIP-712 typed data: %v", err)}
	}
	privateKey, err := ethereumCrypto.HexToECDSA(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode secp256k1 private key: %w", err)
	}
	signature, err := ethereumCrypto.Sign(digest, privateKey)
	if err != nil {
		return "", fmt.Errorf("sign EIP-712 typed data: %w", err)
	}
	signature[64] += 27

	return hexutil.Encode(signature), nil
}

// --- SignEthereumUserOperationOperation implementation ---

type signEthereumUserOperationOperation struct {
	storage logical.Storage
}

func NewSignEthereumUserOperationOperation() SignEthereumUserOperationOperation {
	return &signEthereumUserOperationOperation{}
}

func (o signEthereumUserOperationOperation) WithStorage(s logical.Storage) SignEthereumUserOperationOperation {
	o.storage = s
	return &o
}

func (o *signEthereumUserOperationOperation) Execute(ctx context.Context, id string, request erc4337.RequestUserOperation, entryPointHex string, version EntryPointVersion, chainIDHex string) (string, error) {
	key, err := loadKey(ctx, o.storage, id)
	if err != nil {
		return "", err
	}
	if key.Curve != crypto.Secp256k1 {
		return "", &InvalidEthereumUserOperationError{message: fmt.Sprintf("UserOperations require a secp256k1 key, got %q", key.Curve)}
	}
	if !common.IsHexAddress(entryPointHex) {
		return "", &InvalidEthereumUserOperationError{message: "entryPoint must be a valid Ethereum address"}
	}
	chainID, err := hexutil.DecodeBig(chainIDHex)
	if err != nil {
		return "", &InvalidEthereumUserOperationError{message: fmt.Sprintf("chainId must be a hexadecimal quantity: %v", err)}
	}

	userOperation, err := request.ToUserOperation()
	if err != nil {
		return "", &InvalidEthereumUserOperationError{message: fmt.Sprintf("invalid UserOperation: %v", err)}
	}
	entryPoint := common.HexToAddress(entryPointHex)
	var digest common.Hash
	switch version {
	case EntryPointVersion07:
		digest, err = erc4337.HashUserOperationV07(userOperation, entryPoint, chainID)
	case EntryPointVersion08:
		digest, err = erc4337.HashUserOperationV08(userOperation, entryPoint, chainID)
	case EntryPointVersion09:
		digest, err = erc4337.HashUserOperationV09(userOperation, entryPoint, chainID)
	default:
		return "", &InvalidEthereumUserOperationError{message: fmt.Sprintf("unsupported EntryPoint version: %q", version)}
	}
	if err != nil {
		return "", &InvalidEthereumUserOperationError{message: fmt.Sprintf("hash UserOperation: %v", err)}
	}

	privateKey, err := ethereumCrypto.HexToECDSA(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode secp256k1 private key: %w", err)
	}
	signature, err := ethereumCrypto.Sign(digest.Bytes(), privateKey)
	if err != nil {
		return "", fmt.Errorf("sign UserOperation: %w", err)
	}
	signature[64] += 27

	return hexutil.Encode(signature), nil
}

func buildEthereumTransaction(transaction EthereumTransaction, chainID *big.Int, nonce, gasLimit uint64, to *common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	switch EthereumTransactionType(strings.ToLower(string(transaction.Type))) {
	case EthereumLegacyTransaction:
		gasPrice, err := parseEthereumQuantity("gasPrice", transaction.GasPrice, false)
		if err != nil {
			return nil, err
		}
		return types.NewTx(&types.LegacyTx{Nonce: nonce, To: to, Value: value, Gas: gasLimit, GasPrice: gasPrice, Data: data}), nil
	case EthereumEIP1559Transaction:
		gasTipCap, err := parseEthereumQuantity("maxPriorityFeePerGas", transaction.MaxPriorityFeePerGas, false)
		if err != nil {
			return nil, err
		}
		gasFeeCap, err := parseEthereumQuantity("maxFeePerGas", transaction.MaxFeePerGas, false)
		if err != nil {
			return nil, err
		}
		if gasFeeCap.Cmp(gasTipCap) < 0 {
			return nil, &InvalidEthereumTransactionError{message: "maxFeePerGas must be greater than or equal to maxPriorityFeePerGas"}
		}
		return types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: gasTipCap, GasFeeCap: gasFeeCap, Gas: gasLimit, To: to, Value: value, Data: data}), nil
	default:
		return nil, &InvalidEthereumTransactionError{message: fmt.Sprintf("unsupported Ethereum transaction type: %q", transaction.Type)}
	}
}

func parseEthereumQuantity(field, value string, allowEmpty bool) (*big.Int, error) {
	if value == "" && allowEmpty {
		return new(big.Int), nil
	}
	quantity, err := hexutil.DecodeBig(value)
	if err != nil {
		return nil, &InvalidEthereumTransactionError{message: fmt.Sprintf("%s must be a hexadecimal quantity: %v", field, err)}
	}
	return quantity, nil
}

func parseEthereumUint64(field, value string) (uint64, error) {
	quantity, err := hexutil.DecodeUint64(value)
	if err != nil {
		return 0, &InvalidEthereumTransactionError{message: fmt.Sprintf("%s must be a hexadecimal quantity: %v", field, err)}
	}
	return quantity, nil
}

func parseEthereumAddress(value string) (*common.Address, error) {
	if value == "" {
		return nil, nil
	}
	if !common.IsHexAddress(value) {
		return nil, &InvalidEthereumTransactionError{message: "to must be a valid Ethereum address"}
	}
	address := common.HexToAddress(value)
	return &address, nil
}

func parseEthereumData(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, &InvalidEthereumTransactionError{message: fmt.Sprintf("data must be hexadecimal: %v", err)}
	}
	return data, nil
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
		h := extraSha3.NewLegacyKeccak256()
		h.Write(message)
		return h.Sum(nil), nil
	case HashFunctionSHA512:
		digest := sha512.Sum512(message)
		return digest[:], nil
	case HashFunctionSHA3256:
		h := sha3.New256()
		_, err := h.Write(message)
		if err != nil {
			return nil, fmt.Errorf("failed to hash message with SHA3-256: %w", err)
		}
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
	privKey, err := ecdsa.ParseRawPrivateKey(curve, privKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse P-256 private key: %w", err)
	}

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
