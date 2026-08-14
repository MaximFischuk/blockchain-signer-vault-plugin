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
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/storage"
	extraSha3 "golang.org/x/crypto/sha3"
)

// UnsupportedCurveForSigningError is returned when a curve does not support signing.
type UnsupportedCurveForSigningError string

func (e UnsupportedCurveForSigningError) Error() string {
	return fmt.Sprintf("curve %q does not support signing", string(e))
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
