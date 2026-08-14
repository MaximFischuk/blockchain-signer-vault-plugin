package sign

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
)

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
