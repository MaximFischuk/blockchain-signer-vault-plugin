package sign

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/erc4337"
)

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
