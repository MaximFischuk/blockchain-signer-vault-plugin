package sign

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethereumCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
)

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
