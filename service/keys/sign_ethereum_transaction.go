package privatekeys

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	serviceErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
	operations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
)

func (c *controller) NewSignEthereumTransactionOperation() *framework.PathOperation {
	successExample := Example200ResponseSignEthereumTransaction()
	return &framework.PathOperation{
		Callback:    c.signEthereumTransactionHandler(),
		Summary:     "Sign an Ethereum transaction",
		Description: "Builds, Keccak-256 hashes, and signs a legacy or EIP-1559 transaction with a secp256k1 key. The returned signed_transaction is 0x-prefixed and ready for eth_sendRawTransaction.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a legacy Ethereum transfer",
				Data: map[string]any{
					service.TransactionTypeLabel: "legacy",
					service.NonceLabel:           0,
					service.ToLabel:              "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
					service.AmountLabel:          "1000000000000000000",
					service.GasLimitLabel:        21000,
					service.GasPriceLabel:        "20000000000",
					service.ChainIDLabel:         "1",
				},
				Response: successExample,
			},
		},
		Responses: map[int][]framework.Response{
			200: {*successExample},
			400: {service.Example400Response()},
			404: {service.Example404Response()},
			500: {service.Example500Response()},
		},
	}
}

func (c *controller) signEthereumTransactionHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError(service.IDLabel))
		}

		nonce := data.Get(service.NonceLabel).(int)
		gasLimit := data.Get(service.GasLimitLabel).(int)
		if nonce < 0 {
			return serviceErrors.ErrorResponse(fmt.Errorf("nonce must be non-negative"))
		}
		if gasLimit <= 0 {
			return serviceErrors.ErrorResponse(fmt.Errorf("gas_limit must be greater than zero"))
		}

		transaction := operations.EthereumTransaction{
			Type:                 operations.EthereumTransactionType(data.Get(service.TransactionTypeLabel).(string)),
			Nonce:                uint64(nonce),
			To:                   data.Get(service.ToLabel).(string),
			Value:                data.Get(service.AmountLabel).(string),
			GasLimit:             uint64(gasLimit),
			ChainID:              data.Get(service.ChainIDLabel).(string),
			Data:                 data.Get(service.DataLabel).(string),
			GasPrice:             data.Get(service.GasPriceLabel).(string),
			MaxPriorityFeePerGas: data.Get(service.MaxPriorityFeePerGasLabel).(string),
			MaxFeePerGas:         data.Get(service.MaxFeePerGasLabel).(string),
		}

		ctx = log.Context(ctx, c.logger)
		signed, err := c.operations.SignEthereumTransaction().WithStorage(req.Storage).Execute(ctx, id, transaction)
		if err != nil {
			if isEthereumTransactionClientError(err) {
				return serviceErrors.ErrorResponse(err)
			}
			var coreErr *coreErrors.Error
			if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
				return nil, nil
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return EthereumTransactionResponse(signed.RawTransaction, signed.TransactionHash), nil
	}
}

func isEthereumTransactionClientError(err error) bool {
	var transactionErr *operations.InvalidEthereumTransactionError
	if errors.As(err, &transactionErr) {
		return true
	}
	return isSignClientError(err)
}
