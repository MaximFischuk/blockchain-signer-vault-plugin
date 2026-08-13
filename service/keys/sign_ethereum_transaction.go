package privatekeys

import (
	"context"
	"errors"

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
		Description: "Signs an eth_signTransaction-compatible legacy or EIP-1559 transaction with a secp256k1 key. All quantities must be 0x-prefixed hexadecimal strings. The returned signed_transaction is ready for eth_sendRawTransaction.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a legacy Ethereum transfer with JSON-RPC transaction fields",
				Data: map[string]any{
					service.TransactionTypeLabel: "0x0",
					service.NonceLabel:           "0x0",
					service.ToLabel:              "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
					service.AmountLabel:          "0xde0b6b3a7640000",
					service.GasLimitLabel:        "0x5208",
					service.GasPriceLabel:        "0x4a817c800",
					service.ChainIDLabel:         "0x1",
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

		transaction := operations.EthereumTransaction{
			Type:                 operations.EthereumTransactionType(data.Get(service.TransactionTypeLabel).(string)),
			Nonce:                data.Get(service.NonceLabel).(string),
			To:                   data.Get(service.ToLabel).(string),
			Value:                data.Get(service.AmountLabel).(string),
			GasLimit:             data.Get(service.GasLimitLabel).(string),
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
