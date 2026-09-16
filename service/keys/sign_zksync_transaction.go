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

func (c *controller) NewSignZkSyncTransactionOperation() *framework.PathOperation {
	data := ExampleZkSyncEIP712TransactionRequestData()
	successExample := Example200ResponseSignZkSyncTransaction()
	return &framework.PathOperation{
		Callback:    c.signZkSyncTransactionHandler(),
		Summary:     "Sign a zkSync EIP-712 transaction",
		Description: "Signs a zkSync native EIP-712 transaction using a secp256k1 key. The transaction type is fixed to 0x71.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a zkSync transfer",
				Data:        data,
				Response:    successExample,
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

func (c *controller) signZkSyncTransactionHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError(service.IDLabel))
		}

		transaction := operations.ZkSyncEIP712Transaction{
			From:                   data.Get(service.FromLabel).(string),
			To:                     data.Get(service.ToLabel).(string),
			GasLimit:               data.Get(service.GasLimitLabel).(string),
			GasPerPubdataByteLimit: data.Get(service.GasPerPubdataByteLimitLabel).(string),
			MaxFeePerGas:           data.Get(service.MaxFeePerGasLabel).(string),
			MaxPriorityFeePerGas:   data.Get(service.MaxPriorityFeePerGasLabel).(string),
			Paymaster:              data.Get(service.PaymasterLabel).(string),
			Nonce:                  data.Get(service.NonceLabel).(string),
			Value:                  data.Get(service.AmountLabel).(string),
			Data:                   data.Get(service.DataLabel).(string),
			FactoryDeps: func() []string {
				factoryDeps, _ := data.Get(service.FactoryDepsLabel).([]string)
				return factoryDeps
			}(),
			PaymasterInput:         data.Get(service.PaymasterInputLabel).(string),
			ChainID:                data.Get(service.ChainIDLabel).(string),
		}

		ctx = log.Context(ctx, c.logger)
		signature, err := c.operations.SignZkSyncTransaction().WithStorage(req.Storage).Execute(ctx, id, transaction)
		if err != nil {
			if isZkSyncTransactionClientError(err) {
				return serviceErrors.ErrorResponse(err)
			}
			var coreErr *coreErrors.Error
			if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
				return nil, nil
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return SignatureResponse(signature), nil
	}
}

func isZkSyncTransactionClientError(err error) bool {
	var transactionErr *operations.InvalidZkSyncTransactionError
	if errors.As(err, &transactionErr) {
		return true
	}
	return isSignClientError(err)
}
