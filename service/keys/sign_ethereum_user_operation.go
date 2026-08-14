package privatekeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/erc4337"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	serviceErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
	operations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
)

func (c *controller) NewSignEthereumUserOperationOperation() *framework.PathOperation {
	successExample := Example200ResponseSignEthereumUserOperation()
	return &framework.PathOperation{
		Callback:    c.signEthereumUserOperationHandler(),
		Summary:     "Sign an ERC-4337 UserOperation",
		Description: "Hashes and signs an ERC-7769 UserOperation with a secp256k1 key. EntryPoint version selects the v0.7, v0.8, or v0.9 hashing protocol.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a UserOperation for EntryPoint v0.8",
				Data: map[string]any{
					service.UserOperationLabel:     exampleUserOperation(),
					service.EntryPointLabel:        "0x0000000071727De22E5E9d8bAF0edAc6f37da032",
					service.EntryPointVersionLabel: "0.8",
					service.ChainIDLabel:           "0x1",
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

func (c *controller) signEthereumUserOperationHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError(service.IDLabel))
		}
		rawUserOperation, ok := data.GetOk(service.UserOperationLabel)
		if !ok {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError(service.UserOperationLabel))
		}
		payload, err := json.Marshal(rawUserOperation)
		if err != nil {
			return serviceErrors.ErrorResponse(fmt.Errorf("encode UserOperation: %w", err))
		}
		var userOperation erc4337.RequestUserOperation
		if err := json.Unmarshal(payload, &userOperation); err != nil {
			return serviceErrors.ErrorResponse(fmt.Errorf("decode UserOperation: %w", err))
		}

		ctx = log.Context(ctx, c.logger)
		signature, err := c.operations.SignEthereumUserOperation().WithStorage(req.Storage).Execute(
			ctx,
			id,
			userOperation,
			data.Get(service.EntryPointLabel).(string),
			operations.EntryPointVersion(data.Get(service.EntryPointVersionLabel).(string)),
			data.Get(service.ChainIDLabel).(string),
		)
		if err != nil {
			if isEthereumUserOperationClientError(err) {
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

func isEthereumUserOperationClientError(err error) bool {
	var userOperationErr *operations.InvalidEthereumUserOperationError
	if errors.As(err, &userOperationErr) {
		return true
	}
	return isSignClientError(err)
}

func exampleUserOperation() map[string]any {
	return map[string]any{
		"sender":               "0x9f22F7C0c9D5a27881D1b4A29d14A7F88547DdbD",
		"nonce":                "0x7",
		"callData":             "0xcafebabe",
		"callGasLimit":         "0x249f0",
		"verificationGasLimit": "0x186a0",
		"preVerificationGas":   "0xc350",
		"maxPriorityFeePerGas": "0x64",
		"maxFeePerGas":         "0x3e8",
	}
}
