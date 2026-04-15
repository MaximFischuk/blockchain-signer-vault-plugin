package privatekeys

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	coreErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	serviceErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
	operations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
)

func (c *controller) NewSignMessageOperation() *framework.PathOperation {
	successExample := Example200ResponseSignMessage()
	return &framework.PathOperation{
		Callback:    c.signMessageHandler(),
		Summary:     "Hash and sign a message",
		Description: "Hashes the provided message (hex-encoded bytes) with the specified hash function and signs the resulting digest using the private key identified by the given ID",
		Examples: []framework.RequestExample{
			{
				Description: "Hash and sign a message with an existing key",
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

func (c *controller) signMessageHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		messageHex := data.Get(service.MessageLabel).(string)
		hashFnStr := data.Get(service.HashFunctionLabel).(string)

		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("id"))
		}
		if messageHex == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("message"))
		}
		if hashFnStr == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("hash_function"))
		}

		messageBytes, err := hex.DecodeString(messageHex)
		if err != nil {
			return serviceErrors.ErrorResponse(errors.New("message must be a valid hex string"))
		}

		ctx = log.Context(ctx, c.logger)
		sig, err := c.operations.SignMessage().WithStorage(req.Storage).Execute(ctx, id, messageBytes, operations.HashFunction(hashFnStr))
		if err != nil {
			if isSignClientError(err) {
				return serviceErrors.ErrorResponse(err)
			}
			var coreErr *coreErrors.Error
			if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
				return nil, nil
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return SignatureResponse(sig), nil
	}
}
