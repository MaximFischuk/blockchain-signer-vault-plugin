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

func (c *controller) NewSignBatchHashesOperation() *framework.PathOperation {
	successExample := Example200ResponseSignBatch()
	return &framework.PathOperation{
		Callback:    c.signBatchHashesHandler(),
		Summary:     "Sign a batch of pre-computed hashes",
		Description: "Signs a list of pre-computed hashes using hex (default), base32, base58, or base64url encoding. Signatures are returned in the same order as the input hashes.",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a batch of pre-computed hashes with an existing key",
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

func (c *controller) signBatchHashesHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		hashes, _ := data.Get(service.HashesLabel).([]string)
		encoding := operations.MessageEncoding(data.Get(service.HashEncodingLabel).(string))

		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("id"))
		}
		if len(hashes) == 0 {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("hashes"))
		}

		ctx = log.Context(ctx, c.logger)
		signatures, err := c.operations.SignBatchHashes().WithStorage(req.Storage).Execute(ctx, id, hashes, encoding)
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

		return SignaturesResponse(signatures), nil
	}
}
