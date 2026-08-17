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

func (c *controller) NewSignHashOperation() *framework.PathOperation {
	successExample := Example200ResponseSignHash()
	return &framework.PathOperation{
		Callback:    c.signHashHandler(),
		Summary:     "Sign a pre-computed hash",
		Description: "Signs bytes using hex (default), base32, base58 or base64url encoding",
		Examples: []framework.RequestExample{
			{
				Description: "Sign a pre-computed hash with an existing key",
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

func (c *controller) signHashHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		hash := data.Get(service.HashLabel).(string)
		encoding := operations.MessageEncoding(data.Get(service.HashEncodingLabel).(string))

		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("id"))
		}
		if hash == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("hash"))
		}

		ctx = log.Context(ctx, c.logger)
		sig, err := c.operations.SignHash().WithStorage(req.Storage).Execute(ctx, id, hash, encoding)
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

func isSignClientError(err error) bool {
	if errors.As(err, new(operations.UnsupportedHashFunctionError)) {
		return true
	}
	if errors.As(err, new(operations.UnsupportedCurveForSigningError)) {
		return true
	}
	if errors.As(err, new(operations.UnsupportedHashEncodingError)) {
		return true
	}
	var coreErr *coreErrors.Error
	if errors.As(err, &coreErr) {
		switch coreErr.Code {
		case coreErrors.MissingFieldCode:
			return true
		}
	}
	return false
}
