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
)

func (c *controller) NewReadOperation() *framework.PathOperation {
	successExample := Example200ResponseKeyRead()
	return &framework.PathOperation{
		Callback:    c.readHandler(),
		Summary:     "Reads a key pair by ID",
		Description: "Reads a key pair by ID, returning the public key and metadata. The private key scalar is never included in the response.",
		Examples: []framework.RequestExample{
			{
				Description: "Read an existing key pair by ID",
				Response:    successExample,
			},
		},
		Responses: map[int][]framework.Response{
			200: {*successExample},
			404: {service.Example404Response()},
			500: {service.Example500Response()},
		},
	}
}

func (c *controller) readHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("id"))
		}

		ctx = log.Context(ctx, c.logger)
		key, err := c.operations.ReadKey().WithStorage(req.Storage).Execute(ctx, id)
		if err != nil {
			// A not-found error is not a server fault. Returning (nil, nil) is
			// the Vault SDK convention for signalling a 404: the framework
			// translates a nil response into "no data at this path".
			var coreErr *coreErrors.Error
			if errors.As(err, &coreErr) && coreErr.Code == coreErrors.StorageEntryNotFoundCode {
				return nil, nil
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return KeyReadResponse(key), nil
	}
}
