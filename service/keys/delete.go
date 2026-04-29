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

func (c *controller) NewDeleteOperation() *framework.PathOperation {
	successExample := Example200ResponseKeyDelete()
	return &framework.PathOperation{
		Callback:    c.deleteHandler(),
		Summary:     "Delete a key pair",
		Description: "Deletes a key pair by ID, returning a confirmation message. The key pair is permanently removed and cannot be recovered.",
		Examples: []framework.RequestExample{
			{
				Description: "Delete an existing key pair by ID",
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

func (c *controller) deleteHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return serviceErrors.ErrorResponse(coreErrors.MissingFieldError("id"))
		}

		ctx = log.Context(ctx, c.logger)
		err := c.operations.DeleteKey().WithStorage(req.Storage).Execute(ctx, id)
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

		// Return an empty 200 response to indicate success. The key was deleted, so there's no data to return.
		return &logical.Response{}, nil
	}
}
