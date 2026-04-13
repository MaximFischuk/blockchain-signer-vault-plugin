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

func (c *controller) NewListOperation() *framework.PathOperation {
	successExample := Example200ResponseKeysList()
	return &framework.PathOperation{
		Callback:    c.listHandler(),
		Summary:     "Lists all key pairs",
		Description: "Lists all key pairs, returning their IDs and metadata. The private key scalars are never included in the response.",
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

func (c *controller) listHandler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		ctx = log.Context(ctx, c.logger)
		keys, err := c.operations.ListKeys().WithStorage(req.Storage).Execute(ctx)
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

		return KeysListResponse(keys), nil
	}
}
