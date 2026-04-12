package privatekeys

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	errorsPkg "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
)

func (c *controller) NewCreateOperation() *framework.PathOperation {
	successExample := Example200ResponseKeyCreated()
	return &framework.PathOperation{
		Callback:    c.handler(),
		Summary:     "Creates a new key pair",
		Description: "Creates a new key pair by generating a private key, storing it in the Vault and computing its public key",
		Examples: []framework.RequestExample{
			{
				Description: "Creates a new key pair on the tenant namespace",
				Response:    successExample,
			},
		},
		Responses: map[int][]framework.Response{
			200: {*successExample},
			500: {service.Example500Response()},
		},
	}
}

func (c *controller) handler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		curve := data.Get(service.CurveLabel).(string)
		metadata := data.Get(service.MetadataLabel).(map[string]string)

		if curve == "" {
			return errors.ErrorResponse(errorsPkg.MissingFieldError("curve"))
		}

		ctx = log.Context(ctx, c.logger)
		key, err := c.operations.CreateKey().WithStorage(req.Storage).Execute(ctx, id, curve, metadata)
		if err != nil {
			return errors.ErrorResponse(err)
		}

		return KeyCreatedResponse(key), nil
	}
}
