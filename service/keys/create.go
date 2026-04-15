package privatekeys

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	errorsPkg "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/errors"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	cryptoPkg "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	serviceErrors "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/errors"
)

// isClientError reports whether err should be surfaced as an HTTP 400 (bad
// request) rather than an HTTP 500 (internal server error).
//
// Rules:
//   - UnsupportedCurveError   → caller sent an unrecognised curve name (400)
//   - AlreadyExistsCode       → caller tried to create a duplicate key (400)
//   - MissingFieldCode        → caller omitted a required field (400)
//   - everything else         → storage failure, entropy error, etc. (500)
func isClientError(err error) bool {
	if errors.As(err, new(cryptoPkg.UnsupportedCurveError)) {
		return true
	}
	coreErr, ok := errors.AsType[errorsPkg.Error](err)
	if ok {
		switch coreErr.Code {
		case errorsPkg.MissingFieldCode,
			errorsPkg.AlreadyExistsCode:
			return true
		}
	}
	return false
}

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
			400: {service.Example400Response()},
			500: {service.Example500Response()},
		},
	}
}

func (c *controller) handler() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		id := data.Get(service.IDLabel).(string)
		curve := data.Get(service.CurveLabel).(string)
		metadata, _ := data.Get(service.MetadataLabel).(map[string]string)
		if metadata == nil {
			metadata = map[string]string{}
		}

		if id == "" {
			return serviceErrors.ErrorResponse(errorsPkg.MissingFieldError("id"))
		}
		if curve == "" {
			return serviceErrors.ErrorResponse(errorsPkg.MissingFieldError("curve"))
		}

		ctx = log.Context(ctx, c.logger)
		key, err := c.operations.CreateKey().WithStorage(req.Storage).Execute(ctx, id, curve, metadata)
		if err != nil {
			if isClientError(err) {
				return serviceErrors.ErrorResponse(err)
			}
			return serviceErrors.ServerErrorResponse(err)
		}

		return KeyCreatedResponse(key), nil
	}
}

func (c *controller) ExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		id := data.Get(service.IDLabel).(string)
		if id == "" {
			return false, errorsPkg.MissingFieldError("id")
		}

		ctx = log.Context(ctx, c.logger)
		_, err := c.operations.ExistsKey().WithStorage(req.Storage).Execute(ctx, id)
		if err != nil {
			var coreErr *errorsPkg.Error
			if errors.As(err, &coreErr) && coreErr.Code == errorsPkg.StorageEntryNotFoundCode {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}
