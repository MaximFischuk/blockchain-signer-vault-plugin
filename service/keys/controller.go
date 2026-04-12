package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations"
)

type controller struct {
	operations operations.KeysOperations
	logger     log.Logger
}

func NewController(logger log.Logger) *controller {
	if logger == nil {
		logger = log.Default()
	}

	return &controller{
		operations: newKeysOperations(),
		logger:     logger.Named("keys"),
	}
}

func (c *controller) Paths() []*framework.Path {
	return framework.PathAppend(
		[]*framework.Path{
			c.pathKeys(),
		},
	)
}

func (c *controller) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern:         "keys/?",
		HelpSynopsis:    "Manage private keys",
		HelpDescription: "Create and manage private keys used for signing operations",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: c.NewCreateOperation(),
		},
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel:       service.IDFieldSchema,
			service.CurveLabel:    service.CurveFieldSchema,
			service.MetadataLabel: service.MetadataFieldSchema,
		},
	}
}

type keysOperations struct {
	createKey operations.CreateKeyOperation
}

func newKeysOperations() operations.KeysOperations {
	return &keysOperations{
		createKey: operations.NewCreateKeyOperation(),
	}
}

func (o *keysOperations) CreateKey() operations.CreateKeyOperation {
	return o.createKey
}
