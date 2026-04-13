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
			c.pathKey(),
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
			logical.UpdateOperation: c.NewCreateOperation(),
			logical.ReadOperation:   c.NewListOperation(),
			logical.ListOperation:   c.NewListOperation(),
		},
		ExistenceCheck: c.ExistenceCheck(),
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel:       service.IDFieldSchema,
			service.CurveLabel:    service.CurveFieldSchema,
			service.MetadataLabel: service.MetadataFieldSchema,
		},
	}
}

func (c *controller) pathKey() *framework.Path {
	return &framework.Path{
		Pattern:         "keys/" + framework.GenericNameRegex(service.IDLabel),
		HelpSynopsis:    "Read a private key by ID",
		HelpDescription: "Read a private key by ID, returning the public key and metadata. The private scalar is never returned.",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: c.NewReadOperation(),
		},
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel: service.IDFieldSchema,
		},
	}
}

type keysOperations struct {
	createKey operations.CreateKeyOperation
	readKey   operations.ReadKeyOperation
	checkKey  operations.ExistsKeyOperation
	listKeys  operations.ListKeysOperation
}

func newKeysOperations() operations.KeysOperations {
	return &keysOperations{
		createKey: operations.NewCreateKeyOperation(),
		readKey:   operations.NewReadKeyOperation(),
		checkKey:  operations.NewExistsKeyOperation(),
		listKeys:  operations.NewListKeysOperation(),
	}
}

func (o *keysOperations) CreateKey() operations.CreateKeyOperation {
	return o.createKey
}

func (o *keysOperations) ReadKey() operations.ReadKeyOperation {
	return o.readKey
}

func (o *keysOperations) ExistsKey() operations.ExistsKeyOperation {
	return o.checkKey
}

func (o *keysOperations) ListKeys() operations.ListKeysOperation {
	return o.listKeys
}
