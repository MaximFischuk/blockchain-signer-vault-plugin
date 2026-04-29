package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	log "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/core/log"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	operations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/keys"
	signOperations "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/operations/sign"
)

type ControllerOperations interface {
	operations.KeysOperations
	signOperations.SignOperations
}

type controller struct {
	operations ControllerOperations
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
			c.pathSignHash(),
			c.pathSignMessage(),
			c.pathSignBatchHashes(),
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
			logical.ReadOperation:   c.NewReadOperation(),
			logical.DeleteOperation: c.NewDeleteOperation(),
		},
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel: service.IDFieldSchema,
		},
	}
}

func (c *controller) pathSignHash() *framework.Path {
	return &framework.Path{
		Pattern:         "keys/" + framework.GenericNameRegex(service.IDLabel) + "/sign/hash",
		HelpSynopsis:    "Sign a pre-computed hash",
		HelpDescription: "Signs a pre-computed hash (hex-encoded) using the private key identified by the given ID",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: c.NewSignHashOperation(),
			logical.UpdateOperation: c.NewSignHashOperation(),
		},
		ExistenceCheck: c.ExistenceCheck(),
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel:   service.IDFieldSchema,
			service.HashLabel: service.HashFieldSchema,
		},
	}
}

func (c *controller) pathSignMessage() *framework.Path {
	return &framework.Path{
		Pattern:         "keys/" + framework.GenericNameRegex(service.IDLabel) + "/sign/message",
		HelpSynopsis:    "Hash and sign a message",
		HelpDescription: "Hashes the provided message with the specified hash function and signs the resulting digest using the private key identified by the given ID",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: c.NewSignMessageOperation(),
			logical.UpdateOperation: c.NewSignMessageOperation(),
		},
		ExistenceCheck: c.ExistenceCheck(),
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel:           service.IDFieldSchema,
			service.MessageLabel:      service.MessageFieldSchema,
			service.HashFunctionLabel: service.HashFunctionFieldSchema,
		},
	}
}

func (c *controller) pathSignBatchHashes() *framework.Path {
	return &framework.Path{
		Pattern:         "keys/" + framework.GenericNameRegex(service.IDLabel) + "/sign/batch",
		HelpSynopsis:    "Sign a batch of pre-computed hashes",
		HelpDescription: "Signs a list of pre-computed hashes (each hex-encoded) using the private key identified by the given ID. Signatures are returned in the same order as the input hashes.",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: c.NewSignBatchHashesOperation(),
			logical.UpdateOperation: c.NewSignBatchHashesOperation(),
		},
		ExistenceCheck: c.ExistenceCheck(),
		Fields: map[string]*framework.FieldSchema{
			service.IDLabel:     service.IDFieldSchema,
			service.HashesLabel: service.HashesFieldSchema,
		},
	}
}

type keysOperations struct {
	createKey operations.CreateKeyOperation
	readKey   operations.ReadKeyOperation
	checkKey  operations.ExistsKeyOperation
	listKeys  operations.ListKeysOperation
	deleteKey operations.DeleteKeyOperation

	signHash        signOperations.SignHashOperation
	signMessage     signOperations.SignMessageOperation
	signBatchHashes signOperations.SignBatchHashesOperation
}

func newKeysOperations() ControllerOperations {
	return &keysOperations{
		createKey: operations.NewCreateKeyOperation(),
		readKey:   operations.NewReadKeyOperation(),
		checkKey:  operations.NewExistsKeyOperation(),
		listKeys:  operations.NewListKeysOperation(),
		deleteKey: operations.NewDeleteKeyOperation(),

		signHash:        signOperations.NewSignHashOperation(),
		signMessage:     signOperations.NewSignMessageOperation(),
		signBatchHashes: signOperations.NewSignBatchHashesOperation(),
	}
}

// KeysOperations interface methods

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

func (o *keysOperations) DeleteKey() operations.DeleteKeyOperation {
	return o.deleteKey
}

// SignOperations interface methods

func (o *keysOperations) SignHash() signOperations.SignHashOperation {
	return o.signHash
}

func (o *keysOperations) SignMessage() signOperations.SignMessageOperation {
	return o.signMessage
}

func (o *keysOperations) SignBatchHashes() signOperations.SignBatchHashesOperation {
	return o.signBatchHashes
}
