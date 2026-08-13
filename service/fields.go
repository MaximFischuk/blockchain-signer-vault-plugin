package service

import "github.com/hashicorp/vault/sdk/framework"

const (
	PrivateKeyLabel           = "private_key"
	IDLabel                   = "id"
	DataLabel                 = "data"
	NonceLabel                = "nonce"
	ToLabel                   = "to"
	AmountLabel               = "value"
	GasPriceLabel             = "gasPrice"
	GasLimitLabel             = "gas"
	ChainIDLabel              = "chainId"
	PrivateFromLabel          = "private_from"
	PrivateForLabel           = "private_for"
	PrivacyGroupIDLabel       = "privacy_group_id"
	MetadataLabel             = "metadata"
	CurveLabel                = "curve"
	AddressLabel              = "address"
	PublicKeyLabel            = "public_key"
	CompressedPublicKeyLabel  = "compressed_public_key"
	NamespaceLabel            = "namespace"
	SignatureLabel            = "signature"
	SignaturesLabel           = "signatures"
	AlgorithmLabel            = "signing_algorithm"
	VersionLabel              = "version"
	KeyTypeLabel              = "key_type"
	CreatedAtLabel            = "created_at"
	UpdatedAtLabel            = "updated_at"
	SourceNamespace           = "source_namespace"
	KeysLabel                 = "keys"
	HashLabel                 = "hash"
	HashesLabel               = "hashes"
	MessageLabel              = "message"
	HashFunctionLabel         = "hash_function"
	TransactionTypeLabel      = "type"
	MaxPriorityFeePerGasLabel = "maxPriorityFeePerGas"
	MaxFeePerGasLabel         = "maxFeePerGas"
	SignedTransactionLabel    = "signed_transaction"
	TransactionHashLabel      = "transaction_hash"

	NamespaceHeader = "X-Vault-Namespace"
)

var IDFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "ID of the key pair",
	Required:    true,
}

var AddressFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Address of the account",
	Required:    true,
}

var NonceFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Transaction nonce as an Ethereum JSON-RPC hexadecimal quantity",
	Required:    true,
}

var ToFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Recipient of the transaction. Empty for contract deployments",
}

var AmountFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Transaction value in wei as an Ethereum JSON-RPC hexadecimal quantity",
}

var GasPriceFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Legacy gas price in wei as an Ethereum JSON-RPC hexadecimal quantity",
}

var GasLimitFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Transaction gas limit as an Ethereum JSON-RPC hexadecimal quantity",
	Required:    true,
}

var ChainIDFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Chain ID as an Ethereum JSON-RPC hexadecimal quantity",
	Required:    true,
}

var DataFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Transaction calldata in hexadecimal format, with optional 0x prefix",
}

var TransactionTypeFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Ethereum transaction type as a hexadecimal quantity: 0x0 for legacy or 0x2 for EIP-1559",
	Required:    true,
}

var MaxPriorityFeePerGasFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "EIP-1559 maximum priority fee per gas in wei as an Ethereum JSON-RPC hexadecimal quantity",
}

var MaxFeePerGasFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "EIP-1559 maximum fee per gas in wei as an Ethereum JSON-RPC hexadecimal quantity",
}

var PrivateFromFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "EEA PrivateFrom address in base64 format",
}

var PrivateForFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeCommaStringSlice,
	Description: "EEA PrivateFor addresses in base64 format",
}

var PrivacyGroupIDFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "EEA PrivacyGroupID address in base64 format",
}

var MetadataFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeKVPairs,
	Description: "Metadata associated with the key pair",
	Required:    true,
}

var CurveFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Elliptic curve used for the key pair",
	Required:    true,
}

var HashFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Pre-computed hash to sign, in hex format (without 0x prefix)",
	Required:    true,
}

var HashesFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeCommaStringSlice,
	Description: "List of pre-computed hashes to sign, each in hex format (without 0x prefix)",
	Required:    true,
}

var MessageFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Raw message bytes to hash and sign, in hex format (without 0x prefix)",
	Required:    true,
}

var HashFunctionFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Hash function to apply to the message before signing (sha256, keccak256, sha512, sha3-256)",
	Required:    true,
}
