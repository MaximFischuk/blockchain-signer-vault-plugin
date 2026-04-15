package service

import "github.com/hashicorp/vault/sdk/framework"

const (
	PrivateKeyLabel          = "private_key"
	IDLabel                  = "id"
	DataLabel                = "data"
	NonceLabel               = "nonce"
	ToLabel                  = "to"
	AmountLabel              = "amount"
	GasPriceLabel            = "gas_price"
	GasLimitLabel            = "gas_limit"
	ChainIDLabel             = "chain_id"
	PrivateFromLabel         = "private_from"
	PrivateForLabel          = "private_for"
	PrivacyGroupIDLabel      = "privacy_group_id"
	MetadataLabel            = "metadata"
	CurveLabel               = "curve"
	AddressLabel             = "address"
	PublicKeyLabel           = "public_key"
	CompressedPublicKeyLabel = "compressed_public_key"
	NamespaceLabel           = "namespace"
	SignatureLabel           = "signature"
	SignaturesLabel          = "signatures"
	AlgorithmLabel           = "signing_algorithm"
	VersionLabel             = "version"
	KeyTypeLabel             = "key_type"
	CreatedAtLabel           = "created_at"
	UpdatedAtLabel           = "updated_at"
	SourceNamespace          = "source_namespace"
	KeysLabel                = "keys"
	HashLabel                = "hash"
	HashesLabel              = "hashes"
	MessageLabel             = "message"
	HashFunctionLabel        = "hash_function"

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
	Type:        framework.TypeInt,
	Description: "Nonce of the transaction",
	Required:    true,
}

var ToFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Recipient of the transaction. Empty for contract deployments",
}

var AmountFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Amount of ETH (in wei) to transfer",
}

var GasPriceFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "The gas price for the transaction (in wei)",
	Required:    true,
}

var GasLimitFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeInt,
	Description: "The gas limit for the transaction",
	Required:    true,
}

var ChainIDFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Network ID of the chain where the transaction will be deployed",
	Required:    true,
}

var DataFieldSchema = &framework.FieldSchema{
	Type:        framework.TypeString,
	Description: "Data of the transaction",
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
