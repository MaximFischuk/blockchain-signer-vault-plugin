package privatekeys

import (
	"testing"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	"github.com/stretchr/testify/require"
)

func TestEIP712TypedData(t *testing.T) {
	typedData, err := eip712TypedData(&framework.FieldData{
		Raw: exampleEIP712TypedData(),
		Schema: map[string]*framework.FieldSchema{
			service.EIP712TypesLabel:       service.EIP712TypesFieldSchema,
			service.EIP712PrimaryTypeLabel: service.EIP712PrimaryTypeFieldSchema,
			service.EIP712DomainLabel:      service.EIP712DomainFieldSchema,
			service.MessageLabel:           service.EIP712MessageFieldSchema,
		},
	})
	require.NoError(t, err)

	_, _, err = apitypes.TypedDataAndHash(typedData)
	require.NoError(t, err)
}
