package privatekeys

import (
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
)

func KeyCreatedResponse(key *entities.PrivateKey) *logical.Response {
	return &logical.Response{
		Data: map[string]any{
			service.IDLabel:        key.ID,
			service.CurveLabel:     key.Curve,
			service.PublicKeyLabel: key.PublicKey,
			service.MetadataLabel:  key.Metadata,
		},
	}
}
