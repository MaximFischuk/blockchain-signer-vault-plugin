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

// KeyReadResponse is richer than KeyCreatedResponse: it also surfaces
// key_type, created_at, and updated_at so callers can inspect the full
// non-sensitive record. The private scalar is intentionally omitted.
func KeyReadResponse(key *entities.PrivateKey) *logical.Response {
	return &logical.Response{
		Data: map[string]any{
			service.IDLabel:        key.ID,
			service.KeyTypeLabel:   key.KeyType,
			service.CurveLabel:     key.Curve,
			service.PublicKeyLabel: key.PublicKey,
			service.MetadataLabel:  key.Metadata,
			service.CreatedAtLabel: key.CreatedAt,
			service.UpdatedAtLabel: key.UpdatedAt,
		},
	}
}
