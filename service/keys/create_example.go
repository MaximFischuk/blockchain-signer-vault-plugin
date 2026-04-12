package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
)

func ExampleKey() *entities.PrivateKey {
	return &entities.PrivateKey{
		ID:         "",
		Curve:      crypto.Secp256k1,
		PrivateKey: "0x00112233445566778899001122334455667788990011223344556677889900",
		PublicKey:  "0x001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899",
		Metadata: map[string]string{
			"example": "metadata",
		},
	}
}

func Example200ResponseKeyCreated() *framework.Response {
	return &framework.Response{
		Description: "Key created successfully",
		Example:     KeyCreatedResponse(ExampleKey()),
	}
}
