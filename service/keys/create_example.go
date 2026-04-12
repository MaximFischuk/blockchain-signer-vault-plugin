package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/crypto"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/vault/entities"
)

func ExampleKey() *entities.PrivateKey {
	return &entities.PrivateKey{
		// Real secp256k1 values: 32-byte private scalar and 33-byte
		// compressed public point, both as lowercase hex — no 0x prefix.
		ID:         "example-key-id",
		KeyType:    crypto.KeyTypeEC,
		Curve:      crypto.Secp256k1,
		PrivateKey: "0011223344556677889900112233445566778899001122334455667788990011",
		PublicKey:  "020011223344556677889900112233445566778899001122334455667788990011",
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
