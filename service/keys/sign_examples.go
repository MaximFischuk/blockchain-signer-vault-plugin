package privatekeys

import "github.com/hashicorp/vault/sdk/framework"

const (
	exampleSignature = "3044022049b4b5a4f8b3c2e1d0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c702201a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
	exampleHash      = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
)

func Example200ResponseSignHash() *framework.Response {
	return &framework.Response{
		Description: "Hash signed successfully",
		Example:     SignatureResponse(exampleSignature),
	}
}

func Example200ResponseSignMessage() *framework.Response {
	return &framework.Response{
		Description: "Message hashed and signed successfully",
		Example:     SignatureResponse(exampleSignature),
	}
}

func Example200ResponseSignBatch() *framework.Response {
	return &framework.Response{
		Description: "Batch of hashes signed successfully",
		Example: SignaturesResponse([]string{
			exampleSignature,
			exampleSignature,
		}),
	}
}

func Example200ResponseSignEthereumTransaction() *framework.Response {
	return &framework.Response{
		Description: "Ethereum transaction signed successfully",
		Example: EthereumTransactionResponse(
			"0xf86c808504a817c80082520894d8da6bf26964af9d7eed9e03e53415d37aa96045880de0b6b3a76400008025a0b0f06a4f09e750ea473b30ac0d0be8cbec6e37e64be39d21dc4e1ccac4b1c7ca4a7a059a8db13c91c7c8e97b1b0587f3ea3a548645f8c0d739de5d9d90d3495b4c6e940f3",
			"0x3f44b2c3b6cf3e4c435405f6ec09c7f2a94e7f42d4ab701fb2dd4bf9266c9f3a",
		),
	}
}

func Example200ResponseSignEthereumTypedData() *framework.Response {
	return &framework.Response{
		Description: "EIP-712 typed data signed successfully",
		Example:     SignatureResponse("0x49b4b5a4f8b3c2e1d0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c71a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b1b"),
	}
}
