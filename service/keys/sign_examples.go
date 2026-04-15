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
