package privatekeys

import "github.com/hashicorp/vault/sdk/framework"

func Example200ResponseKeyRead() *framework.Response {
	return &framework.Response{
		Description: "Key read successfully",
		Example:     KeyReadResponse(ExampleKey()),
	}
}
