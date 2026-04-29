package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Example200ResponseKeyDelete() *framework.Response {
	return &framework.Response{
		Description: "Key deleted successfully",
		Example:     &logical.Response{},
	}
}
