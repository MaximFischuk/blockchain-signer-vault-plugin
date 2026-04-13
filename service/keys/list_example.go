package privatekeys

import (
	"github.com/hashicorp/vault/sdk/framework"
)

func Example200ResponseKeysList() *framework.Response {
	return &framework.Response{
		Description: "Keys listed successfully",
		Example: KeysListResponse(
			[]string{
				"key-123",
				"key-456",
				"key-789",
			},
		),
	}
}
