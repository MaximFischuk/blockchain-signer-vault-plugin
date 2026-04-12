package service

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Example500Response() framework.Response {
	return framework.Response{
		Description: "Internal server error",
		Example: &logical.Response{
			Data: map[string]any{
				"error": "an unexpected error occurred, please try again later",
			},
		},
	}
}

func Example400Response() framework.Response {
	return framework.Response{
		Description: "Bad request",
		Example: &logical.Response{
			Data: map[string]any{
				"error": "error message bad request",
			},
		},
	}
}

func Example404Response() framework.Response {
	return framework.Response{
		Description: "Not found",
		Example: &logical.Response{
			Data: map[string]any{
				"error": "error message resource not found",
			},
		},
	}
}
