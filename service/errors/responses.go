package errors

import "github.com/hashicorp/vault/sdk/logical"

func ErrorResponse(err error) (*logical.Response, error) {
	return logical.ErrorResponse(err.Error()), nil
}
