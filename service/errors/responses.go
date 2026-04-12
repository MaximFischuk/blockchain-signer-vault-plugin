package errors

import "github.com/hashicorp/vault/sdk/logical"

// ErrorResponse maps a client-caused error (validation, bad input) to an
// HTTP 400 response. The error is surfaced in the response body; the second
// return value is nil so Vault does not additionally wrap it as a 500.
func ErrorResponse(err error) (*logical.Response, error) {
	return logical.ErrorResponse(err.Error()), nil
}

// ServerErrorResponse maps a server-caused error (storage failure, entropy
// exhaustion, …) to an HTTP 500 response. Returning a non-nil error as the
// second value is the canonical Vault SDK way to signal an internal fault.
func ServerErrorResponse(err error) (*logical.Response, error) {
	return nil, err
}
