package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestBackendFactory(t *testing.T) {
	backend, err := Factory(context.Background(), &logical.BackendConfig{})

	assert.NoError(t, err)
	assert.NotEmpty(t, backend)
}
