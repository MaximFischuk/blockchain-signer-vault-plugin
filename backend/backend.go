package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	privatekeys "github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/service/keys"
	"github.com/maximfischuk/blockchain-signer-hashicorp-vault-plugin/version"
)

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}

	b.Logger().Info("Blockchain Signer Vault Plugin backend factory initialized successfully")
	return b, nil
}

type backend struct {
	*framework.Backend
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	keysController := privatekeys.NewController(c.Logger)

	b.Backend = &framework.Backend{
		Help:        "Blockchain Signer Vault Plugin",
		BackendType: logical.TypeLogical,
		Secrets:     []*framework.Secret{},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"wallets/",
				"keys/",
			},
		},
		Paths: framework.PathAppend(
			keysController.Paths(),
		),
		RunningVersion: "v" + version.Version,
	}

	return &b
}
