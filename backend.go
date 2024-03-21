package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"sync"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backblazeB2Backend struct {
	*framework.Backend

	client *b2client.Client

	// We're going to have to be able to rotate the client
	// if the mount configured credentials change, use
	// this to protect it
	clientMutex sync.RWMutex
}

// Factory returns a configured instance of the B2 backend
func Factory(version string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := backend(version)
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}

		b.Logger().Info("Plugin successfully initialized")
		return b, nil
	}
}

// Backend returns a configured B2 backend
func backend(version string) *backblazeB2Backend {
	var b backblazeB2Backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "The B2 secrets backend provisions API keys for the Backblaze B2 service",

		Paths: []*framework.Path{
			// path_config.go
			// ^config
			b.pathConfigCRUD(),

			// path_config_rotate.go
			// ^config/rotate
			b.pathConfigRotate(),

			// path_roles.go
			// ^roles (LIST)
			b.pathRoles(),
			// ^roles/<role>
			b.pathRolesCRUD(),

			// path_keys.go
			// ^keys/<role>
			b.pathKeysRead(),
		},

		Secrets: []*framework.Secret{
			b.b2ApplicationsKeys(),
		},
	}

	if version != "" {
		b.Backend.RunningVersion = fmt.Sprintf("v%s", version)
	}

	b.client = (*b2client.Client)(nil)

	return &b
}
