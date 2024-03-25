package vault_plugin_secrets_backblazeb2

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Define the R functions for the keys path
func (b *backblazeB2Backend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern:      "creds/" + framework.GenericNameRegex("role"),
		HelpSynopsis: "Provision an application key for this role.",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of role",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyRead,
			},
		},
	}
}

// Read a new key
func (b *backblazeB2Backend) pathKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("role").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error fetching role: %w", err)
	}

	if role == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	name := uuid.New().String()
	newKeyName := fmt.Sprintf("%s%s", role.KeyNamePrefix, name)

	// Generate key
	newKey, err := b.b2ApplicationKeyCreate(ctx, req.Storage, newKeyName, *role)
	if err != nil {
		return nil, err
	}

	// Gin up response
	resp := b.Secret(b2KeyType).Response(map[string]interface{}{
		"application_key_id": newKey.ID(),
		"application_key":    newKey.Secret(),
	}, map[string]interface{}{
		"application_key_id": newKey.ID(),
		"role":               roleName,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}
