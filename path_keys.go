package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Define the R functions for the keys path
func (b *backblazeB2Backend) pathKeysRead() *framework.Path {
	return &framework.Path{
		Pattern:      fmt.Sprintf("keys/" + framework.GenericNameRegex("role")),
		HelpSynopsis: "Provision a key for this role.",

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of role",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Lifetime of applicationKey in seconds",
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

	role, err := b.GetRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error fetching role: %w", err)
	}

	config, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error fetching config: %w", err)
	}

	newKeyName := fmt.Sprintf("%s%s", role.KeyNamePrefix, req.ID)

	// Calculate lifetime
	reqTTL := time.Duration(d.Get("ttl").(int)) * time.Second
	ttl, _, err := framework.CalculateTTL(b.System(), 0, role.DefaultTTL, reqTTL, role.MaxTTL, 0, time.Time{})
	if err != nil {
		return nil, err
	}

	// Add a small buffer so key expires after lease does
	realttl := ttl + (time.Second * 5)

	// Generate key
	newKey, err := b.b2ApplicationKeyCreate(ctx, req.Storage, newKeyName, config.AccountId, role.Capabilities, role.BucketName, role.NamePrefix, realttl)
	if err != nil {
		return nil, err
	}

	// Gin up response
	resp := b.Secret(b2KeyType).Response(map[string]interface{}{
		// Returned secret
		"keyName":          newKey.Name(),
		"applicationKeyId": newKey.ID(),
		"applicationKey":   newKey.Secret(),
		"capabilities":     newKey.Capabilities(),
		"accountId":        config.AccountId,
		"bucketName":       role.BucketName,
		"namePrefix":       role.NamePrefix,
	}, map[string]interface{}{
		// Internal Data
		"applicationKeyId": newKey.ID(),
		"accountId":        config.AccountId,
	})

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}
