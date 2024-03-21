package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Define the CRU functions for the config path
func (b *backblazeB2Backend) pathConfigCRUD() *framework.Path {
	return &framework.Path{
		Pattern:         fmt.Sprintf("config/?$"),
		HelpSynopsis:    "Configure the Backblaze B2 connection.",
		HelpDescription: "Use this endpoint to set the Backblaze B2 account id, key id and key.",

		Fields: map[string]*framework.FieldSchema{
			"account_id": {
				Type:        framework.TypeString,
				Description: "The Backblaze B2 Account Id.",
			},
			"key_id": {
				Type:        framework.TypeString,
				Description: "The Backblaze B2 Key Id.",
			},
			"key": {
				Type:        framework.TypeString,
				Description: "The Backblaze B2 Key.",
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "(Optional) Key name.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigUpdate,
			},
		},
	}
}

// Read the current configuration
func (b *backblazeB2Backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account_id": c.AccountId,
			"key_id":     c.KeyId,
			"key_name":   c.KeyName,
		},
	}, nil
}

// Update the configuration
func (b *backblazeB2Backend) pathConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Update the internal configuration
	changed, err := c.Update(d)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// If we changed the configuration, store it
	if changed {
		// Make a new storage entry
		entry, err := logical.StorageEntryJSON("config", c)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JSON configuration: %w", err)
		}

		// And store it
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to persist configuration: %w", err)
		}

	}

	// Destroy any old b2client which may exist so we get a new one
	// with the next request

	b.client = nil

	return nil, nil
}
