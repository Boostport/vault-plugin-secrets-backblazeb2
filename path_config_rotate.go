package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Define the rotate path
func (b *backblazeB2Backend) pathConfigRotate() *framework.Path {
	return &framework.Path{
		Pattern:         "config/rotate-root",
		HelpSynopsis:    "Use the existing application key to generate a set a new application key",
		HelpDescription: "Use this endpoint to use the current application key to generate a new application key, and use that",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootUpdate,
			},
		},
	}
}

// Rotate the key
func (b *backblazeB2Backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Get the current b.client before we blow it away
	client, err := b.getB2Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Fetch configuration
	c, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Save the old ApplicationKeyId so we can destroy it
	oldApplicationKeyId := c.ApplicationKeyId

	// Look up the old key to get the key name
	oldKeys, _, err := b.client.ListKeys(ctx, 1, oldApplicationKeyId)
	if err != nil {
		b.Logger().Error("Error looking up previous application key", "error", err)
		return nil, fmt.Errorf("failed to look up previous application key: %w", err)
	}

	if len(oldKeys) != 1 {
		return nil, fmt.Errorf("failed to look up previous application key: expected 1 key, got %d", len(oldKeys))
	}

	oldKeyName := oldKeys[0].Name()

	// Set new key options
	var opts []b2client.KeyOption
	opts = append(opts, b2client.Capabilities("listKeys", "writeKeys", "deleteKeys"))

	// Create new key
	newKey, err := client.CreateKey(ctx, oldKeyName, opts...)
	if err != nil {
		return nil, err
	}

	c.ApplicationKeyId = newKey.ID()
	c.ApplicationKey = newKey.Secret()

	// Make a new storage entry
	entry, err := logical.StorageEntryJSON(configStoragePath, c)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JSON configuration: %w", err)
	}

	b.reset()

	// And store it
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to persist configuration: %w", err)
	}

	// Replace client
	client, err = b.getB2Client(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create new b2client: %w", err)
	}
	b.client = client

	// Destroy old key
	b.Logger().Info("Deleting previous key", "id", oldApplicationKeyId)

	// We *should* only get one, and *should* only get the
	// one we asked for, but be safe
	for _, key := range oldKeys {
		b.Logger().Debug("Deleting old key, examining", "ID", key.ID())
		if key.ID() == oldApplicationKeyId {
			if err = key.Delete(ctx); err != nil {
				b.Logger().Error("Error deleting old key", "error", err)
				return nil, fmt.Errorf("error deleting old key: %w", err)
			}
		}
	}

	return nil, nil
}
