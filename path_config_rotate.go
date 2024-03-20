package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"strings"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Define the rotate path
func (b *backend) pathConfigRotate() *framework.Path {
	return &framework.Path{
		Pattern:         fmt.Sprintf("config/rotate/?$"),
		HelpSynopsis:    "Use the existing key to generate a set a new key",
		HelpDescription: "Use this endpoint to use the current key to generate a new key, and use that",

		Fields: map[string]*framework.FieldSchema{
			"key_name": {
				Type:        framework.TypeString,
				Description: "The name for the newly generated key.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateKey,
			},
		},
	}
}

// Rotate the key
func (b *backend) pathRotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Get the current b.client before we blow it away
	client, err := b.getB2Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Fetch configuration
	c, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Save the old KeyId so we can destroy it
	oldKeyId := c.KeyId

	// Set new key options
	var opts []b2client.KeyOption
	opts = append(opts, b2client.Capabilities("listKeys", "writeKeys", "deleteKeys"))

	// Set key_name
	var newKeyName string
	if v, ok := d.GetOk("key_name"); ok {
		newKeyName = strings.TrimSpace(v.(string))
	} else {
		newKeyName = fmt.Sprintf("%s-%s", "vault-root-key", req.ID)
	}

	// Create new key

	newKey, err := client.CreateKey(ctx, newKeyName, opts...)
	if err != nil {
		return nil, err
	}

	// Gin up a FieldData to pass to Update
	nd := &framework.FieldData{
		Schema: map[string]*framework.FieldSchema{
			"key_id":   {Type: framework.TypeString},
			"key":      {Type: framework.TypeString},
			"key_name": {Type: framework.TypeString},
		},
		Raw: map[string]interface{}{
			"key_id":   newKey.ID(),
			"key":      newKey.Secret(),
			"key_name": newKey.Name(),
		},
	}

	// Update the internal configuration
	changed, err := c.Update(nd)
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

	// Replace client

	client, err = b.getB2Client(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create new b2client: %w", err)
	}
	b.client = client

	// Destroy old key
	b.Logger().Info("Deleting previous key", "id", oldKeyId)

	// Have to look up old key first --- there's no way in blazer to
	// "instantiate" a key knowing the keyId, although that's all
	// Delete is going to need to delete the key
	oldKeys, _, err := b.client.ListKeys(ctx, 1, oldKeyId)
	if err != nil {
		b.Logger().Error("Error looking up previous key", "error", err)
		return nil, fmt.Errorf("failed to look up previous key: %w", err)
	}

	// We *should* only get one, and *should* only get the
	// one we asked for, but be safe
	for _, key := range oldKeys {
		b.Logger().Debug("Deleting old key, examining", "ID", key.ID())
		if key.ID() == oldKeyId {
			if err = key.Delete(ctx); err != nil {
				b.Logger().Error("Error deleting old key", "error", err)
				return nil, fmt.Errorf("error deleting old key: %w", err)
			}
		}
	}

	return nil, nil
}
