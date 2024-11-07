package vault_plugin_secrets_backblazeb2

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

type backblazeB2Config struct {
	ApplicationKeyId string `json:"application_key_id"`
	ApplicationKey   string `json:"application_key"`
}

// Define the CRU functions for the config path
func (b *backblazeB2Backend) pathConfigCRUD() *framework.Path {
	return &framework.Path{
		Pattern:         "config",
		HelpSynopsis:    "Configure the Backblaze B2 connection.",
		HelpDescription: "Use this endpoint to set the Backblaze B2 key id and key.",

		Fields: map[string]*framework.FieldSchema{
			"application_key_id": {
				Type:        framework.TypeString,
				Description: "The Backblaze B2 application key id",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Application Key ID",
					Sensitive: false,
				},
			},
			"application_key": {
				Type:        framework.TypeString,
				Description: "The Backblaze B2 application key",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Application Key",
					Sensitive: true,
				},
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
	}
}
func (b *backblazeB2Backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// Read the current configuration
func (b *backblazeB2Backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"application_key_id": config.ApplicationKeyId,
		},
	}, nil
}

// Update the configuration
func (b *backblazeB2Backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(backblazeB2Config)
	}

	if applicationKeyID, ok := data.GetOk("application_key_id"); ok {
		config.ApplicationKeyId = applicationKeyID.(string)
	}

	if applicationKey, ok := data.GetOk("application_key"); ok {
		config.ApplicationKey = applicationKey.(string)
	}

	if config.ApplicationKeyId == "" || config.ApplicationKey == "" {
		return nil, errors.New("both application_key_id and application_key must be set")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

func (b *backblazeB2Backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func (b *backblazeB2Backend) getConfig(ctx context.Context, s logical.Storage) (*backblazeB2Config, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error reading mount configuration: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	config := new(backblazeB2Config)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}
