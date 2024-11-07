package vault_plugin_secrets_backblazeb2

import (
	"context"
	"errors"
	"fmt"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const b2KeyType = "b2_application_key"

func (b *backblazeB2Backend) b2ApplicationsKey() *framework.Secret {
	return &framework.Secret{
		Type: b2KeyType,
		Fields: map[string]*framework.FieldSchema{
			"application_key_id": {
				Type:        framework.TypeString,
				Description: "Application Key ID",
			},
			"application_key": {
				Type:        framework.TypeString,
				Description: "Application Key",
			},
		},
		Revoke: b.b2ApplicationKeyRevoke,
		Renew:  b.b2ApplicationKeyRenew,
	}
}

func (b *backblazeB2Backend) b2ApplicationKeyCreate(ctx context.Context, s logical.Storage,
	keyName string, role backblazeB2RoleEntry) (*b2client.Key, error) {

	client, err := b.getB2Client(ctx, s)
	if err != nil {
		return nil, err
	}

	// Set key options
	var keyOpts []b2client.KeyOption

	// Set capabilities
	keyOpts = append(keyOpts, b2client.Capabilities(role.Capabilities...))

	// If bucketName is set, look up the bucket and create that way.
	// Else, create the key directly. This is how Blazer does it.
	if role.BucketName != "" {
		bucket, err := client.Bucket(ctx, role.BucketName)
		if err != nil {
			return nil, err
		}
		// Set prefix if asked for
		if role.NamePrefix != "" {
			keyOpts = append(keyOpts, b2client.Prefix(role.NamePrefix))
		}

		newKey, err := bucket.CreateKey(ctx, keyName, keyOpts...)
		if err != nil {
			return nil, err
		}
		return newKey, nil

	} else {
		newKey, err := client.CreateKey(ctx, keyName, keyOpts...)
		if err != nil {
			return nil, err
		}
		return newKey, nil
	}

}

func (b *backblazeB2Backend) b2ApplicationKeyRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	client, err := b.getB2Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Get applicationKeyId from secret internal data
	applicationKeyIdRaw, ok := req.Secret.InternalData["application_key_id"]

	if !ok {
		return nil, fmt.Errorf("secret is missing internal application_key_id")
	}

	applicationKeyId, ok := applicationKeyIdRaw.(string)
	if !ok {
		return nil, fmt.Errorf("internal application_key_id is not a string")
	}

	// Find key
	var applicationKey *b2client.Key
	keys, _, err := client.ListKeys(ctx, 1, applicationKeyId)
	if err != nil {
		return nil, err
	}

	// We should only get one, but verify
	for _, key := range keys {
		if key.ID() == applicationKeyId {
			applicationKey = key
			break
		}
	}

	if applicationKey == nil {
		return nil, fmt.Errorf("cannot find key in b2")
	}

	if err := applicationKey.Delete(ctx); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backblazeB2Backend) b2ApplicationKeyRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
