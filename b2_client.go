package vault_plugin_secrets_backblazeb2

import (
	"context"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/logical"
)

// Call this to set a new b2client in the backend.
func (b *backblazeB2Backend) newB2Client(ctx context.Context, applicationKeyID string, applicationKey string) error {

	b.Logger().Debug("newB2Client", "applicationKeyID", applicationKeyID)

	client, err := b2client.NewClient(ctx, applicationKeyID, applicationKey)

	if err != nil {
		b.Logger().Error("Error getting new b2 client", "error", err)
		return err
	}

	b.Logger().Debug("Getting clientMutex.Lock")
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = client
	b.Logger().Debug("Set new b.client, unlocking and returning")
	return nil
}

// Convenience function to get the b2client
func (b *backblazeB2Backend) getB2Client(ctx context.Context, s logical.Storage) (*b2client.Client, error) {
	b.Logger().Debug("getB2Client, getting clientMutex.RLock")
	b.lock.RLock()
	if b.client != nil {
		b.Logger().Debug("have client already, unlocking and returning")
		b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	// We don't have a current client, look up the id and key
	// from the current configuration and create a new client

	b.Logger().Info("Getting new b2 client, fetching config")
	c, err := b.getConfig(ctx, s)
	if err != nil {
		b.Logger().Error("Error fetching configuration to make new b2client", "error", err)
		return nil, err
	}

	if c.ApplicationKeyId == "" {
		b.Logger().Error("KeyID not set when trying to create new client")
		return nil, err
	}

	if c.ApplicationKey == "" {
		b.Logger().Error("Key not set when trying to create new client")
		return nil, err
	}

	if err := b.newB2Client(ctx, c.ApplicationKeyId, c.ApplicationKey); err != nil {
		return nil, err
	}

	return b.client, nil
}
