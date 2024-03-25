package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"os"
	"testing"

	b2client "github.com/Backblaze/blazer/b2"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathConfigRotateRoot(t *testing.T) {

	if !runAcceptanceTests {
		t.SkipNow()
	}

	skipIfMissingEnvVars(t,
		envVarBackblazeB2ApplicationKeyID,
		envVarBackblazeB2ApplicationKey,
	)

	client, err := b2client.NewClient(context.Background(), os.Getenv(envVarBackblazeB2ApplicationKeyID), os.Getenv(envVarBackblazeB2ApplicationKey))

	if err != nil {
		t.Fatalf("Unable to create b2 client: %s", err)
	}

	key, err := client.CreateKey(context.Background(), "test-rotation-key", b2client.Capabilities("listKeys", "writeKeys", "deleteKeys"))

	if err != nil {
		t.Fatalf("Unable to create test rotation key: %s", err)
	}

	defer func() {
		err := key.Delete(context.Background())
		if err != nil {
			t.Errorf("Unable to delete test rotation key: %s", err)
		}
	}()

	b, s := getTestBackend(t)

	configData := map[string]interface{}{
		"application_key_id": key.ID(),
		"application_key":    key.Secret(),
	}

	err = testConfigCreate(b, s, configData)

	if err != nil {
		t.Fatalf("Cannot create config: %s", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Data:      map[string]interface{}{},
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	config, err := b.getConfig(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}

	if config.ApplicationKeyId == "" {
		t.Fatal(fmt.Errorf("application key id was empty after rotate root, it shouldn't be"))
	}

	if config.ApplicationKeyId == key.ID() {
		t.Fatal("old and new application key ids are equal after rotate-root, it shouldn't be")
	}

	if config.ApplicationKey == "" {
		t.Fatal("application key is empty, it shouldn't be")
	}

	if config.ApplicationKey == key.Secret() {
		t.Fatal("old and new application keys are equal after rotate-root, it shouldn't be")
	}

	keys, _, err := client.ListKeys(context.Background(), 1, config.ApplicationKeyId)
	for _, currentKey := range keys {
		if currentKey.ID() == config.ApplicationKeyId {
			if err = currentKey.Delete(context.Background()); err != nil {
				t.Errorf("Unable to delete rotated key: %s", err)
			}
		}
	}
}
