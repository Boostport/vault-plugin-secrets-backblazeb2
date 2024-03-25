package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	applicationKeyID = "0012fa8nbg613rd0000046326"
	applicationKey   = "A026v4BE4xU4ZJuzGSsv224GqhWkTLj"
)

func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {

		t.Run("Create Configuration - empty", func(t *testing.T) {
			err := testConfigCreate(b, reqStorage, map[string]interface{}{
				"application_key_id": "",
				"application_key":    "",
			})
			assert.Error(t, err)
		})

		t.Run("Create Configuration - empty application key", func(t *testing.T) {
			err := testConfigCreate(b, reqStorage, map[string]interface{}{
				"application_key_id": applicationKeyID,
				"application_key":    "",
			})
			assert.Error(t, err)
		})

		t.Run("Create Configuration - empty application key id", func(t *testing.T) {
			err := testConfigCreate(b, reqStorage, map[string]interface{}{
				"application_key_id": "",
				"application_key":    applicationKey,
			})
			assert.Error(t, err)
		})

		t.Run("Create Configuration - pass", func(t *testing.T) {
			err := testConfigCreate(b, reqStorage, map[string]interface{}{
				"application_key_id": applicationKeyID,
				"application_key":    applicationKey,
			})
			assert.NoError(t, err)
		})

		t.Run("Read Configuration - pass", func(t *testing.T) {
			err := testConfigRead(b, reqStorage, map[string]interface{}{
				"application_key_id": applicationKeyID,
			})
			assert.NoError(t, err)
		})

		t.Run("Update Configuration - pass", func(t *testing.T) {
			err := testConfigUpdate(b, reqStorage, map[string]interface{}{
				"application_key_id": "updated_application_key_id",
				"application_key":    "updated_application_key",
			})
			assert.NoError(t, err)
		})

		t.Run("Read Updated Configuration - pass", func(t *testing.T) {
			err := testConfigRead(b, reqStorage, map[string]interface{}{
				"application_key_id": "updated_application_key_id",
			})
			assert.NoError(t, err)
		})

		t.Run("Delete Configuration - pass", func(t *testing.T) {
			err := testConfigDelete(b, reqStorage)
			assert.NoError(t, err)
		})
	})
}

func testConfigCreate(b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigDelete(b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigUpdate(b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigRead(b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}
