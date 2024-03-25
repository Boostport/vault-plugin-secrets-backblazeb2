package vault_plugin_secrets_backblazeb2

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	envVarRunAccTests                 = "VAULT_ACC"
	envVarBackblazeB2ApplicationKeyID = "TEST_BACKBLAZEB2_APPLICATION_KEY_ID"
	envVarBackblazeB2ApplicationKey   = "TEST_BACKBLAZEB2_APPLICATION_KEY"
)

func getTestBackend(tb testing.TB) (*backblazeB2Backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory("test")(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*backblazeB2Backend), config.StorageView
}

// runAcceptanceTests will separate unit tests from
// acceptance tests, which will make active requests
// to your target API.
var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

// testCloudEnv creates an object to store and track testing environment
// resources.
type testCloudEnv struct {
	ApplicationKeyID string
	ApplicationKey   string

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	// SecretToken tracks the API token, for checking rotations.
	SecretToken string

	// Tracks the generated application keys, to make sure we clean up.
	ApplicationKeyIDs []string
}

// AddConfig adds the configuration to the test backend.
// Make sure data includes all of the configuration
// attributes you need and the `config` path!
func (e *testCloudEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"application_key_id": e.ApplicationKeyID,
			"application_key":    e.ApplicationKey,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testCloudEnv) AddRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"capabilities": []string{"listFiles", "readFiles", "writeFiles"},
		},
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, resp)
	require.Nil(t, err)
}

func (e *testCloudEnv) ReadApplicationKey(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Secret.InternalData["application_key_id"])
	require.NotNil(t, resp.Secret)
	require.NotEmpty(t, resp.Data["application_key_id"])
	require.NotEmpty(t, resp.Data["application_key"])

	if e.SecretToken != "" {
		require.NotEqual(t, e.SecretToken, resp.Data["application_key"])
	}

	e.SecretToken = resp.Data["application_key"].(string)

	e.ApplicationKeyIDs = append(e.ApplicationKeyIDs, resp.Secret.InternalData["application_key_id"].(string))
}

func (e *testCloudEnv) VerifyNumberOfIssuedCredentials(t *testing.T) {
	if len(e.ApplicationKeyIDs) != 2 {
		t.Fatalf("expected 2 application keys, got: %d", len(e.ApplicationKeyIDs))
	}
}

func (e *testCloudEnv) CleanupCreds(t *testing.T) {

	if len(e.ApplicationKeyIDs) <= 0 {
		return
	}

	b := e.Backend.(*backblazeB2Backend)
	client, err := b.getB2Client(e.Context, e.Storage)
	if err != nil {
		t.Fatal("error getting client")
	}

	for _, id := range e.ApplicationKeyIDs {
		keys, _, err := client.ListKeys(context.Background(), 1, id)
		if err != nil {
			t.Fatalf("error listing keys: %s", err)
		}

		// We should only get one, but verify
		for _, key := range keys {
			if key.ID() == id {
				err = key.Delete(context.Background())
				if err != nil {
					t.Fatalf("error deleting key: %s", err)
				}
				break
			}
		}
	}
}

func skipIfMissingEnvVars(t *testing.T, envVars ...string) {
	t.Helper()
	for _, envVar := range envVars {
		if os.Getenv(envVar) == "" {
			t.Skipf("Missing env variable: [%s] - skipping test", envVar)
		}
	}
}
