package vault_plugin_secrets_backblazeb2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backblazeB2RoleEntry struct {

	// Capabilities is a list of strings which reflects
	// the capabilities this key will have in B2
	Capabilities []string `json:"capabilities"`

	// KeyNamePrefix is what we prepend to the key name when we
	// create it, followed by the Vault request ID which asked
	// for the key to be made
	KeyNamePrefix string `json:"key_name_prefix"`

	// BucketName is an optional restriction to limit this key to
	// a particular bucket
	BucketName string `json:"bucket_name"`

	// NamePrefix is an optional restriction to limit which object
	// name prefixes this key can operate on
	NamePrefix string `json:"name_prefix"`

	// DefaultTTL is the TTL which will be applied to keys if no
	// TTL is requested
	TTL time.Duration `json:"ttl"`

	// MaxTTL is the maximum any TTL can be for this role
	MaxTTL time.Duration `json:"max_ttl"`
}

// List the defined roles
func (b *backblazeB2Backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern:      "roles/?",
		HelpSynopsis: "List configured roles.",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRolesList,
			},
		},
	}
}

// pathRolesList lists the currently defined roles
func (b *backblazeB2Backend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve list of roles: %w", err)
	}

	return logical.ListResponse(roles), nil
}

// Define the CRUD functions for the roles path
func (b *backblazeB2Backend) pathRolesCRUD() *framework.Path {
	return &framework.Path{
		Pattern:         "roles/" + framework.GenericNameRegex("role"),
		HelpSynopsis:    "Configure a Backblaze B2 role.",
		HelpDescription: "Use this endpoint to set the polices for generated keys in this role.",

		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Role name",
				Required:    true,
			},
			"capabilities": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of capabilities",
				Required:    true,
			},
			"key_name_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix for key names generated by this role",
				Default:     "vault-",
				Required:    false,
			},
			"bucket_name": {
				Type:        framework.TypeString,
				Description: "Optional bucket name on which to restrict this key",
				Required:    false,
			},
			"name_prefix": {
				Type:        framework.TypeString,
				Description: "Optional prefix to further restrict access to files whose names start with the prefix",
				Required:    false,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Optional default TTL to apply to keys",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Optional maximum TTL to apply to keys",
			},
		},

		ExistenceCheck: b.pathRoleExistsCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},
	}
}

// pathRoleExistsCheck checks to see if a role exists
func (b *backblazeB2Backend) pathRoleExistsCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("role").(string))
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

// pathRoleRead reads information on a current role
func (b *backblazeB2Backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("role").(string))

	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	roleData := map[string]interface{}{
		"key_name_prefix": entry.KeyNamePrefix,
		"capabilities":    entry.Capabilities,
		"bucket_name":     entry.BucketName,
		"name_prefix":     entry.NamePrefix,
		"ttl":             entry.TTL.Seconds(),
		"max_ttl":         entry.MaxTTL.Seconds(),
	}

	return &logical.Response{
		Data: roleData,
	}, nil
}

// pathRoleWrite creates/updates a role entry
func (b *backblazeB2Backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get("role").(string)

	r, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	roleExists := true

	if r == nil {
		roleExists = false
		r = &backblazeB2RoleEntry{}
	}

	keys := []string{"key_name_prefix", "bucket_name", "name_prefix"}

	for _, key := range keys {

		v, ok := d.GetOk(key)

		if !ok && roleExists {
			continue
		}

		nv := ""

		if ok {
			nv = strings.TrimSpace(v.(string))
		} else if !roleExists {
			v := d.GetDefaultOrZero(key)
			nv = strings.TrimSpace(v.(string))
		}

		switch key {
		case "name_prefix":
			r.NamePrefix = nv
		case "bucket_name":
			r.BucketName = nv
		case "key_name_prefix":
			r.KeyNamePrefix = nv
		}
	}

	if r.NamePrefix != "" && r.BucketName == "" {
		return logical.ErrorResponse("bucket_name must be set if name_prefix is set"), nil
	}

	// Handle TTLs
	createOperation := req.Operation == logical.CreateOperation

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		r.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		r.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		r.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		r.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if r.MaxTTL != 0 && r.TTL > r.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// Handle capabilities
	if c, ok := d.GetOk("capabilities"); ok {
		r.Capabilities = c.([]string)
	}

	if len(r.Capabilities) <= 0 {
		return logical.ErrorResponse("capabilities must be set"), nil
	}

	entry, err := logical.StorageEntryJSON("roles/"+role, &r)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write entry to storage: %w", err)
	}

	return nil, nil
}

// pathRoleDelete deletes a role
func (b *backblazeB2Backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role"), nil
	}

	if err := req.Storage.Delete(ctx, "roles/"+roleName); err != nil {
		return nil, fmt.Errorf("failed to delete role from storage: %w", err)
	}

	return nil, nil
}

func (b *backblazeB2Backend) getRole(ctx context.Context, s logical.Storage, role string) (*backblazeB2RoleEntry, error) {
	if role == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "roles/"+role)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve role %q: %w", role, err)
	}

	if entry == nil {
		return nil, nil
	}

	var rv backblazeB2RoleEntry
	if err := entry.DecodeJSON(&rv); err != nil {
		return nil, fmt.Errorf("unable to decode role %q: %w", role, err)
	}

	return &rv, nil
}