package b2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	ErrRoleNotFound = errors.New("role not found")
)

// A role stored in the storage backend
type Role struct {

	// Capabilities is a list of strings which reflects
	// the capabilities this key will have in B2
	Capabilities []string `json:"capabilities"`

	// KeyNamePrefix is what we prepend to the key name when we
	// create it, followed by the Vault request ID which asked
	// for the key to be made

	KeyNamePrefix string `json:"key_name_prefix"`

	// BucketName is an optional restriction to limit this key to
	// a particular bucket
	BucketName string `json:"bucket_id"`

	// NamePrefix is an optional restriction to limit which object
	// name prefixes this key can operate on
	NamePrefix string `json:"name_prefix"`

	// DefaultTTL is the TTL which will be applied to keys if no
	// TTL is requested
	DefaultTTL time.Duration `json:"default_ttl"`

	// MaxTTL is the maximum any TTL can be for this role
	MaxTTL time.Duration `json:"max_ttl"`
}

// List Roles

func (b *backend) ListRoles(ctx context.Context, s logical.Storage) ([]string, error) {
	roles, err := s.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve list of roles: %w", err)
	}

	return roles, nil
}

// Get Role

func (b *backend) GetRole(ctx context.Context, s logical.Storage, role string) (*Role, error) {
	r, err := s.Get(ctx, "roles/"+role)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve role %q: %w", role, err)
	}

	if r == nil {
		return nil, ErrRoleNotFound
	}

	var rv Role
	if err := r.DecodeJSON(&rv); err != nil {
		return nil, fmt.Errorf("unable to decode role %q: %w", role, err)
	}

	return &rv, nil
}
