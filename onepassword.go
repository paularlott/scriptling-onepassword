// Package onepassword adds 1Password service account support to
// Scriptling's onepassword secret provider. Import it for its side effect:
//
//	import _ "github.com/paularlott/scriptling-onepassword"
//
// A provider config with service_account_token then resolves through the
// 1Password Go SDK instead of 1Password Connect. It lives outside Scriptling
// because the SDK is large (about 14 MB); only binaries that import it link
// it.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	sdk "github.com/1password/onepassword-sdk-go"
	"github.com/paularlott/scriptling/build"
	"github.com/paularlott/scriptling/extlibs/secretprovider"
)

// IntegrationName and IntegrationVersion identify the integration to
// 1Password. Embedding applications may set them before first use.
var (
	IntegrationName    = "Scriptling"
	IntegrationVersion = build.Version
)

func init() {
	secretprovider.RegisterOnePasswordServiceAccount(func(cfg secretprovider.Config) (secretprovider.Provider, error) {
		return New(cfg)
	})
}

// Provider resolves secrets with a 1Password service account through the
// 1Password Go SDK — no Connect server. Paths and fields follow the Connect
// provider (vault/item by name or id, the same field matching and
// default-field fallbacks), so switching a provider from Connect to a
// service account needs no script changes.
type Provider struct {
	token        string
	defaultField string

	mu     sync.Mutex
	client onePasswordSDK
}

// onePasswordSDK is the slice of the SDK the provider uses, so tests can
// swap the 1Password client out.
type onePasswordSDK interface {
	resolve(ctx context.Context, reference string) (string, error)
	listVaults(ctx context.Context) ([]sdkRef, error)
	listItems(ctx context.Context, vaultID string) ([]sdkRef, error)
	getItem(ctx context.Context, vaultID, itemID string) (*sdkItem, error)
}

type sdkRef struct {
	ID    string
	Title string
}

type sdkItem struct {
	Title  string
	Fields []sdkField
	Notes  string
}

type sdkField struct {
	ID    string
	Title string
	Value string
}

// newOnePasswordSDK builds the SDK client for a service account token. The
// client is built on first use, not at startup: building it loads the SDK
// core and signs in to 1Password, which must not hold up or fail boot.
var newOnePasswordSDK = func(ctx context.Context, token string) (onePasswordSDK, error) {
	client, err := sdk.NewClient(ctx,
		sdk.WithServiceAccountToken(token),
		sdk.WithIntegrationInfo(IntegrationName, IntegrationVersion),
	)
	if err != nil {
		return nil, err
	}
	return &sdkClient{client: client}, nil
}

// New creates a 1Password service account provider from cfg.
func New(cfg secretprovider.Config) (*Provider, error) {
	if cfg.Address != "" || cfg.Token != "" {
		return nil, fmt.Errorf("onepassword secret provider: use either service_account_token, or address and token for 1Password Connect, not both")
	}
	if !strings.HasPrefix(cfg.ServiceAccountToken, "ops_") {
		return nil, fmt.Errorf("onepassword secret provider: service_account_token is not a 1Password service account token (expected ops_...)")
	}

	provider := &Provider{
		token:        cfg.ServiceAccountToken,
		defaultField: cfg.DefaultField,
	}
	if provider.defaultField == "" {
		provider.defaultField = "password"
	}
	return provider, nil
}

func splitPath(path string) (string, string, error) {
	path = strings.Trim(path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("onepassword: path must be vault/item, got %q", path)
	}
	return parts[0], parts[1], nil
}

func (p *Provider) ID() string {
	return "onepassword"
}

func (p *Provider) sdk(ctx context.Context) (onePasswordSDK, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client == nil {
		client, err := newOnePasswordSDK(ctx, p.token)
		if err != nil {
			return nil, fmt.Errorf("onepassword: %w", err)
		}
		p.client = client
	}
	return p.client, nil
}

func (p *Provider) Resolve(ctx context.Context, path, field string) (string, error) {
	vaultRef, itemRef, err := splitPath(path)
	if err != nil {
		return "", err
	}
	if field == "" {
		field = p.defaultField
	}

	client, err := p.sdk(ctx)
	if err != nil {
		return "", err
	}

	// One request: 1Password resolves the vault, item and field names
	// itself. A secret reference can't apply the default-field fallbacks or
	// say which part was missing, so a failure is retried with the full
	// lookup, which does both.
	if value, err := client.resolve(ctx, "op://"+vaultRef+"/"+itemRef+"/"+field); err == nil {
		return value, nil
	} else {
		var rateLimited *sdk.RateLimitExceededError
		if errors.As(err, &rateLimited) {
			return "", fmt.Errorf("onepassword: %w", err)
		}
	}

	vaultID, err := p.resolveVault(ctx, client, vaultRef)
	if err != nil {
		return "", err
	}
	item, err := p.resolveItem(ctx, client, vaultID, itemRef)
	if err != nil {
		return "", err
	}

	value, err := p.resolveField(item, field)
	if err != nil {
		return "", fmt.Errorf("onepassword: %w", err)
	}

	return value, nil
}

// List returns the item titles in a vault, or the field names of an item
// for vault/item, as the Connect provider does.
func (p *Provider) List(ctx context.Context, path string) ([]string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, fmt.Errorf("onepassword: path must be a vault name or vault/item")
	}
	parts := strings.SplitN(path, "/", 2)

	client, err := p.sdk(ctx)
	if err != nil {
		return nil, err
	}
	vaultID, err := p.resolveVault(ctx, client, parts[0])
	if err != nil {
		return nil, err
	}

	if len(parts) == 2 && parts[1] != "" {
		item, err := p.resolveItem(ctx, client, vaultID, parts[1])
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(item.Fields))
		for _, f := range item.Fields {
			if f.Title != "" {
				names = append(names, f.Title)
			}
		}
		return names, nil
	}

	items, err := client.listItems(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("onepassword: list items in vault %q: %w", parts[0], err)
	}
	titles := make([]string, 0, len(items))
	for _, item := range items {
		titles = append(titles, item.Title)
	}
	return titles, nil
}

func (p *Provider) resolveVault(ctx context.Context, client onePasswordSDK, vaultRef string) (string, error) {
	vaults, err := client.listVaults(ctx)
	if err != nil {
		return "", fmt.Errorf("onepassword: list vaults: %w", err)
	}
	for _, v := range vaults {
		if v.ID == vaultRef || v.Title == vaultRef {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("onepassword: vault %q not found", vaultRef)
}

func (p *Provider) resolveItem(ctx context.Context, client onePasswordSDK, vaultID, itemRef string) (*sdkItem, error) {
	items, err := client.listItems(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("onepassword: list items: %w", err)
	}
	for _, item := range items {
		if item.ID == itemRef || item.Title == itemRef {
			full, err := client.getItem(ctx, vaultID, item.ID)
			if err != nil {
				return nil, fmt.Errorf("onepassword: get item %q: %w", itemRef, err)
			}
			return full, nil
		}
	}
	return nil, fmt.Errorf("onepassword: item %q not found", itemRef)
}

// resolveField matches like the Connect provider: field id or label, case
// insensitive, falling back to password, credential and the notes when the
// default field is asked for and missing.
func (p *Provider) resolveField(item *sdkItem, field string) (string, error) {
	if value, ok := matchSDKField(item, field); ok {
		return value, nil
	}

	if field == p.defaultField {
		for _, fallback := range []string{"password", "credential", "notesPlain"} {
			if fallback == field {
				continue
			}
			if value, ok := matchSDKField(item, fallback); ok {
				return value, nil
			}
		}
	}

	return "", fmt.Errorf("field %q not found in item %q", field, item.Title)
}

func matchSDKField(item *sdkItem, field string) (string, bool) {
	field = strings.ToLower(field)

	for _, f := range item.Fields {
		if (strings.ToLower(f.ID) == field || strings.ToLower(f.Title) == field) && f.Value != "" {
			return f.Value, true
		}
	}
	// Connect exposes an item's notes as the notesPlain field; the SDK
	// holds them on the item.
	if (field == "notesplain" || field == "notes") && item.Notes != "" {
		return item.Notes, true
	}
	return "", false
}

// sdkClient adapts the SDK client to onePasswordSDK. It must hold *Client
// itself: the SDK releases the client's id in a finalizer on *Client, so
// keeping only its sub-APIs fails later calls with "invalid client id" once
// the client is garbage collected.
type sdkClient struct {
	client *sdk.Client
}

func (c *sdkClient) resolve(ctx context.Context, reference string) (string, error) {
	return c.client.Secrets().Resolve(ctx, reference)
}

func (c *sdkClient) listVaults(ctx context.Context) ([]sdkRef, error) {
	vaults, err := c.client.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	refs := make([]sdkRef, 0, len(vaults))
	for _, v := range vaults {
		refs = append(refs, sdkRef{ID: v.ID, Title: v.Title})
	}
	return refs, nil
}

func (c *sdkClient) listItems(ctx context.Context, vaultID string) ([]sdkRef, error) {
	items, err := c.client.Items().List(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	refs := make([]sdkRef, 0, len(items))
	for _, item := range items {
		refs = append(refs, sdkRef{ID: item.ID, Title: item.Title})
	}
	return refs, nil
}

func (c *sdkClient) getItem(ctx context.Context, vaultID, itemID string) (*sdkItem, error) {
	item, err := c.client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return nil, err
	}
	out := &sdkItem{Title: item.Title, Notes: item.Notes}
	for _, f := range item.Fields {
		out.Fields = append(out.Fields, sdkField{ID: f.ID, Title: f.Title, Value: f.Value})
	}
	return out, nil
}
