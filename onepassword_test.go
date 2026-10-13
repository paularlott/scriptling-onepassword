package onepassword

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/paularlott/scriptling/extlibs/secretprovider"
)

type fakeSDK struct {
	builds   *int
	resolves int
	lists    int
	vaults   []sdkRef
	items    map[string][]sdkRef
	full     map[string]*sdkItem
	getCalls int
}

// resolve answers a secret reference the way 1Password does: vault and
// item by exact name or id, field by exact id or title, no fallbacks.
func (f *fakeSDK) resolve(_ context.Context, reference string) (string, error) {
	f.resolves++
	parts := strings.SplitN(strings.TrimPrefix(reference, "op://"), "/", 3)
	if len(parts) != 3 {
		return "", errors.New("invalid secret reference")
	}
	for _, v := range f.vaults {
		if v.ID != parts[0] && v.Title != parts[0] {
			continue
		}
		for _, it := range f.items[v.ID] {
			if it.ID != parts[1] && it.Title != parts[1] {
				continue
			}
			for _, fl := range f.full[v.ID+"/"+it.ID].Fields {
				if fl.ID == parts[2] || fl.Title == parts[2] {
					return fl.Value, nil
				}
			}
		}
	}
	return "", errors.New("error resolving secret reference: no match")
}

func (f *fakeSDK) listVaults(context.Context) ([]sdkRef, error) {
	f.lists++
	return f.vaults, nil
}

func (f *fakeSDK) listItems(_ context.Context, vaultID string) ([]sdkRef, error) {
	f.lists++
	return f.items[vaultID], nil
}

func (f *fakeSDK) getItem(_ context.Context, vaultID, itemID string) (*sdkItem, error) {
	f.getCalls++
	item, ok := f.full[vaultID+"/"+itemID]
	if !ok {
		return nil, errors.New("no such item")
	}
	return item, nil
}

func withFake(t *testing.T) *fakeSDK {
	t.Helper()
	fake := &fakeSDK{
		builds: new(int),
		vaults: []sdkRef{{ID: "vlt1", Title: "Engineering"}},
		items: map[string][]sdkRef{
			"vlt1": {{ID: "itm1", Title: "Database"}, {ID: "itm2", Title: "Notes Only"}, {ID: "itm3", Title: "API"}},
		},
		full: map[string]*sdkItem{
			"vlt1/itm1": {Title: "Database", Fields: []sdkField{
				{ID: "username", Title: "username", Value: "admin"},
				{ID: "password", Title: "password", Value: "hunter2"},
				{ID: "abc123", Title: "Port", Value: "5432"},
			}},
			"vlt1/itm2": {Title: "Notes Only", Notes: "just notes"},
			"vlt1/itm3": {Title: "API", Fields: []sdkField{{ID: "credential", Title: "credential", Value: "key-123"}}},
		},
	}
	previous := newOnePasswordSDK
	newOnePasswordSDK = func(_ context.Context, token string) (onePasswordSDK, error) {
		*fake.builds++
		return fake, nil
	}
	t.Cleanup(func() { newOnePasswordSDK = previous })
	return fake
}

func newTestProvider(t *testing.T, defaultField string) secretprovider.Provider {
	t.Helper()
	p, err := secretprovider.NewProvider(secretprovider.Config{
		Provider:            "onepassword",
		ServiceAccountToken: "ops_test",
		DefaultField:        defaultField,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestResolveMatchesConnectSemantics(t *testing.T) {
	fake := withFake(t)
	p := newTestProvider(t, "")
	ctx := context.Background()

	tests := []struct {
		path, field, want string
	}{
		{"Engineering/Database", "", "hunter2"},       // default field
		{"Engineering/Database", "username", "admin"}, // by id
		{"Engineering/Database", "PORT", "5432"},      // by label, case-insensitive
		{"vlt1/itm1", "password", "hunter2"},          // vault and item by id
		{"Engineering/Notes Only", "", "just notes"},  // default falls back to notes
		{"Engineering/Notes Only", "notesPlain", "just notes"},
		{"Engineering/API", "", "key-123"}, // default falls back to credential
	}
	for _, tt := range tests {
		got, err := p.Resolve(ctx, tt.path, tt.field)
		if err != nil || got != tt.want {
			t.Errorf("Resolve(%q, %q) = %q, %v; want %q", tt.path, tt.field, got, err, tt.want)
		}
	}

	if *fake.builds != 1 {
		t.Fatalf("SDK client built %d times, want once", *fake.builds)
	}
}

func TestResolveErrors(t *testing.T) {
	withFake(t)
	p := newTestProvider(t, "")
	ctx := context.Background()

	for _, tt := range []struct{ path, field, want string }{
		{"Engineering", "", "path must be vault/item"},
		{"Missing/Database", "", `vault "Missing" not found`},
		{"Engineering/Missing", "", `item "Missing" not found`},
		{"Engineering/Database", "nope", `field "nope" not found`},
	} {
		_, err := p.Resolve(ctx, tt.path, tt.field)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Resolve(%q, %q) err = %v, want %q", tt.path, tt.field, err, tt.want)
		}
	}
}

func TestList(t *testing.T) {
	withFake(t)
	p := newTestProvider(t, "")
	ctx := context.Background()

	items, err := p.List(ctx, "Engineering")
	if err != nil || !reflect.DeepEqual(items, []string{"Database", "Notes Only", "API"}) {
		t.Fatalf("List(vault) = %v, %v", items, err)
	}
	fields, err := p.List(ctx, "Engineering/Database")
	if err != nil || !reflect.DeepEqual(fields, []string{"username", "password", "Port"}) {
		t.Fatalf("List(vault/item) = %v, %v", fields, err)
	}
}

func TestConfigValidation(t *testing.T) {
	withFake(t)

	if _, err := secretprovider.NewProvider(secretprovider.Config{
		Provider: "onepassword", ServiceAccountToken: "ops_x", Address: "http://connect:8080", Token: "t",
	}); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both modes: err = %v", err)
	}
	if _, err := secretprovider.NewProvider(secretprovider.Config{
		Provider: "onepassword", ServiceAccountToken: "not-a-token",
	}); err == nil || !strings.Contains(err.Error(), "ops_") {
		t.Fatalf("bad token: err = %v", err)
	}
}

func TestResolveIsOneRequest(t *testing.T) {
	fake := withFake(t)
	p := newTestProvider(t, "")
	ctx := context.Background()

	if v, err := p.Resolve(ctx, "Engineering/Database", "username"); err != nil || v != "admin" {
		t.Fatalf("Resolve = %q, %v", v, err)
	}
	if fake.resolves != 1 || fake.lists != 0 || fake.getCalls != 0 {
		t.Fatalf("resolves=%d lists=%d gets=%d, want a single resolve", fake.resolves, fake.lists, fake.getCalls)
	}

	// The default field falls back through the full lookup only when the
	// direct reference misses.
	if v, err := p.Resolve(ctx, "Engineering/API", ""); err != nil || v != "key-123" {
		t.Fatalf("fallback Resolve = %q, %v", v, err)
	}
	if fake.resolves != 2 || fake.lists == 0 {
		t.Fatalf("fallback: resolves=%d lists=%d, want the full lookup after the miss", fake.resolves, fake.lists)
	}
}
