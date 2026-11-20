package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestClientCredentialsLifecycle(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	vault, err := db.CreateVault(ctx, "enrollment")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var reject atomic.Bool
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.Method != "POST" || r.FormValue("grant_type") != "client_credentials" || r.FormValue("client_id") != "client" || r.FormValue("client_secret") != "test-secret" || r.FormValue("scope") != "auth_keys" || r.Form.Has("refresh_token") {
			t.Error("unexpected token request")
		}
		n := requests.Add(1)
		if reject.Load() {
			http.Error(w, "test-secret", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"access_token":"fixture-%d","expires_in":3600}`, n)
	}))
	defer endpoint.Close()
	srv := newTestServer(withStore(db))
	previous := oauth.TokenClient
	oauth.TokenClient = endpoint.Client()
	defer func() { oauth.TokenClient = previous }()
	ctx = context.WithValue(ctx, sessionContextKey, &store.Session{VaultID: vault.ID, VaultRole: "member"})
	setup := func() *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"vault":"enrollment","key":"TS","grant_type":"client_credentials","client_id":"client","client_secret":"test-secret","scopes":"auth_keys","token_url":%q}`, endpoint.URL)
		req := httptest.NewRequestWithContext(ctx, "POST", "/v1/credentials/oauth/connect", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handleOAuthConnect(rec, req)
		return rec
	}
	if rec := setup(); rec.Code != 200 || strings.Contains(rec.Body.String(), "fixture-") {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	cfg, err := db.GetCredentialOAuth(ctx, vault.ID, "TS")
	if err != nil || cfg.GrantType != oauth.ClientCredentialsGrant || len(cfg.RefreshTokenCT) != 0 || cfg.TokenExpiresAt == nil {
		t.Fatalf("invalid persisted configuration: %v", err)
	}
	_, err = db.SetBrokerConfig(ctx, vault.ID, `[{"name":"api","host":"resource.example","auth":{"type":"bearer","token":"TS"}}]`)
	if err != nil {
		t.Fatal(err)
	}
	provider := brokercore.NewStoreCredentialProvider(credentialStoreAdapter{db}, srv.encKey)
	provider.OAuthStore = db
	provider.Refresher = oauth.NewRefresher()
	inject := func() (*brokercore.InjectResult, error) {
		return provider.Inject(ctx, vault.ID, "resource.example", 443, "/")
	}
	checkBearer := func(want string) {
		t.Helper()
		got, err := inject()
		if err != nil || got.Headers["Authorization"] != "Bearer "+want {
			t.Fatalf("wrong injected bearer: %v", err)
		}
	}
	checkBearer("fixture-1")
	expire := func() {
		cred, err := db.GetCredential(ctx, vault.ID, "TS")
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(-time.Hour)
		if err := db.UpdateCredentialOAuthTokens(ctx, vault.ID, "TS", cred.Ciphertext, cred.Nonce, nil, nil, &past, cred.Nonce); err != nil {
			t.Fatal(err)
		}
	}
	expire()
	checkBearer("fixture-2")
	checkBearer("fixture-2")
	reject.Store(true)
	if rec := setup(); rec.Code != 502 || strings.Contains(rec.Body.String(), "test-secret") {
		t.Fatalf("failed setup: %d", rec.Code)
	}
	checkBearer("fixture-2")
	expire()
	got, err := inject()
	if err == nil || len(got.Headers) != 0 || strings.Contains(err.Error(), "test-secret") {
		t.Fatal("failed renewal did not fail closed")
	}
	for _, query := range []string{"", "&key=TS"} {
		rec := httptest.NewRecorder()
		srv.handleCredentialsList(rec, httptest.NewRequestWithContext(ctx, "GET", "/v1/credentials?vault=enrollment&reveal=true"+query, nil))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "fixture-") {
			t.Fatalf("reveal: %d", rec.Code)
		}
	}
}

func TestDefaultOAuthGrantUsesRefreshToken(t *testing.T) {
	ctx := t.Context()
	db, err := store.Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.CreateVault(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "fixture-refresh" {
			t.Error("incorrect refresh request")
		}
		fmt.Fprint(w, `{"access_token":"renewed","expires_in":3600}`)
	}))
	defer endpoint.Close()
	srv := newTestServer(withStore(db))
	previous := oauth.TokenClient
	oauth.TokenClient = endpoint.Client()
	defer func() { oauth.TokenClient = previous }()
	cfg := &store.CredentialOAuth{VaultID: vault.ID, CredentialKey: "LEGACY", TokenURL: endpoint.URL, ClientID: "legacy"}
	if err := db.SetCredentialOAuth(ctx, cfg, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err = db.GetCredentialOAuth(ctx, vault.ID, "LEGACY")
	if err != nil || cfg.GrantType != "authorization_code" {
		t.Fatalf("unexpected default grant: %v", err)
	}
	old, oldNonce, err := crypto.Encrypt([]byte("old"), srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	refresh, refreshNonce, err := crypto.Encrypt([]byte("fixture-refresh"), srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := db.UpdateCredentialOAuthTokens(ctx, vault.ID, "LEGACY", old, oldNonce, refresh, refreshNonce, &past, nil); err != nil {
		t.Fatal(err)
	}
	_, err = db.SetBrokerConfig(ctx, vault.ID, `[{"name":"api","host":"resource.example","auth":{"type":"bearer","token":"LEGACY"}}]`)
	if err != nil {
		t.Fatal(err)
	}
	provider := brokercore.NewStoreCredentialProvider(credentialStoreAdapter{db}, srv.encKey)
	provider.OAuthStore = db
	provider.Refresher = oauth.NewRefresher()
	got, err := provider.Inject(ctx, vault.ID, "resource.example", 443, "/")
	if err != nil || got.Headers["Authorization"] != "Bearer renewed" {
		t.Fatalf("legacy refresh failed: %v", err)
	}
}

// swapOnFirstOAuthRead replaces the stored bearer just before the first OAuth
// configuration read, as a concurrent exchange committing between the
// broker's two reads would.
type swapOnFirstOAuthRead struct {
	*store.SQLStore
	swap func()
	done atomic.Bool
}

func (s *swapOnFirstOAuthRead) GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error) {
	if s.done.CompareAndSwap(false, true) {
		s.swap()
	}
	return s.SQLStore.GetCredentialOAuth(ctx, vaultID, key)
}

func TestClientCredentialsRereadsReplacedToken(t *testing.T) {
	ctx := t.Context()
	db, err := store.Open(filepath.Join(t.TempDir(), "swap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.CreateVault(ctx, "enrollment")
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(withStore(db))
	future := time.Now().Add(time.Hour)
	first, firstNonce, err := crypto.Encrypt([]byte("first"), srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &store.CredentialOAuth{
		GrantType: oauth.ClientCredentialsGrant, VaultID: vault.ID, CredentialKey: "TS",
		TokenURL: "https://token.invalid/oauth/token", ClientID: "client", TokenExpiresAt: &future,
	}
	if err := db.SetCredentialOAuth(ctx, cfg, &store.EncryptedKV{Key: "TS", Ciphertext: first, Nonce: firstNonce}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetBrokerConfig(ctx, vault.ID, `[{"name":"api","host":"resource.example","auth":{"type":"bearer","token":"TS"}}]`); err != nil {
		t.Fatal(err)
	}
	wrapped := &swapOnFirstOAuthRead{SQLStore: db, swap: func() {
		second, secondNonce, err := crypto.Encrypt([]byte("second"), srv.encKey)
		if err != nil {
			t.Error(err)
			return
		}
		if err := db.UpdateCredentialOAuthTokens(ctx, vault.ID, "TS", second, secondNonce, nil, nil, &future, firstNonce); err != nil {
			t.Error(err)
		}
	}}
	provider := brokercore.NewStoreCredentialProvider(credentialStoreAdapter{db}, srv.encKey)
	provider.OAuthStore = wrapped
	provider.Refresher = oauth.NewRefresher()
	got, err := provider.Inject(ctx, vault.ID, "resource.example", 443, "/")
	if err != nil || got.Headers["Authorization"] != "Bearer second" {
		t.Fatalf("replaced token not reread: %v", err)
	}
}
