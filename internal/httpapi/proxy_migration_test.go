package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"yyb_go/internal/store"
)

func newProxyMigrationApp(t *testing.T) (*App, string, string) {
	t.Helper()
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite", RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	tokens := []string{}
	for _, role := range []string{"admin", "user"} {
		user, err := app.auth.CreateUser(context.Background(), "migration-"+role, role, "synthetic-password", role)
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := app.auth.CreateSession(context.Background(), user.ID, "fixture", "127.0.0.1", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	return app, tokens[0], tokens[1]
}
func proxyMigrationCall(app *App, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/proxy-accounts/migrate", strings.NewReader(body))
	if token != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	w := httptest.NewRecorder()
	app.handleProxyAccountMigrate(w, r)
	return w
}
func migrationProfile(t *testing.T, app *App, name, provider string) *store.ProxyProviderProfile {
	t.Helper()
	raw := "https://service.ipzan.com/core-extract?no=fixture&secret=synthetic"
	if provider == "juliang" {
		raw = "juliang://company/dynamic?trade_no=12345678&key=0123456789abcdef0123456789abcdef&mode=auth"
	}
	p, err := app.db.CreateProxyProviderProfile(context.Background(), name, provider, "http", raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func migrationAccount(t *testing.T, app *App, p *store.ProxyProviderProfile, name, code, province, city string) *store.WechatAccount {
	t.Helper()
	ctx := context.Background()
	acc, err := app.db.UpsertAccount(ctx, name, "synthetic", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := "direct"
	if _, err := app.db.UpsertAccountProxySetting(ctx, acc.ID, "api", "http", "", "", &p.ID, code, province, city, 1200, &policy); err != nil {
		t.Fatal(err)
	}
	if err := app.db.PutSession(ctx, acc.ID, nil, map[string]any{"fixture": true}, time.Now().Add(time.Hour).Unix(), "old"); err != nil {
		t.Fatal(err)
	}
	app.proxyMu.Lock()
	app.proxyLeases[acc.ID] = accountProxyLease{Value: "synthetic-lease", ExpiresAt: time.Now().Add(time.Hour)}
	app.proxyMu.Unlock()
	return acc
}
func TestProxyMigrationPermissionsAndSameProvider(t *testing.T) {
	app, admin, user := newProxyMigrationApp(t)
	ctx := context.Background()
	from := migrationProfile(t, app, "source", "ipzan")
	to := migrationProfile(t, app, "target", "ipzan")
	acc := migrationAccount(t, app, from, "selected", "110100", "省甲", "市甲")
	skipped := migrationAccount(t, app, from, "missing", "", "", "")
	outsider := migrationAccount(t, app, to, "unselected", "220100", "省乙", "市乙")
	before, err := app.db.GetAccountProxySetting(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d}`, from.ID, to.ID)
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {"invalid", 401}, {user, 403}} {
		w := proxyMigrationCall(app, tc.token, body)
		if w.Code != tc.status {
			t.Fatalf("permission %d: %s", w.Code, w.Body.String())
		}
		after, _ := app.db.GetAccountProxySetting(ctx, acc.ID)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("unauthorized mutation")
		}
		if _, err := app.db.GetSessionForRecovery(ctx, acc.ID, "old"); err != nil {
			t.Fatal("unauthorized session deletion", err)
		}
	}
	w := proxyMigrationCall(app, admin, fmt.Sprintf(`{"from_dynamic_proxy_id":%d,"to_dynamic_proxy_id":%d}`, from.ID, to.ID))
	if w.Code != 400 {
		t.Fatal("legacy node IDs accepted", w.Body.String())
	}
	w = proxyMigrationCall(app, admin, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var response struct {
		Data proxyMigrationResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Migrated) != 1 || response.Data.Migrated[0].AccountID != acc.ID || len(response.Data.Skipped) != 1 || response.Data.Skipped[0].Reason != "missing_region" {
		t.Fatal(w.Body.String())
	}
	after, err := app.db.GetAccountProxySetting(ctx, acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := *before
	want.ProviderProfileID = &to.ID
	want.UpdatedAt = after.UpdatedAt
	if !reflect.DeepEqual(*after, want) {
		t.Fatal("preserved fields changed", after)
	}
	if _, err := app.db.GetSessionForRecovery(ctx, acc.ID, "old"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("old session retained", err)
	}
	app.proxyMu.Lock()
	_, has := app.proxyLeases[acc.ID]
	app.proxyMu.Unlock()
	if has {
		t.Fatal("lease retained")
	}
	for _, untouched := range []*store.WechatAccount{skipped, outsider} {
		if _, err := app.db.GetSessionForRecovery(ctx, untouched.ID, "old"); err != nil {
			t.Fatal("unmigrated session deleted", err)
		}
		app.proxyMu.Lock()
		_, has := app.proxyLeases[untouched.ID]
		app.proxyMu.Unlock()
		if !has {
			t.Fatal("unmigrated lease deleted")
		}
	}
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "synthetic-lease") {
		t.Fatal("response leaked credentials")
	}
}
func TestProxyMigrationExactCatalogOffline(t *testing.T) {
	app, admin, _ := newProxyMigrationApp(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/provinces" {
			fmt.Fprint(w, `{"data":[{"code":"110000","name":"省甲"}]}`)
			return
		}
		if r.URL.Path == "/cities" && r.URL.Query().Get("province") == "110000" {
			fmt.Fprint(w, `{"data":[{"code":"110100","name":"市甲"}]}`)
			return
		}
		http.Error(w, "unexpected fixture request", 500)
	}))
	defer server.Close()
	oldProvince, oldCity := ipzanProvinceAreasEndpoint, ipzanCityAreasEndpoint
	ipzanProvinceAreasEndpoint, ipzanCityAreasEndpoint = server.URL+"/provinces", server.URL+"/cities?province="
	defer func() { ipzanProvinceAreasEndpoint, ipzanCityAreasEndpoint = oldProvince, oldCity }()
	from := migrationProfile(t, app, "cross-source", "juliang")
	to := migrationProfile(t, app, "cross-target", "ipzan")
	matched := migrationAccount(t, app, from, "match", "old-code", "省甲", "市甲")
	migrationAccount(t, app, from, "fuzzy", "old-code", "甲", "市甲")
	migrationAccount(t, app, from, "missing-city", "old-code", "省甲", "不存在市")
	body := fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d}`, from.ID, to.ID)
	w := proxyMigrationCall(app, admin, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var response struct {
		Data proxyMigrationResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Migrated) != 1 || response.Data.Migrated[0].RegionCode != "110100" || response.Data.Migrated[0].AccountID != matched.ID || len(response.Data.Skipped) != 2 || calls != 2 {
		t.Fatalf("calls=%d result=%s", calls, w.Body.String())
	}
	// There is no Juliang region catalog: reverse migration must skip, not guess.
	w = proxyMigrationCall(app, admin, fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d}`, to.ID, from.ID))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "target_region_catalog_unavailable") {
		t.Fatal(w.Body.String())
	}
}
func TestProxyMigrationCatalogRejectsAmbiguityAndFailure(t *testing.T) {
	from := &store.ProxyProviderProfile{Provider: "juliang"}
	to := &store.ProxyProviderProfile{Provider: "ipzan"}
	setting := &store.AccountProxySetting{RegionProvince: "省甲", RegionCity: "市甲"}
	for _, tc := range []struct {
		name   string
		fetch  func(context.Context, string) ([]proxyArea, error)
		reason string
	}{
		{"failure", func(context.Context, string) ([]proxyArea, error) { return nil, errors.New("offline") }, "region_catalog_unavailable"},
		{"ambiguous", func(context.Context, string) ([]proxyArea, error) {
			return []proxyArea{{Code: "110000", Name: "省甲"}, {Code: "220000", Name: "省甲"}}, nil
		}, "province_not_unique_exact_match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := proxyMigrationCatalog{fetch: tc.fetch, cache: map[string]proxyMigrationAreas{}}
			code, reason := c.remap(context.Background(), from, to, setting)
			if code != "" || reason != tc.reason {
				t.Fatal(code, reason)
			}
		})
	}
}

func TestProxyMigrationRequiresLiveAdminCookie(t *testing.T) {
	app, admin, userToken := newProxyMigrationApp(t)
	body := `{"from_provider_profile_id":1,"to_provider_profile_id":2}`
	if got := proxyMigrationCall(&App{}, "", body); got.Code != 401 {
		t.Fatal("auth-disabled write accepted", got.Code)
	}
	// Even an injected admin context is not a substitute for a validated cookie.
	adminUser, _, err := app.auth.UserBySession(context.Background(), admin)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/proxy-accounts/migrate", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), authUserKey, adminUser))
	w := httptest.NewRecorder()
	app.handleProxyAccountMigrate(w, r)
	if w.Code != 401 {
		t.Fatal("context-only admin accepted", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/proxy-accounts/migrate", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: admin})
	r = r.WithContext(context.WithValue(r.Context(), scopedProtocolContext{}, scopedProtocolPrincipal{}))
	w = httptest.NewRecorder()
	app.handleProxyAccountMigrate(w, r)
	if w.Code != 403 {
		t.Fatal("scoped key combined with cookie accepted", w.Code)
	}
	if err := app.auth.DeleteSession(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	if got := proxyMigrationCall(app, admin, body); got.Code != 401 {
		t.Fatal("revoked admin accepted", got.Code)
	}
	if got := proxyMigrationCall(app, userToken, body); got.Code != 403 {
		t.Fatal("member accepted", got.Code)
	}
}

func TestProxyMigrationSelectionAndCancelledLease(t *testing.T) {
	app, admin, _ := newProxyMigrationApp(t)
	ctx := context.Background()
	from := migrationProfile(t, app, "select-from", "ipzan")
	to := migrationProfile(t, app, "select-to", "ipzan")
	acc := migrationAccount(t, app, from, "cancelled", "110100", "省甲", "市甲")
	for _, body := range []string{
		fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d,"account_ids":[%d,%d]}`, from.ID, to.ID, acc.ID, acc.ID),
		fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d} {}`, from.ID, to.ID),
	} {
		if w := proxyMigrationCall(app, admin, body); w.Code != 400 {
			t.Fatal("bad selection accepted", w.Code, w.Body.String())
		}
	}
	// Hold extraction lock. Timeout must leave settings, sessions and lease intact.
	lock := app.proxyLeaseLockFor(acc.ID)
	lock <- struct{}{}
	defer func() { <-lock }()
	requestCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/api/proxy-accounts/migrate", strings.NewReader(fmt.Sprintf(`{"from_provider_profile_id":%d,"to_provider_profile_id":%d,"account_ids":[%d]}`, from.ID, to.ID, acc.ID))).WithContext(requestCtx)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: admin})
	w := httptest.NewRecorder()
	app.handleProxyAccountMigrate(w, r)
	if w.Code != 408 {
		t.Fatal("expected cancelled lease wait", w.Code, w.Body.String())
	}
	setting, err := app.db.GetAccountProxySetting(ctx, acc.ID)
	if err != nil || *setting.ProviderProfileID != from.ID {
		t.Fatal("cancelled request changed binding", err)
	}
	if _, err := app.db.GetSessionForRecovery(ctx, acc.ID, "old"); err != nil {
		t.Fatal("cancelled request deleted session", err)
	}
	app.proxyMu.Lock()
	_, has := app.proxyLeases[acc.ID]
	app.proxyMu.Unlock()
	if !has {
		t.Fatal("cancelled request cleared lease")
	}
}
