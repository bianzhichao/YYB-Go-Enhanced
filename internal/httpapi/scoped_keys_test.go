package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"yyb_go/internal/auth"
)

func TestScopedKeyAuthenticationAndEmptyBindings(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none", ProtocolToken: "synthetic-main"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	if err = app.db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := app.db.CreateAuthKey(ctx, "empty", "synthetic-scoped", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token   string
		ok      bool
		allowed bool
	}{{"synthetic-main", true, true}, {"synthetic-scoped", true, false}, {"wrong", false, false}, {"", false, false}} {
		r := httptest.NewRequest(http.MethodPost, "/wxapp/getCode", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		if got := app.authorizeProtocolKey(w, r); got != tc.ok {
			t.Fatalf("%q auth=%v", tc.token, got)
		}
		if tc.ok && app.scopedAccountAllowed(r, 99) != tc.allowed {
			t.Fatalf("%q resource escalation", tc.token)
		}
	}
	if err = app.db.SetAuthKeyEnabled(ctx, key.ID, false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/wxapp/getCode", nil)
	r.Header.Set("Authorization", "Bearer synthetic-scoped")
	if app.authorizeProtocolKey(httptest.NewRecorder(), r) {
		t.Fatal("revoked key authenticated")
	}
}
func TestScopedKeysAdminCannotBeProtocolKey(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	r := httptest.NewRequest("POST", "/auth/keys", nil)
	r.Header.Set("Authorization", "Bearer synthetic-main")
	w := httptest.NewRecorder()
	app.handleAuthKeys(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("management auth=%d", w.Code)
	}
}
func TestScopedKeysFailClosedOnMissingSchema(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	// Open integration may initialize the schema; force an unavailable ACL table.
	if err = app.db.EnsureAuthKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = app.db.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/wxapp/getCode", nil)
	w := httptest.NewRecorder()
	if app.authorizeProtocolKey(w, r) {
		t.Fatal("ACL DB failure opened global access")
	}
}

func TestScopedProxyBindingAndExclusiveGlobalPolicy(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none", ProtocolToken: "synthetic-main"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	if err = app.db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	status := "alive"
	acc, err := app.db.UpsertAccount(ctx, "synthetic-scoped-openid", "synthetic", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := app.db.CreateProxyProviderProfile(ctx, "synthetic", "static", "http", "http://192.0.2.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.db.CreateAuthKey(ctx, "owner", "synthetic-owner", []int64{acc.ID}, []int64{profile.ID}, true)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := app.db.CreateAuthKey(ctx, "other", "synthetic-other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	makeReq := func(token string) *http.Request {
		r := httptest.NewRequest("POST", "/wxapp/getCode", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if !app.authorizeProtocolKey(httptest.NewRecorder(), r) {
			t.Fatal("auth failed")
		}
		return r
	}
	if app.scopedAccountAllowed(makeReq("synthetic-main"), acc.ID) {
		t.Fatal("main bypassed exclusive business owner")
	}
	if !app.scopedAccountAllowed(makeReq("synthetic-owner"), acc.ID) {
		t.Fatal("owner denied")
	}
	if app.scopedAccountAllowed(makeReq("synthetic-other"), acc.ID) {
		t.Fatal("unbound key bypassed exclusive owner")
	}
	_, _ = owner, unrelated
	// A profile wins over setting.Mode in actual resolution; ACL must do the same.
	_, err = app.db.UpsertAccountProxySetting(ctx, acc.ID, "direct", "http", "", "", &profile.ID, "", "", "", 300, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.checkScopedProxy(makeReq("synthetic-owner").Context(), acc.ID); err != nil {
		t.Fatal(err)
	}
	if err = app.checkScopedProxy(makeReq("synthetic-other").Context(), acc.ID); err == nil {
		t.Fatal("profile hidden behind direct mode bypassed ACL")
	}
}

func TestScopedKeyManagementDisclosesSecretOnce(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.db.EnsureAuthKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, role string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), authUserKey, &auth.User{ID: 1, Role: role}))
		w := httptest.NewRecorder()
		app.handleAuthKeys(w, r)
		return w
	}
	if w := request("POST", "/auth/keys", `{"name":"test"}`, "user"); w.Code != 403 {
		t.Fatalf("nonadmin=%d", w.Code)
	}
	w := request("POST", "/auth/keys", `{"name":"test"}`, "admin")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var envelope struct {
		Data struct {
			KeyValue string `json:"key_value"`
			Key      struct {
				ID int64 `json:"id"`
			} `json:"key"`
		} `json:"data"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope.Data.KeyValue == "" || envelope.Data.Key.ID <= 0 {
		t.Fatal(envelope, err)
	}
	w = request("GET", "/auth/keys", "", "admin")
	if w.Code != 200 || strings.Contains(w.Body.String(), envelope.Data.KeyValue) || strings.Contains(w.Body.String(), "key_value") || strings.Contains(w.Body.String(), "key_hash") {
		t.Fatal("secret in listing", w.Body.String())
	}
}

func TestScopedCredentialProxyChecksDirectBusinessSeparately(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	if err = app.db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	status := "alive"
	account, err := app.db.UpsertAccount(ctx, "synthetic-credential", "synthetic", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := app.db.CreateProxyProviderProfile(ctx, "synthetic", "static", "http", "http://192.0.2.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.db.CreateAuthKey(ctx, "scoped", "synthetic", []int64{account.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	direct := "direct"
	_, err = app.db.UpsertAccountProxySetting(ctx, account.ID, "api", "http", "", "", &profile.ID, "", "", "", 300, &direct)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/wxapp/getCode", nil)
	r.Header.Set("Authorization", "Bearer synthetic")
	if !app.authorizeProtocolKey(httptest.NewRecorder(), r) {
		t.Fatal("auth")
	}
	if err = app.checkScopedProxy(r.Context(), account.ID); err != nil {
		t.Fatal("direct business should not use proxy", err)
	}
	if err = app.checkScopedAccountProxy(r.Context(), account.ID); err == nil {
		t.Fatal("unbound credential proxy allowed")
	}
}
