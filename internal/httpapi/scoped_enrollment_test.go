package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopedEnrollmentFixesKeyAndBrowserOwner(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite", ProtocolToken: "synthetic-main"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	ordinary, err := app.db.CreateAuthKey(ctx, "ordinary", "synthetic-key", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := app.db.CreateAuthKey(ctx, "other", "synthetic-other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/qr", nil)
	r.Header.Set("Authorization", "Bearer synthetic-key")
	enrollment, err := app.prepareScopedEnrollment(httptest.NewRecorder(), r, nil)
	if err != nil || enrollment.OwnerKeyID != ordinary.ID {
		t.Fatal(enrollment, err)
	}
	requested := other.ID
	if _, err = app.prepareScopedEnrollment(httptest.NewRecorder(), r, &requested); err == nil {
		t.Fatal("scoped key chose another owner")
	}
	// A regular Web user cannot silently transfer a scan to an API key.
	web, err := app.auth.CreateUser(ctx, "synthetic-user", "synthetic", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	browser := httptest.NewRequest("POST", "/qr", nil).WithContext(context.WithValue(r.Context(), authUserKey, web))
	if _, err = app.prepareScopedEnrollment(httptest.NewRecorder(), browser, &requested); err == nil {
		t.Fatal("Web user chose API key owner")
	}
}
func TestScopedEnrollmentProxyCreatesAndBindsMappedProfile(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.db.EnsureAuthKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	key, err := app.db.CreateAuthKey(context.Background(), "ordinary", "synthetic-key", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/wxapp/proxyProfiles", strings.NewReader(`{"name":"synthetic","provider":"static","proxy_type":"http","api_url":"http://192.0.2.1:8080"}`))
	r.Header.Set("Authorization", "Bearer synthetic-key")
	w := httptest.NewRecorder()
	app.handleScopedProxyEnrollment(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	updated, err := app.db.GetAuthKey(context.Background(), key.ID)
	if err != nil || len(updated.ProxyIDs) != 1 {
		t.Fatal(updated, err)
	}
}
