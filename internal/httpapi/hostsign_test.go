package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yyb_go/internal/store"
)

func TestHostSignRejectsBeforeAccountResolution(t *testing.T) {
	// No account or usable session: invalid input must fail before account resolution.
	a, err := NewApp(Config{ResourceRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, path := range []string{"/wxapp/getHostSign", "/Wxapp/GetHostSign", "/api/Wxapp/GetHostSign"} {
		for _, body := range []string{
			`{"ref":"1","app_id":"bad","payload":{"provider":"wx1234567890abcdef","inner_version":1}}`,
			`{"openid":"1","appid":"wx1234567890abcdef","Data":"invalid"}`,
			`{"ref":"1","app_id":"wx1234567890abcdef","plugins":[]}`,
		} {
			w := httptest.NewRecorder()
			a.handleGetHostSign(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: status=%d body=%s", path, w.Code, w.Body)
			}
		}
	}
}

func TestHostSignCompatibilityInput(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), ProtocolToken: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	status := "alive"
	acc, err := a.db.UpsertAccount(context.Background(), "synthetic-account", "unused", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"openid":"synthetic-account","appid":"wx1234567890abcdef","provider":"wx1234567890abcdef","inner_version":0}`,
		`{"ref":"synthetic-account","app_id":"wx1234567890abcdef","Data":{"plugins":[{"provider":"wx1234567890abcdef","inner_version":1}]}}`,
	} {
		called := false
		call := func(_ context.Context, got *store.WechatAccount, appID string, payload map[string]any, _ string, _ bool) (map[string]any, error) {
			called = true
			if got.ID != acc.ID || appID != "wx1234567890abcdef" {
				t.Fatal("incorrect account or app_id")
			}
			if err := validateHostSign(appID, payload); err != nil {
				t.Fatal(err)
			}
			return map[string]any{"list": []any{}}, nil
		}
		r := httptest.NewRequest(http.MethodPost, "/Wxapp/GetHostSign", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer synthetic")
		w := httptest.NewRecorder()
		a.handleHostSignCall(w, r, call)
		if !called || w.Code != http.StatusOK {
			t.Fatalf("called=%t status=%d body=%s", called, w.Code, w.Body)
		}
	}
}
