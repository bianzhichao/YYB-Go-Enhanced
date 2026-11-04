package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"yyb_go/internal/store"
)

type userRollRoundTrip func(*http.Request) (*http.Response, error)

func (f userRollRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestUserRollURLRejectsUntrustedDestinations(t *testing.T) {
	for _, raw := range []string{"http://weixin.qq.com/", "https://weixin.qq.com.attacker.test/", "https://weixin.qq.com@evil.test/", "https://evilweixin.qq.com/", "https://weixin.qq.com:8443/", "https://tenpay.com/#fragment", "https://127.0.0.1/"} {
		if _, err := userRollURL(raw); err == nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"https://weixin.qq.com/", "https://mp.weixin.qq.com/", "https://pay.tenpay.com/"} {
		if _, err := userRollURL(raw); err != nil {
			t.Fatal(err)
		}
	}
}
func TestUserRollFetchJSONAndHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		ok     bool
	}{{200, `{"ok":true}`, true}, {302, `{}`, false}, {200, `[]`, false}, {200, `not-json`, false}, {500, `{}`, false}, {200, strings.Repeat("x", (8<<20)+1), false}} {
		calls := 0
		client := &http.Client{Transport: userRollRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "GET" || r.Header.Get("Cookie") != "synthetic-cookie" {
				t.Fatal("request mismatch")
			}
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
		})}
		_, err := fetchUserRoll(context.Background(), client, map[string]any{"full_url": "https://weixin.qq.com/synthetic", "cookie": "synthetic-cookie"})
		if (err == nil) != tc.ok || calls != 1 {
			t.Fatalf("status=%d err=%v calls=%d", tc.status, err, calls)
		}
	}
}
func TestUserRollHandlerFetchOutsideAuthCall(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.db.EnsureAuthKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "synthetic-roll", "synthetic", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	authCalls, fetchCalls := 0, 0
	call := func(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
		authCalls++
		if acc.ID != account.ID || payload["scene"] != 0 {
			t.Fatal("account/default scene")
		}
		return map[string]any{"full_url": "https://weixin.qq.com/synthetic"}, nil
	}
	fetch := func(ctx context.Context, result map[string]any, proxy string) (map[string]any, error) {
		fetchCalls++
		return map[string]any{"synthetic": true}, nil
	}
	r := httptest.NewRequest("POST", "/wxapp/userRollList", strings.NewReader(`{"ref":"synthetic-roll","payload":{"target_url":"https://weixin.qq.com/synthetic"}}`))
	w := httptest.NewRecorder()
	app.handleUserRollCall(w, r, call, fetch)
	if w.Code != 200 || authCalls != 1 || fetchCalls != 1 {
		t.Fatal(w.Code, w.Body.String(), authCalls, fetchCalls)
	}
}
