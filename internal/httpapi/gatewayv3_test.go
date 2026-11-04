package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"yyb_go/internal/gatewayv3"
	"yyb_go/internal/store"
)

func TestGatewayInputBoundaries(t *testing.T) {
	for _, tc := range []struct {
		host, path, method string
		headers            any
	}{
		{"example.com", "/", "POST", nil},
		{"fixture.wxcloudrun.com:443", "/", "POST", nil},
		{"fixture.wxcloudrun.com", "//other.example/path", "POST", nil},
		{"fixture.wxcloudrun.com", "/", "CONNECT", nil},
		{"fixture.wxcloudrun.com", "/", "POST", map[string]string{"X-WX-HTTP-HOST": "other.example"}},
		{"fixture.wxcloudrun.com", "/", "POST", map[string]string{"Foo": "ok\r\nBar:bad"}},
	} {
		r := gatewayProxyRequest{Host: tc.host, Path: tc.path, Method: tc.method, Headers: tc.headers}
		if _, err := r.validate(); err == nil {
			t.Fatalf("accepted unsafe input: %+v", tc)
		}
	}
}

func TestGatewayBusinessFailureIsNotReplayed(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), ProtocolToken: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	status := "alive"
	_, err = a.db.UpsertAccount(context.Background(), "synthetic-account", "unused", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	authCount, callCount := 0, 0
	auth := func(_ context.Context, _ *store.WechatAccount, _ string, _ map[string]any, _ string, _ bool) (map[string]any, error) {
		authCount++
		return map[string]any{"key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "token": "synthetic-token", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}, nil
	}
	call := func(_ context.Context, _ gatewayProxyRequest, _ *gatewayv3.GatewayToken, _ string, _ map[string]string) (*gatewayv3.CallResult, error) {
		callCount++
		return nil, errors.New("synthetic business failure")
	}
	r := httptest.NewRequest(http.MethodPost, "/wxapp/gatewayv3", strings.NewReader(`{"ref":"synthetic-account","app_id":"wx1234567890abcdef","host":"fixture.wxcloudrun.com","path":"/api/run"}`))
	r.Header.Set("Authorization", "Bearer synthetic")
	w := httptest.NewRecorder()
	a.handleGatewayCall(w, r, auth, call)
	if w.Code != http.StatusBadGateway || authCount != 1 || callCount != 1 {
		t.Fatalf("status=%d auth=%d calls=%d body=%s", w.Code, authCount, callCount, w.Body)
	}
}

func TestGatewayAdditionalBoundaries(t *testing.T) {
	for _, headers := range []any{map[string]string{"Bad\tName": "ok"}, map[string]string{"X-Test": "bad\x00value"}, "null", map[string]any{"X-Test": 123}} {
		b := gatewayProxyRequest{Host: "a.wxcloudrun.com", Path: "/api", Headers: headers}
		if _, err := b.validate(); err == nil {
			t.Fatalf("accepted headers: %#v", headers)
		}
	}
	for _, path := range []string{"/x#fragment", "/x\\y", "https://evil.test/x"} {
		b := gatewayProxyRequest{Host: "a.wxcloudrun.com", Path: path}
		if _, err := b.validate(); err == nil {
			t.Fatalf("accepted path %s", path)
		}
	}
	if validGatewayAppID("wx0123456789abcdeg") {
		t.Fatal("non-hex appid")
	}
	b := gatewayProxyRequest{Host: " A.WXCLOUDRUN.COM ", Path: " /api?q=1 ", Headers: `{"X-Test":"ok"}`}
	h, err := b.validate()
	if err != nil || b.Host != "a.wxcloudrun.com" || b.Method != "POST" || h["X-Test"] != "ok" {
		t.Fatalf("normalization: %+v %v", b, err)
	}
}

func TestGatewayRequestGates(t *testing.T) {
	a := newKeepAliveTestApp(t)
	defer a.Close()
	a.cfg.ProtocolToken = "fixture"
	good := `{"ref":"missing","app_id":"wx0123456789abcdef","host":"a.wxcloudrun.com","path":"/api"}`
	for _, tc := range []struct {
		name, method, path, body, auth string
		status                         int
	}{
		{"auth", "POST", "/wxapp/gatewayv3", good, "", 401},
		{"method", "GET", "/wxapp/gatewayv3", good, "fixture", 405},
		{"path", "POST", "/wrong", good, "fixture", 404},
		{"empty", "POST", "/wxapp/gatewayv3", "", "fixture", 400},
		{"trailing", "POST", "/wxapp/gatewayv3", good + " {}", "fixture", 400},
		{"size", "POST", "/wxapp/gatewayv3", `{"x":"` + strings.Repeat("x", gatewayRequestLimit) + `"}`, "fixture", 413},
		{"missing account", "POST", "/wx/gatewayv3", good, "fixture", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+tc.auth)
			w := httptest.NewRecorder()
			a.handleGatewayCall(w, r, nil, nil)
			if w.Code != tc.status {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestGatewayProxyTokenAndResults(t *testing.T) {
	for _, mode := range []string{"success", "status", "nil", "key", "expired", "missing", "rid", "direct"} {
		t.Run(mode, func(t *testing.T) {
			a := newKeepAliveTestApp(t)
			defer a.Close()
			acc := insertKeepAliveTestAccount(t, a, "gw-fixture", time.Now().Add(time.Hour))
			const proxy = "socks5://127.0.0.1:1080"
			policy := "account"
			wantProxy := proxy
			if mode == "direct" {
				policy = "direct"
				wantProxy = ""
			}
			if _, err := a.db.UpsertAccountProxySetting(context.Background(), acc.ID, "static", "socks5", proxy, "", nil, "", "", "", 300, &policy); err != nil {
				t.Fatal(err)
			}
			authCalls, calls := 0, 0
			auth := func(_ context.Context, account *store.WechatAccount, id string, payload map[string]any, p string, fallback bool) (map[string]any, error) {
				authCalls++
				if p != wantProxy || fallback || account.ID != acc.ID || id != "wx0123456789abcdef" || payload["api_name"] != "qbase_commapi" {
					t.Fatal("account/proxy/auth payload mismatch")
				}
				token := map[string]any{"key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "token": "synthetic-secret", "rid": 123, "timestamp": time.Now().UnixMilli(), "expires_in": 3600}
				switch mode {
				case "key":
					token["key"] = "bad"
				case "expired":
					token["timestamp"] = time.Now().Add(-2 * time.Hour).UnixMilli()
				case "missing":
					delete(token, "token")
				case "rid":
					token["rid"] = "bad\r\nvalue"
				}
				return map[string]any{"data": token}, nil
			}
			call := func(_ context.Context, b gatewayProxyRequest, token *gatewayv3.GatewayToken, p string, h map[string]string) (*gatewayv3.CallResult, error) {
				calls++
				if p != wantProxy || token.Token != "synthetic-secret" || b.Path != "/api" {
					t.Fatal("business proxy/token mismatch")
				}
				if mode == "nil" {
					return nil, nil
				}
				status := 200
				if mode == "status" {
					status = 503
				}
				return &gatewayv3.CallResult{StatusCode: status, Data: json.RawMessage(`{"ok":true}`)}, nil
			}
			body := fmt.Sprintf(`{"openid":%q,"appid":"wx0123456789abcdef","host":"a.wxcloudrun.com","path":"/api"}`, acc.OpenID)
			w := httptest.NewRecorder()
			a.handleGatewayCall(w, httptest.NewRequest("POST", "/wx/gatewayv3", strings.NewReader(body)), auth, call)
			wantStatus, wantCalls := 502, 0
			switch mode {
			case "success", "direct":
				wantStatus = 200
				wantCalls = 1
			case "status", "nil":
				wantCalls = 1
			}
			if w.Code != wantStatus || authCalls != 1 || calls != wantCalls || strings.Contains(w.Body.String(), "synthetic-secret") {
				t.Fatalf("status=%d auth=%d calls=%d body=%s", w.Code, authCalls, calls, w.Body.String())
			}
			if mode == "status" && strings.Contains(w.Body.String(), `"code":0`) {
				t.Fatal("upstream failure marked success")
			}
		})
	}
}

func TestGatewayAccountOwnership(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite", ProtocolToken: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	acc := insertKeepAliveTestAccount(t, a, "gateway-owner", time.Now().Add(time.Hour))
	owner, err := a.auth.CreateUser(context.Background(), "gwowner", "owner", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := a.auth.CreateUser(context.Background(), "gwoutsider", "outsider", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.auth.ClaimAccount(context.Background(), acc.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	session, _, err := a.auth.CreateSession(context.Background(), outsider.ID, "test", "192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/wxapp/gatewayv3", strings.NewReader(`{"ref":"gateway-owner","app_id":"wx0123456789abcdef","host":"a.wxcloudrun.com","path":"/api"}`))
	r.Header.Set("Authorization", "Bearer fixture")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	w := httptest.NewRecorder()
	a.handleGatewayCall(w, r, nil, nil)
	if w.Code != 404 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestGatewayTransportDoesNotRedirectOrUseEnvironmentProxy(t *testing.T) {
	client, err := newGatewayHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("direct mode inherited environment proxy")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/another", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 307 || requests != 1 {
		t.Fatalf("redirect followed: status=%d requests=%d", response.StatusCode, requests)
	}
}

func TestGatewayRoutesAndErrorRedaction(t *testing.T) {
	a := newKeepAliveTestApp(t)
	defer a.Close()
	a.cfg.ProtocolToken = "fixture"
	for _, path := range []string{"/wxapp/gatewayv3", "/wx/gatewayv3"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("route %s bypasses token gate: %d", path, w.Code)
		}
		r = httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer fixture")
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 405 {
			t.Fatalf("route %s method: %d", path, w.Code)
		}
	}
	for _, err := range []error{errors.New("secret-cookie"), &gatewayv3.GatewayError{Msg: "secret-cookie", Code: 503}, nil} {
		w := httptest.NewRecorder()
		writeGatewayError(w, err)
		if w.Code != 502 || strings.Contains(w.Body.String(), "secret-cookie") {
			t.Fatalf("error leak: %s", w.Body.String())
		}
	}
}
