package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yyb_go/internal/store"
)

type runtimeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f runtimeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRuntimePayNestedJSONAndHTTP(t *testing.T) {
	body := runtimePayRequest{
		Ref: "fixture", AppID: "wx3723729dc4ac916c", Package: "prepay_id=fixture",
		PaySign: "fixture-sign-with-\"quote", NonceStr: "fixture-nonce", TimeStamp: "1788794834",
	}
	if err := body.validate(true); err != nil {
		t.Fatal(err)
	}
	count := 0
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		count++
		if r.Method != "POST" || r.URL.Host != "open.weixin.qq.com" || r.URL.Path != "/wxaruntime/getuuid" ||
			r.URL.Query().Get("session_id") != "fixture+session" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("incorrect fixed endpoint, query escaping or content type")
		}
		var outer, data, invoke, args map[string]any
		if err := json.NewDecoder(r.Body).Decode(&outer); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			text   any
			target *map[string]any
		}{
			{outer["req_data"], &data},
		} {
			if err := json.Unmarshal([]byte(item.text.(string)), item.target); err != nil {
				t.Fatal(err)
			}
		}
		if err := json.Unmarshal([]byte(data["invokeData"].(string)), &invoke); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(invoke["args"].(string)), &args); err != nil {
			t.Fatal(err)
		}
		if data["runtimeSessionId"] != "fixture+session" || data["runtimeTicket"] != nil ||
			invoke["name"] != "requestPayment" || args["timeStamp"] != body.TimeStamp ||
			args["nonceStr"] != body.NonceStr || args["paySign"] != body.PaySign || args["signType"] != "MD5" {
			t.Fatal("timestamp/nonce/signature were lost or ticket was fabricated")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"uuid":"fixture+uuid"}`)), Header: http.Header{}}, nil
	})}
	result, err := requestRuntimePayQRCode(context.Background(), client, body, "fixture+session")
	if err != nil || count != 1 || result["qrcode_url"] != "https://api.weixin.qq.com/wxaruntime/readqrcode?uuid=fixture%2Buuid" {
		t.Fatalf("result=%v count=%d error=%v", result, count, err)
	}
	for _, tc := range []struct {
		status   int
		response string
	}{
		{502, "secret"}, {200, `{}`}, {200, `{"uuid":"fixture","errcode":-8}`},
		{200, `<html>error</html>`}, {200, strings.Repeat("x", 1024*1024+2)},
	} {
		calls := 0
		client.Transport = runtimeRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.response))}, nil
		})
		if _, err := requestRuntimePayQRCode(context.Background(), client, body, "fixture-secret-session"); err == nil || strings.Contains(err.Error(), "fixture-secret") || calls != 1 {
			t.Fatalf("false success, retry or secret in error: %v calls=%d", err, calls)
		}
	}
	client.Transport = runtimeRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network error containing fixture-secret-session")
	})
	if _, err := requestRuntimePayQRCode(context.Background(), client, body, "fixture-secret-session"); err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("network errors must not expose URL/session tokens")
	}
}

func TestRuntimePayValidationBeforeAccountLookup(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	for _, path := range []string{"/wxapp/getRuntimeSession", "/wxapp/getPayQRCode", "/Wxapp/JSGetSessionid", "/api/Wxapp/JSGetSessionid"} {
		payment := path == "/wxapp/getPayQRCode"
		for _, raw := range []string{"{", `{}`, `{"ref":"fixture","appid":"bad"}`} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(raw))
			app.handleRuntimePayCall(w, r, payment, nil, nil)
			if w.Code != 400 {
				t.Fatalf("%s: got %d", path, w.Code)
			}
		}
	}
	b := runtimePayRequest{Ref: "r", AppID: "wx3723729dc4ac916c", Package: "p", PaySign: "s", NonceStr: "n", TimeStamp: "-1"}
	if err := b.validate(true); err == nil {
		t.Fatal("negative timestamp accepted")
	}
	b.TimeStamp = "123"
	b.SignType = "unsupported"
	if err := b.validate(true); err == nil {
		t.Fatal("invalid signature type accepted")
	}
	b.SignType = "RSA"
	b.RuntimeTicket = strings.Repeat("x", 8193)
	if err := b.validate(true); err == nil {
		t.Fatal("oversized ticket accepted")
	}
	app.cfg.ProtocolToken = "configured"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/wxapp/getPayQRCode", strings.NewReader(`{}`))
	app.handleRuntimePayCall(w, r, true, nil, nil)
	if w.Code != 401 {
		t.Fatal("protocol token bypass")
	}
}

func TestRuntimePayUsesSelectedAccountAndIssuesOneQRCodeRequest(t *testing.T) {
	app := newKeepAliveTestApp(t)
	defer app.Close()
	acc := insertKeepAliveTestAccount(t, app, "synthetic-runtime-account", time.Now().Add(time.Hour))
	const appID = "wx3723729dc4ac916c"
	const sessionID = "synthetic-account-session"
	sessionCalls, qrCalls := 0, 0
	session := func(_ context.Context, selected *store.WechatAccount, selectedAppID string, _ map[string]any, _ string, _ bool) (map[string]any, error) {
		sessionCalls++
		if selected.ID != acc.ID || selectedAppID != appID {
			t.Fatalf("wrong account or AppID: %d %s", selected.ID, selectedAppID)
		}
		return map[string]any{"session_id": sessionID, "experimental": true}, nil
	}
	qr := func(_ context.Context, body runtimePayRequest, gotSessionID, _ string) (map[string]any, error) {
		qrCalls++
		if gotSessionID != sessionID || body.PaySign != "synthetic-sign" || body.RuntimeTicket != "" {
			t.Fatalf("payment request changed: session=%q body=%+v", gotSessionID, body)
		}
		return map[string]any{"uuid": "synthetic-uuid", "experimental": true}, nil
	}
	for _, tc := range []struct {
		path    string
		payment bool
		body    string
		wantQR  int
	}{
		{"/wxapp/getRuntimeSession", false, `{"ref":"synthetic-runtime-account","appid":"wx3723729dc4ac916c"}`, 0},
		{"/wxapp/getPayQRCode", true, `{"ref":"synthetic-runtime-account","appid":"wx3723729dc4ac916c","package":"prepay_id=synthetic","paySign":"synthetic-sign","nonceStr":"synthetic-nonce","timeStamp":"1788794834","session_id":"untrusted-session"}`, 1},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		app.handleRuntimePayCall(w, r, tc.payment, session, qr)
		if w.Code != http.StatusOK || qrCalls != tc.wantQR {
			t.Fatalf("%s: status=%d qrCalls=%d body=%s", tc.path, w.Code, qrCalls, w.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		data, ok := result["data"].(map[string]any)
		if !ok || data["experimental"] != true {
			t.Fatalf("missing experimental result: %v", result)
		}
	}
	if sessionCalls != 2 || qrCalls != 1 {
		t.Fatalf("unexpected replay: session=%d qr=%d", sessionCalls, qrCalls)
	}
}
