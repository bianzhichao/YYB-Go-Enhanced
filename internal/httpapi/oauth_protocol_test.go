package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAppMsgExtSafeArticleAndFixedPost(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "mp.weixin.qq.com" {
			t.Fatalf("host %s", r.URL.Host)
		}
		if r.Method == http.MethodGet {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("article")), Header: http.Header{}}, nil
		}
		if r.URL.Path != "/mp/getappmsgext" || r.URL.Query().Get("pass_ticket") != "ticket+value" {
			t.Fatalf("URL %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"base_resp":{"ret":0},"like_num":7,"more_read_list":[{}]}`)), Header: http.Header{}}, nil
	})}
	result, err := requestAppMsgExt(context.Background(), client, map[string]any{"full_url": "https://mp.weixin.qq.com/s?__biz=biz&mid=1&sn=sn&idx=1&pass_ticket=ticket%2Bvalue"})
	if err != nil || calls != 2 {
		t.Fatalf("result=%v calls=%d err=%v", result, calls, err)
	}
	data := result["data"].(map[string]any)
	if data["like_count"] != float64(7) || data["is_recommended"] != true {
		t.Fatal(data)
	}
	for _, raw := range []string{"http://mp.weixin.qq.com/s?__biz=b&mid=1&sn=s&idx=1&pass_ticket=t", "https://evil.invalid/s?__biz=b&mid=1&sn=s&idx=1&pass_ticket=t"} {
		if _, err := requestAppMsgExt(context.Background(), client, map[string]any{"full_url": raw}); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}
func TestOAuthRedirectDoesNotFollowOrLeak(t *testing.T) {
	client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://evil.invalid"}}}, nil
	})}
	raw, _, err := oauthHTTPOnce(context.Background(), client, http.MethodGet, "https://open.weixin.qq.com/path?ticket=secret", "", nil)
	if err == nil || raw != nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("redirect/error leaked: %s %v", raw, err)
	}
}
func TestThirdAppAuthorizeStagesAndCodeParse(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case "/connect/app/qrconnect":
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`uuid: "fixture-uuid"`)), Header: http.Header{}}, nil
		case "/connect/confirm_reply":
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ret":0}`)), Header: http.Header{}}, nil
		case "/connect/l/qrconnect":
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`window.wx_redirecturl='https://example.com/callback?code=fixture-code'`)), Header: http.Header{}}, nil
		default:
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		}
	})}
	uuid, err := getQRConnectUUID(context.Background(), client, "wx1234567890abcdef", "bundle.example")
	if err != nil || uuid != "fixture-uuid" {
		t.Fatalf("uuid %q %v", uuid, err)
	}
	full := "https://open.weixin.qq.com/connect/confirm?" + url.Values{"uuid": {uuid}, "key": {"k"}, "uin": {"1"}, "pass_ticket": {"t"}}.Encode()
	if _, err := confirmOAuthURL(full, "different"); err == nil {
		t.Fatal("confirmation UUID mismatch accepted")
	}
	if _, err := postConfirmReply(context.Background(), client, full, uuid); err != nil {
		t.Fatal(err)
	}
	code, err := getOAuthCode(context.Background(), client, uuid)
	if err != nil || code != "fixture-code" || calls != 3 {
		t.Fatalf("code %q calls=%d err=%v", code, calls, err)
	}
}
