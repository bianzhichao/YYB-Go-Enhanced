package protocol

import (
	"bytes"
	"google.golang.org/protobuf/encoding/protowire"
	"strings"
	"testing"
)

func TestOAuthAuthorizeRequestAndResponse(t *testing.T) {
	st := AppSession{UIN: 123, HostAppID: []byte("host")}
	device := []byte("fixture-device")
	raw, err := buildOauthAuthorizeRequest(st, "wx1234567890abcdef", "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx1234567890abcdef&redirect_uri=https%3A%2F%2Fexample.com&response_type=code&scope=snsapi_base&state=x#wechat_redirect", "biz", "ref", 4, device)
	if err != nil {
		t.Fatal(err)
	}
	outer := pbParse(raw)
	if outer[7] != int64(1254) || string(outer[2].([]byte)) != "/ilink/ilinkapp/mm/bizoauth/oauth_authorize" {
		t.Fatal("wrong CGI/path")
	}
	body := pbParse(outer[5].([]byte))
	if !bytes.Equal(pbParse(body[1].([]byte))[3].([]byte), device) || string(body[2].([]byte)) == "" || string(body[3].([]byte)) != "biz" || string(body[4].([]byte)) != "ref" || body[5] != int64(4) {
		t.Fatalf("bad body %#v", body)
	}
	ui := a8Bytes(nil, 4, []byte("fixture-biz"))
	ui = a8Bytes(ui, 5, []byte("fixture-state"))
	ui = a8Bytes(ui, 6, []byte("https://example.com/cb"))
	ui = a8Var(ui, 10, 1)
	ui = a8Bytes(ui, 11, a8Bytes(a8Bytes(nil, 2, []byte("fixture-name")), 3, []byte("https://example.com/a.png")))
	ui = a8Bytes(ui, 19, a8Bytes(a8Bytes(nil, 1, []byte("fixture-title")), 2, []byte("fixture-subtitle")))
	out, err := parseOauthAuthorizeResponse(a8Bytes(a8Bytes(nil, 1, []byte{8, 0}), 2, ui))
	if err != nil || out["state"] != "fixture-state" || out["is_authorized"] != true || out["redirect_uri"] != "https://example.com/cb" {
		t.Fatalf("%v %v", out, err)
	}
	profile := out["profile"].(map[string]any)
	if profile["nickname"] != "fixture-name" {
		t.Fatal(profile)
	}
	if _, err := parseOauthAuthorizeResponse([]byte{0xff}); err == nil || strings.Contains(err.Error(), "fixture") {
		t.Fatalf("malformed response %v", err)
	}
}
func TestNormalizeOAuthAuthorize(t *testing.T) {
	app := "wx1234567890abcdef"
	target, scene, err := NormalizeOAuthAuthorize(app, map[string]any{"redirect_uri": "https://example.com/callback?a=1&b=2", "scope": "snsapi_userinfo", "state": "fixed-state", "scene": 4, "forcePopup": true})
	if err != nil || scene != 4 || !strings.Contains(target, "redirect_uri=https%3A%2F%2Fexample.com") || !strings.Contains(target, "forcePopup#wechat_redirect") {
		t.Fatalf("%s %d %v", target, scene, err)
	}
	for _, payload := range []map[string]any{{"redirect_uri": "javascript:alert(1)"}, {"redirect_uri": "https://example.com", "scope": "admin"}, {"target_url": "https://evil.invalid/connect/oauth2/authorize?appid=wx1234567890abcdef&redirect_uri=https%3A%2F%2Fexample.com&response_type=code"}, {"target_url": "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx0000000000000000&redirect_uri=https%3A%2F%2Fexample.com&response_type=code"}} {
		if _, _, err := NormalizeOAuthAuthorize(app, payload); err == nil {
			t.Fatalf("accepted %#v", payload)
		}
	}
	_ = protowire.Number(1)
}
