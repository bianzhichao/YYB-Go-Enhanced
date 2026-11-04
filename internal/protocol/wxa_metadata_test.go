package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

func TestMetadataCallbackErrorsDoNotRetry(t *testing.T) {
	rejected := pbLen(1, pbVar(1, 7))
	_, err := parseMetadataResult(parseWxaAttrSyncResponse, rejected, nil)
	var upstream metadataUpstreamError
	if !IsNoRetry(err) || !errors.As(err, &upstream) || int32(upstream) != 7 {
		t.Fatalf("upstream rejection lost non-retry classification: %v", err)
	}
	_, err = parseMetadataResult(func(_, response []byte) (map[string]any, error) {
		return parseGetAllPhoneResponse(response)
	}, nil, []byte{0x12, 0xff})
	if !IsNoRetry(err) {
		t.Fatalf("malformed phone response can retry: %v", err)
	}
	out, err := parseMetadataResult(parseWxaAttrSyncResponse, pbLen(1, pbVar(1, 0)), nil)
	if err != nil || out == nil {
		t.Fatalf("successful response changed: %v", err)
	}
}

func TestMetadataResponseFixtures(t *testing.T) {
	// Explicit protobuf fields from the source wxapp_pb schema, independent
	// of the request builders. Include repeated attr key/value messages.
	success := []byte{0x08, 0x00}
	inner := append(pbLen(1, success), pbLen(2, []byte("wx1234567890abcdef"))...)
	inner = append(inner, pbLen(3, []byte("pages/index?a=1"))...)
	inner = append(inner, pbVar(5, 2)...)
	inner = append(inner, pbLen(7, []byte("sample"))...)
	short := append(pbLen(1, success), pbLen(2, inner)...)
	out, err := parseCheckShortLinkResponse(short)
	if err != nil || out["appid"] != "wx1234567890abcdef" || out["path"] != "pages/index?a=1" || out["versionType"] != int32(2) {
		t.Fatalf("short=%v err=%v", out, err)
	}
	attr := pbLen(1, success)
	for _, key := range []string{"VersionInfo", "ModuleList"} {
		kv := append(pbLen(1, []byte(key)), pbLen(2, []byte("{}"))...)
		attr = append(attr, pbLen(3, kv)...)
	}
	out, err = parseWxaAttrSyncResponse(attr, nil)
	if err != nil || len(out["keyValues"].([]map[string]any)) != 2 {
		t.Fatalf("attr=%v err=%v", out, err)
	}
	wrapped := append(pbLen(1, success), pbLen(2, attr)...)
	out, err = parseWxaAttrSyncResponse(wrapped, nil)
	if err != nil || len(out["keyValues"].([]map[string]any)) != 2 || out["syncKey"] != base64.StdEncoding.EncodeToString(attr) {
		t.Fatalf("wrapped=%v err=%v", out, err)
	}
	cdn := append(pbLen(1, success), pbLen(3, []byte("https://example.test/a.wxapkg"))...)
	out, err = parseGetWxaCDNDownloadUrlResponse(nil, cdn)
	if err != nil || out["downloadUrl"] != "https://example.test/a.wxapkg" {
		t.Fatalf("cdn=%v err=%v", out, err)
	}
}

func TestMetadataRejectsMalformedAndUpstreamErrors(t *testing.T) {
	rejected := pbLen(1, pbVar(1, uint64(7)))
	for _, raw := range [][]byte{nil, {0x12, 0xff}, rejected} {
		if _, err := parseCheckShortLinkResponse(raw); err == nil {
			t.Fatalf("short accepted %x", raw)
		}
		if _, err := parseWxaAttrSyncResponse(raw, raw); err == nil {
			t.Fatalf("attr accepted %x", raw)
		}
		if _, err := parseGetWxaCDNDownloadUrlResponse(nil, raw); err == nil {
			t.Fatalf("cdn accepted %x", raw)
		}
	}
	// An extracted URL must not mask an explicit upstream rejection.
	if _, err := parseGetWxaCDNDownloadUrlResponse([]byte("https://example.test/"), rejected); err == nil {
		t.Fatal("upstream rejection was hidden")
	}
	if _, err := parseWxaAttrSyncResponse(rejected, pbLen(1, []byte{8, 0})); err == nil {
		t.Fatal("attr rejection was hidden")
	}
}

func TestMetadataValidationBeforeSession(t *testing.T) {
	for _, payload := range []map[string]any{nil, {"shortLink": 1}, {"shortLink": " "}} {
		if err := ValidateCheckShortURL("", payload); err == nil {
			t.Fatal("accepted invalid shortLink")
		}
	}
	for _, payload := range []map[string]any{{"syncKey": "!"}, {"field6": 1.5}, {"field6": float64(1 << 32)}, {"userName": true}} {
		if err := ValidateWxaAttrSync("wx1234567890abcdef", payload); err == nil {
			t.Fatalf("accepted %v", payload)
		}
	}
	if err := ValidateWxaCDNDownloadURL("wx1234567890abcdef", map[string]any{"version": -1}); err == nil {
		t.Fatal("accepted negative version")
	}
	// No pool/database is needed: invalid requests fail before a login is attempted.
	var pool *Pool
	if _, err := pool.WxaAttrSync(context.Background(), "", "bad", nil, 0, "", false); err == nil {
		t.Fatal("expected app validation")
	}
}

func TestMetadataRequestSessionIdentity(t *testing.T) {
	sess := AppSession{UIN: 123, DeviceID: []byte("old-device"), HostAppID: []byte("host")}
	device := []byte("stable-device")
	base, err := parseMetadataFields(metadataBaseReq(sess, device))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.bytes(3), device) || base.number(6) != 5 || base.number(4) != clientVersion {
		t.Fatalf("base fields=%v", base)
	}
	requests := []func() ([]byte, error){func() ([]byte, error) { return buildCheckShortLinkRequest(sess, "https://example.test/", device) }, func() ([]byte, error) {
		return buildWxaAttrSyncRequest(sess, "wx1234567890abcdef", "", nil, "", 0, device)
	}, func() ([]byte, error) {
		return buildGetWxaCDNDownloadUrlRequest(sess, "wx1234567890abcdef", 42, "md5", "subpackage", device)
	}}
	for _, build := range requests {
		raw, err := build()
		if err != nil || !bytes.Contains(raw, device) || bytes.Contains(raw, sess.DeviceID) {
			t.Fatalf("request identity err=%v", err)
		}
	}
}
