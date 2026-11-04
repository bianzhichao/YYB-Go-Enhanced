package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeHostSignPayloadForms(t *testing.T) {
	valid := []map[string]any{
		{"data": map[string]any{"plugins": []map[string]any{{"provider": "wx1234567890abcdef", "inner_version": 1}}}},
		{"plugins": []map[string]any{{"provider": "wx1234567890abcdef", "inner_version": 3}}},
		{"provider": "wx1234567890abcdef", "inner_version": 2},
	}
	for i, payload := range valid {
		raw, err := NormalizeHostSignPayload(payload)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			t.Fatalf("case %d: output not JSON object: %s", i, raw)
		}
		if _, ok := object["plugins"]; !ok {
			t.Fatalf("case %d: output missing plugins: %s", i, raw)
		}
	}
}

func TestNormalizeHostSignPayloadInvalid(t *testing.T) {
	cases := []map[string]any{
		nil,
		{},
		{"data": "not-json"},
		{"data": map[string]any{}},
		{"plugins": []map[string]any{}},
		{"plugins": []map[string]any{{"provider": "bad", "inner_version": 1}}},
		{"plugins": []map[string]any{{"provider": "wx1234567890abcdef", "inner_version": -1}}},
		{"plugins": []map[string]any{{"provider": "wx1234567890abcdef"}}},
	}
	for i, payload := range cases {
		if _, err := NormalizeHostSignPayload(payload); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestParseHostSignResponseJSON(t *testing.T) {
	payload := "{\"errcode\":0,\"list\":[{\"provider\":\"wx1234567890abcdef\",\"host_sign\":\"sig\"}]}"
	out, err := parseHostSignResponse([]byte(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["raw_json"] != payload {
		t.Fatalf("raw_json mismatch: %v", out["raw_json"])
	}
}

func TestParseHostSignResponseWrapped(t *testing.T) {
	inner := []byte{0x19}
	inner = append(inner, []byte("{\"ret\":0,\"plugins\":[{\"host_sign\":\" abc \"}]}")...)
	out, err := parseHostSignResponse(nil, inner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := out["list"].([]map[string]any)
	if list[0]["host_sign"].(string) != " abc " {
		t.Fatalf("sign mismatch: %v", list[0])
	}
}

func TestParseHostSignResponseErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("{\"errcode\":5}"),
		[]byte("{\"list\":[]}"),
		[]byte("{\"list\":[{\"host_sign\":\"\"}]}"),
		[]byte("{\"other\":1}"),
		[]byte("garbage"),
		nil,
	}
	for i, raw := range cases {
		if _, err := parseHostSignResponse(raw); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestBuildHostSignRequestRejectsBadAppID(t *testing.T) {
	if _, err := buildHostSignRequest(1, "bad", []byte("{}"), nil, nil); err == nil {
		t.Fatal("expected error")
	}
	if _, err := buildHostSignRequest(1, "wx1234567890abcdef", []byte("{}"), nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHostSignDeepInputTerminates(t *testing.T) {
	deep := strings.Repeat("[", 64) + strings.Repeat("]", 64)
	if _, err := parseHostSignResponse([]byte(deep)); err == nil {
		t.Fatal("expected error for non-JSON deep payload")
	}
}


