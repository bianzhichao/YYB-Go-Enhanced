package httpapi

import (
	"context"
	"testing"
)

func TestNormalizeRequestProxy(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"socks5://user:secret@127.0.0.1:1080", "socks5://user:secret@127.0.0.1:1080"},
		{"127.0.0.1:1080", "socks5://127.0.0.1:1080"},
		{"socks5h://proxy.example:1080", "socks5://proxy.example:1080"},
		{"http://proxy.example:8080", "http-connect://proxy.example:8080"},
	}
	for _, tc := range cases {
		got, err := normalizeRequestProxy(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("%q => %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestNormalizeRequestProxyRejectsInvalidWithoutEchoingSecret(t *testing.T) {
	for _, in := range []string{"socks5://u:password@host", "socks5://host:0", "socks5://host:1080/path", "ftp://host:21", "socks5://host:1080?q=secret", "socks5://host:1080#secret"} {
		if _, err := normalizeRequestProxy(in); err == nil {
			t.Fatalf("accepted %q", in)
		} else if err.Error() == in {
			t.Fatalf("error echoes input: %v", err)
		}
	}
}

func TestWithRequestProxyNullAndDirect(t *testing.T) {
	ctx := context.Background()
	same, err := withRequestProxy(ctx, nil)
	if err != nil || same != ctx {
		t.Fatal("null override changed context")
	}
	got, err := withRequestProxy(ctx, stringPtrForTest(""))
	if err != nil {
		t.Fatal(err)
	}
	value, ok := got.Value(requestProxyKey{}).(requestProxy)
	if !ok || value.value != "" {
		t.Fatal("empty string must preserve explicit direct mode")
	}
}
func stringPtrForTest(value string) *string { return &value }
