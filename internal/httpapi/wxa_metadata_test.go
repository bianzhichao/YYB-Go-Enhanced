package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWXAMetadataHandlersValidateBeforeAccountLookup(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	cases := []struct {
		path    string
		handler http.HandlerFunc
		payload string
	}{
		{"/wxapp/checkShortUrl", a.handleCheckShortUrl, `{"shortLink":""}`},
		{"/wxapp/wxaAttrSync", a.handleWxaAttrSync, `{"syncKey":"not base64!"}`},
		{"/wxapp/wxaAppSync", a.handleWxaAppSync, `{"field6":1.5}`},
		{"/wxapp/getWxaCDNDownloadUrl", a.handleGetWxaCDNDownloadUrl, `{"version":-1}`},
	}
	for _, tt := range cases {
		t.Run(tt.path, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req := httptest.NewRequest(method, tt.path, strings.NewReader(`{"ref":"missing","app_id":"wx1234567890abcdef","payload":`+tt.payload+`}`))
				w := httptest.NewRecorder()
				tt.handler(w, req)
				want := http.StatusBadRequest
				if method == http.MethodGet {
					want = http.StatusMethodNotAllowed
				}
				if w.Code != want {
					t.Fatalf("method=%s status=%d body=%s", method, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestWXAMetadataAliasAndProtocolToken(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none", ProtocolToken: "synthetic-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, path := range []string{"/wxapp/wxaAttrSync", "/wxapp/wxaAppSync"} {
		for _, token := range []string{"", "Bearer synthetic-token"} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"ref":"missing","app_id":"wx1234567890abcdef","payload":{}}`))
			r.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			a.handleWxaAppSync(w, r)
			if token == "" {
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("token bypass: %d", w.Code)
				}
			} else if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), `"error":"not found"`) {
				t.Fatalf("alias did not reach account lookup: %d %s", w.Code, w.Body.String())
			}
		}
	}
}
