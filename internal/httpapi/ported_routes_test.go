package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortedRoutesAreWiredAndProtected(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), ProtocolToken: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	h := a.Handler()
	for _, path := range []string{"/wxapp/getHostSign", "/Wxapp/GetHostSign", "/api/Wxapp/GetHostSign", "/wxapp/getAllPhone", "/wx/getallphonenumber", "/wxapp/checkShortUrl", "/wxapp/wxaAttrSync", "/wxapp/wxaAppSync", "/wxapp/getWxaCDNDownloadUrl", "/wxapp/gatewayv3", "/wx/gatewayv3", "/wxapp/getRuntimeSession", "/Wxapp/JSGetSessionid", "/api/Wxapp/JSGetSessionid", "/wxapp/getPayQRCode", "/wxapp/getWxaCode", "/wxapp/getA8Key", "/wxapp/userRollList"} {
		for _, authorized := range []bool{false, true} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{"))
			if authorized {
				r.Header.Set("Authorization", "Bearer synthetic")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if authorized {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Errorf("%s authorized=%t status=%d want=%d body=%s", path, authorized, w.Code, want, w.Body)
			}
		}
	}
}
