package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllPhoneRoutesValidateBeforeLookup(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for _, path := range []string{"/wxapp/getAllPhone", "/wx/getallphonenumber"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			r := httptest.NewRequest(method, path, strings.NewReader(`{"ref":"synthetic","app_id":"invalid"}`))
			w := httptest.NewRecorder()
			a.handleGetAllPhone(w, r)
			want := http.StatusBadRequest
			if method == http.MethodGet {
				want = http.StatusMethodNotAllowed
			}
			if w.Code != want {
				t.Fatalf("%s %s: %d", method, path, w.Code)
			}
		}
	}
	a.cfg.ProtocolToken = "test-token"
	r := httptest.NewRequest(http.MethodPost, "/wxapp/getAllPhone", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	a.handleGetAllPhone(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token bypass: %d", w.Code)
	}
}
