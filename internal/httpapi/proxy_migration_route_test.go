package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyMigrationRouteRequiresBrowserAdmin(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/proxy-accounts/migrate", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
}
