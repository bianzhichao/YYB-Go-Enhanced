package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func TestPortedDefinitiveErrorDoesNotRefreshOrReplay(t *testing.T) {
	a := newKeepAliveTestApp(t)
	defer a.Close()
	acc := insertKeepAliveTestAccount(t, a, "synthetic-terminal", time.Now().Add(time.Hour))
	refreshes, calls := 0, 0
	a.refreshCredentials = func(_ context.Context, c protocol.LoginBufferCredentials) (protocol.LoginBufferCredentials, error) {
		refreshes++
		return c, nil
	}
	cause := errors.New("synthetic parser rejection")
	call := func(_ context.Context, _ *store.WechatAccount, _ string, _ map[string]any, _ string, _ bool) (map[string]any, error) {
		calls++
		return nil, protocol.MarkNoRetry(cause)
	}
	_, err := a.invokeWXApp(context.Background(), acc, "wx1234567890abcdef", nil, call)
	if !errors.Is(err, cause) || !protocol.IsNoRetry(err) || calls != 1 || refreshes != 0 {
		t.Fatalf("err=%v calls=%d refresh=%d", err, calls, refreshes)
	}
}

func TestIntegrationTokenCannotBypassExclusiveOwnership(t *testing.T) {
	a, err := NewApp(Config{ResourceRoot: t.TempDir(), IntegrationToken: "synthetic-integration"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	acc, err := a.db.UpsertAccount(ctx, "synthetic-exclusive", "unused", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.db.CreateAuthKey(ctx, "owner", "synthetic-owner", []int64{acc.ID}, nil, true); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/integration/actions/get-code", nil)
	r.Header.Set("Authorization", "Bearer synthetic-integration")
	if !a.authorizeIntegration(httptest.NewRecorder(), r) {
		t.Fatal("integration token was not recognized")
	}
	if a.accountVisible(r, acc.ID) {
		t.Fatal("integration token bypassed exclusive owner")
	}
	console := httptest.NewRequest("GET", "/accounts", nil)
	if !a.accountVisible(console, acc.ID) {
		t.Fatal("business ownership removed local console visibility")
	}
}
