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

func TestFleetMergeScopedAndExclusiveACL(t *testing.T) {
	for _, scoped := range []bool{true, false} {
		t.Run(map[bool]string{true: "scoped", false: "exclusive"}[scoped], func(t *testing.T) {
			app, a, b := fleetTestSetup(t)
			principal := scopedProtocolPrincipal{Owners: map[int64]int64{}}
			if scoped {
				principal.Key = &store.AuthKey{ID: 7, AccountIDs: []int64{a.ID}}
			} else {
				principal.Owners[b.ID] = 8
			}
			ctx := context.WithValue(context.Background(), scopedProtocolContext{}, principal)
			calls := 0
			_, err := app.invokeWithFleet(ctx, a, "wx1234567890abcdef", nil, func(_ context.Context, member *store.WechatAccount, _ string, _ map[string]any, _ string, _ bool) (map[string]any, error) {
				calls++
				if member.ID != a.ID {
					t.Fatal("unauthorized fleet member called")
				}
				return nil, &protocol.ShortlinkRejectedError{Code: -14}
			})
			if err == nil || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestFleetMergeNoRetryStopsFailover(t *testing.T) {
	app, a, _ := fleetTestSetup(t)
	terminal := protocol.MarkNoRetry(&protocol.ShortlinkRejectedError{Code: -14})
	calls := 0
	_, err := app.invokeWithFleet(context.Background(), a, "wx1234567890abcdef", nil, func(context.Context, *store.WechatAccount, string, map[string]any, string, bool) (map[string]any, error) {
		calls++
		return nil, terminal
	})
	if !errors.Is(err, terminal) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestFleetLRUIsScopedToApp(t *testing.T) {
	first, a, b := fleetTestSetup(t)
	first.fleetMarkUsed(a.ID)
	if got := first.fleetOrder([]*store.WechatAccount{a, b}); got[0].ID != b.ID {
		t.Fatal("first app did not remember usage")
	}
	second, x, y := fleetTestSetup(t)
	if got := second.fleetOrder([]*store.WechatAccount{x, y}); got[0].ID != x.ID {
		t.Fatal("fleet usage leaked between apps")
	}
}

func TestFleetMergeRequestProxySurvivesFailover(t *testing.T) {
	app, a, _ := fleetTestSetup(t)
	direct := ""
	ctx, err := withRequestProxy(context.Background(), &direct)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = app.invokeWithFleet(ctx, a, "wx1234567890abcdef", nil, func(_ context.Context, member *store.WechatAccount, _ string, _ map[string]any, proxy string, fallback bool) (map[string]any, error) {
		calls++
		if proxy != "" || fallback {
			t.Fatal("explicit direct proxy override lost")
		}
		if member.ID == a.ID {
			return nil, &protocol.ShortlinkRejectedError{Code: -14}
		}
		return map[string]any{"ok": true}, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestFleetMergeBrowserOwnership(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	user, err := app.auth.CreateUser(ctx, "fleet-owner", "fleet-owner", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	a := insertKeepAliveTestAccount(t, app, "fleet-owned", time.Now().Add(time.Hour))
	b := insertKeepAliveTestAccount(t, app, "fleet-unowned", time.Now().Add(time.Hour))
	if err := app.auth.ClaimAccount(ctx, a.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{a.ID, b.ID} {
		if err := app.db.SetAccountFleet(ctx, id, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	a, err = app.db.GetAccount(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, authUserKey, user)
	req := httptest.NewRequest("POST", "/wxapp/getCode", nil).WithContext(ctx)
	ctx = context.WithValue(ctx, fleetRequestContext{}, req)
	calls := 0
	_, err = app.invokeWithFleet(ctx, a, "wx1234567890abcdef", nil, func(_ context.Context, member *store.WechatAccount, _ string, _ map[string]any, _ string, _ bool) (map[string]any, error) {
		calls++
		if member.ID != a.ID {
			t.Fatal("browser ownership bypassed")
		}
		return nil, &protocol.ShortlinkRejectedError{Code: -14}
	})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
