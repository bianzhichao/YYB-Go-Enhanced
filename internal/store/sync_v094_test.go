package store

import (
	"context"
	"errors"
	"testing"

	"yyb_go/internal/qbbrowser"
)

func TestScopedQQPushPreservesStandaloneAuthorizationAndGrants(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	key, err := db.CreateAuthKey(ctx, "exclusive", "synthetic-key", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	policy := ScanKeyEnrollment{OwnerKeyID: key.ID, RequireExistingGrant: true}
	qb := qbbrowser.Credentials{OpenID: "synthetic", QBAccessToken: "access", WXRefreshToken: "refresh", UnionID: "union"}
	status := "alive"
	creds := func(q qbbrowser.Credentials) map[string]any {
		return map[string]any{"provider": "qbbrowser", "qbbrowser": q}
	}
	account, err := db.UpsertAccountForAuthKey(ctx, policy, qb.Identity(), "native-buffer", nil, nil, nil, nil, creds(qb), &status)
	if err != nil {
		t.Fatal(err)
	}
	bridge := qb
	bridge.WXRefreshToken = ""
	if _, err := db.UpsertAccountForAuthKey(ctx, policy, qb.Identity(), "bridge-buffer", nil, nil, nil, nil, creds(bridge), &status); !errors.Is(err, ErrQQBrowserBridgeDowngrade) {
		t.Fatalf("scoped push must reject downgrade: %v", err)
	}
	saved, err := db.GetAccount(ctx, account.ID)
	if err != nil || !saved.SameAuthorization(account) || saved.OnlineSince == nil || *saved.OnlineSince != *account.OnlineSince {
		t.Fatal("rejected push changed authorization or online interval", err)
	}
	owners, err := db.ExclusiveAccountOwners(ctx)
	if err != nil || owners[account.ID] != key.ID {
		t.Fatal("exclusive grant lost", err)
	}
	if _, err := db.UpsertAccountForAuthKey(ctx, policy, qb.Identity(), "rescanned-buffer", nil, nil, nil, nil, creds(qb), &status); err != nil {
		t.Fatal("independent rescan rejected", err)
	}
}
