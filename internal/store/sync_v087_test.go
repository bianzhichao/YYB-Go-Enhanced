package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestMultiLinkPreservesExclusiveAccountsAndOnlineIntervals(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "multi.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base, err := db.UpsertAccount(ctx, "root", "old", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	link, err := db.CreateAccountLinkWithChannels(ctx, "synthetic-hash", "", "update", base.ID, nil, base.OpenID, time.Now().Add(time.Hour).Unix(), "appstore", false, true, &base.ID)
	if err != nil {
		t.Fatal(err)
	}
	member, err := db.SaveAccountLinkScan(ctx, link, base, nil, "pcmgr", "pcmgr:new", "new", nil, nil, nil, map[string]any{"provider": "pcmgr"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if member.OnlineSince == nil || member.OnlineBasis != "login" {
		t.Fatal("new channel lost online interval")
	}
	base, err = db.GetAccount(ctx, base.ID)
	if err != nil {
		t.Fatal(err)
	}
	member, err = db.SaveAccountLinkScan(ctx, link, base, member, "pcmgr", member.OpenID, "newer", nil, nil, nil, map[string]any{"provider": "pcmgr"}, nil)
	if err != nil || member.OnlineSince == nil {
		t.Fatal("channel refresh lost online interval", err)
	}
	_, err = db.CreateAuthKey(ctx, "exclusive", "synthetic-key", []int64{base.ID}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAccountLinkScan(ctx, link, base, member, "pcmgr", member.OpenID, "forbidden", nil, nil, nil, nil, nil); err == nil {
		t.Fatal("old public link bypassed exclusive owner")
	}
	fresh, err := db.GetAccount(ctx, member.ID)
	if err != nil || !fresh.SameAuthorization(member) {
		t.Fatal("rejected link changed authorization", err)
	}
}
