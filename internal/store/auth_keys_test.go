package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthKeyLifecycleAndExclusiveOwnership(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{1, 2} {
		if _, err = db.sql.ExecContext(ctx, `INSERT INTO wechat_accounts(id,openid,login_buffer,created_at,updated_at) VALUES(?,?,'synthetic',0,0)`, id, strings.Repeat("x", id)); err != nil {
			t.Fatal(err)
		}
	}
	a, err := db.CreateAuthKey(ctx, "shared", "synthetic-secret-a", []int64{1, 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exclusive, err := db.CreateAuthKey(ctx, "exclusive", "synthetic-secret-b", []int64{1}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	a, err = db.GetAuthKey(ctx, a.ID)
	if err != nil || len(a.AccountIDs) != 1 || a.AccountIDs[0] != 2 {
		t.Fatalf("claim did not remove stale grant: %#v %v", a, err)
	}
	if _, err = db.UpdateAuthKey(ctx, a.ID, "shared", "", []int64{1}, nil); err == nil {
		t.Fatal("rebound exclusive account")
	}
	a, err = db.GetAuthKey(ctx, a.ID)
	if err != nil || len(a.AccountIDs) != 1 || a.AccountIDs[0] != 2 {
		t.Fatalf("failed transaction lost grants: %#v %v", a, err)
	}
	if _, err = db.UpdateAuthKey(ctx, exclusive.ID, "exclusive", "", nil, nil); err == nil {
		t.Fatal("removed exclusive ownership")
	}
	if err = db.DeleteAuthKey(ctx, exclusive.ID); err == nil {
		t.Fatal("deleted exclusive key with live account")
	}
	if err = db.SetAuthKeyEnabled(ctx, exclusive.ID, false); err != nil {
		t.Fatal(err)
	}
	owners, err := db.ExclusiveAccountOwners(ctx)
	if err != nil || owners[1] != exclusive.ID {
		t.Fatal("revocation must not publish exclusive account", owners, err)
	}
	if _, err = db.UpdateAuthKey(ctx, a.ID, "rotated", "synthetic-secret-new", []int64{2}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetAuthKeyByHash(ctx, HashAuthKey("synthetic-secret-a")); err == nil {
		t.Fatal("old secret still valid")
	}
	var schemaSQL string
	if err = db.sql.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name='auth_keys'`).Scan(&schemaSQL); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(schemaSQL, "key_value") {
		t.Fatal("schema stores plaintext")
	}
	if err = db.DeleteAccount(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteAuthKey(ctx, exclusive.ID); err != nil {
		t.Fatal(err)
	}
}
func TestAuthKeyBindingsRejectUnknownResources(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.EnsureAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateAuthKey(ctx, "invalid", "synthetic", []int64{99}, nil); err == nil {
		t.Fatal("unknown account accepted")
	}
	if _, err = db.CreateAuthKey(ctx, "invalid", "synthetic", nil, []int64{99}); err == nil {
		t.Fatal("unknown proxy accepted")
	}
	keys, err := db.ListAuthKeys(ctx)
	if err != nil || len(keys) != 0 {
		t.Fatalf("failed create persisted rows: %v %v", keys, err)
	}
	key, err := db.CreateAuthKey(ctx, "empty", "synthetic-empty", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(key.AccountIDs) != 0 || len(key.ProxyIDs) != 0 {
		t.Fatal(key)
	}
}

func TestCompactAccountIDsPreservesAuthKeyIdentity(t *testing.T) {
	for _, exclusive := range []bool{false, true} {
		name := "shared"
		if exclusive {
			name = "exclusive"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db, err := Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err = db.EnsureAuthKeys(ctx); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				id     int64
				openid string
			}{{2, "synthetic-A"}, {3, "synthetic-B"}} {
				if _, err = db.sql.ExecContext(ctx, `INSERT INTO wechat_accounts(id,openid,login_buffer,created_at,updated_at) VALUES(?,?,'synthetic',0,0)`, item.id, item.openid); err != nil {
					t.Fatal(err)
				}
			}
			key, err := db.CreateAuthKey(ctx, "scoped", "synthetic", []int64{2}, nil, exclusive)
			if err != nil {
				t.Fatal(err)
			}
			mapping, err := db.CompactAccountIDs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mapping[2] != 1 || mapping[3] != 2 {
				t.Fatal("unexpected compaction", mapping)
			}
			key, err = db.GetAuthKey(ctx, key.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(key.AccountIDs) != 1 || key.AccountIDs[0] != 1 {
				t.Fatalf("key rebound across identities: %#v", key.AccountIDs)
			}
			account, err := db.GetAccount(ctx, key.AccountIDs[0])
			if err != nil || account.OpenID != "synthetic-A" {
				t.Fatalf("binding identity = %#v, %v", account, err)
			}
			owners, err := db.ExclusiveAccountOwners(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if exclusive && (owners[1] != key.ID || owners[2] != 0) {
				t.Fatal("exclusive owner moved to wrong identity", owners)
			}
			if !exclusive && len(owners) != 0 {
				t.Fatal("unexpected exclusive owner", owners)
			}
			rows, err := db.sql.QueryContext(ctx, `PRAGMA foreign_key_check`)
			if err != nil {
				t.Fatal(err)
			}
			if rows.Next() {
				rows.Close()
				t.Fatal("foreign key violation after compaction")
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			rows.Close()
		})
	}
}
