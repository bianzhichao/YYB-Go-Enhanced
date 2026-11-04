package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func proxyMigrationFixture(t *testing.T) (*DB, *ProxyProviderProfile, *ProxyProviderProfile, []ProxyMigrationItem) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	from, err := db.CreateProxyProviderProfile(ctx, "from", "ipzan", "http", "synthetic-from")
	if err != nil {
		t.Fatal(err)
	}
	to, err := db.CreateProxyProviderProfile(ctx, "to", "ipzan", "socks5", "synthetic-to")
	if err != nil {
		t.Fatal(err)
	}
	var items []ProxyMigrationItem
	for _, name := range []string{"first", "second"} {
		acc, err := db.UpsertAccount(ctx, name, "buffer", nil, nil, nil, nil, map[string]any{"synthetic": true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		policy := "direct"
		setting, err := db.UpsertAccountProxySetting(ctx, acc.ID, "api", "http", "retained-static", "retained-api", &from.ID, "110100", "省甲", "市甲", 900, &policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range []string{"old", "other"} {
			if err := db.PutSession(ctx, acc.ID, nil, map[string]any{"test": true}, time.Now().Add(time.Hour).Unix(), route); err != nil {
				t.Fatal(err)
			}
		}
		items = append(items, ProxyMigrationItem{Account: acc, Setting: setting, RegionCode: "220200"})
	}
	return db, from, to, items
}
func TestProxyMigrationAtomicPreservation(t *testing.T) {
	db, from, to, items := proxyMigrationFixture(t)
	ctx := context.Background()
	if err := db.MigrateAccountProxyProfiles(ctx, from, to, items[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAccountProxySetting(ctx, items[0].Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	expected := *items[0].Setting
	expected.ProviderProfileID = &to.ID
	expected.ProxyType = to.ProxyType
	expected.RegionCode = "220200"
	expected.UpdatedAt = got.UpdatedAt
	if !reflect.DeepEqual(*got, expected) || got.UpdatedAt <= items[0].Setting.UpdatedAt {
		t.Fatalf("fields changed unexpectedly: %+v", got)
	}
	after, err := db.GetAccount(ctx, items[0].Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, items[0].Account) {
		t.Fatal("account credentials or observation changed")
	}
	for _, route := range []string{"old", "other"} {
		if _, err := db.GetSessionForRecovery(ctx, items[0].Account.ID, route); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("migrated session retained", err)
		}
		if _, err := db.GetSessionForRecovery(ctx, items[1].Account.ID, route); err != nil {
			t.Fatal("unselected session removed", err)
		}
	}
}
func TestProxyMigrationRollback(t *testing.T) {
	for _, mode := range []string{"session_delete", "setting_changed", "account_replaced", "profile_changed", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			db, from, to, items := proxyMigrationFixture(t)
			ctx := context.Background()
			switch mode {
			case "session_delete":
				if _, err := db.sql.Exec(`CREATE TRIGGER fail_second_session BEFORE DELETE ON sessions WHEN OLD.wechat_account_id=2 BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
					t.Fatal(err)
				}
			case "setting_changed":
				if _, err := db.sql.Exec(`UPDATE account_proxy_settings SET region_city='changed' WHERE account_id=?`, items[1].Account.ID); err != nil {
					t.Fatal(err)
				}
			case "account_replaced":
				if err := db.SetAccountCredential(ctx, items[1].Account.ID, "new-buffer", nil); err != nil {
					t.Fatal(err)
				}
			case "profile_changed":
				if _, err := db.UpdateProxyProviderProfile(ctx, to.ID, to.Name, to.Provider, to.ProxyType, "changed"); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				items = append(items, items[0])
			}
			err := db.MigrateAccountProxyProfiles(ctx, from, to, items)
			if err == nil {
				t.Fatal("expected rollback")
			}
			if mode != "session_delete" && !errors.Is(err, ErrProxyMigrationConflict) {
				t.Fatal(err)
			}
			for _, item := range items[:2] {
				got, err := db.GetAccountProxySetting(ctx, item.Account.ID)
				if err != nil {
					t.Fatal(err)
				}
				if got.ProviderProfileID == nil || *got.ProviderProfileID != from.ID || got.UpdatedAt != item.Setting.UpdatedAt || got.RegionCode != item.Setting.RegionCode {
					t.Fatal("partial batch committed")
				}
				for _, route := range []string{"old", "other"} {
					if _, err := db.GetSessionForRecovery(ctx, item.Account.ID, route); err != nil {
						t.Fatal("session deletion not rolled back", err)
					}
				}
			}
		})
	}
}
