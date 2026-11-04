package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func openOnlineTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "online.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func getOnlineAccount(t *testing.T, db *DB, id int64) *WechatAccount {
	t.Helper()
	account, err := db.GetAccount(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func assertOnlineInterval(t *testing.T, account *WechatAccount, since, ended *int64, basis string) {
	t.Helper()
	equal := func(a, b *int64) bool {
		return a == nil && b == nil || a != nil && b != nil && *a == *b
	}
	if !equal(account.OnlineSince, since) || !equal(account.OnlineEndedAt, ended) || account.OnlineBasis != basis {
		data, _ := json.Marshal(account.Public())
		t.Fatalf("unexpected interval: %s; want since=%v ended=%v basis=%q", data, since, ended, basis)
	}
	public := account.Public()
	if !equal(public.OnlineSince, since) || !equal(public.OnlineEndedAt, ended) || public.OnlineBasis != basis {
		t.Fatal("public account lost online interval")
	}
}

func TestOnlineIntervalsLegacyMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Freeze the pre-migration schema rather than deriving it from new columns.
	_, err = legacy.Exec(`CREATE TABLE wechat_accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, openid TEXT NOT NULL UNIQUE,
		uin INTEGER, alias TEXT, nickname TEXT, avatar TEXT, user_info TEXT,
		login_buffer TEXT NOT NULL, credentials TEXT, status TEXT,
		last_checked_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`)
	if err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	for _, status := range []string{"alive", "expired", "unknown"} {
		_, err = legacy.Exec(`INSERT INTO wechat_accounts
			(openid,login_buffer,credentials,status,last_checked_at,created_at,updated_at)
			VALUES(?,'synthetic-buffer','{"last_scan_at":10,"refresh_token_observed_at":20}',?,30,1,40)`, status, status)
		if err != nil {
			_ = legacy.Close()
			t.Fatal(err)
		}
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		accounts, err := db.ListAccounts(ctx)
		if err != nil || len(accounts) != 3 {
			_ = db.Close()
			t.Fatalf("legacy accounts = %d, %v", len(accounts), err)
		}
		for _, account := range accounts {
			assertOnlineInterval(t, account, nil, nil, "")
			if account.CreatedAt != 1 || account.UpdatedAt != 40 || account.LastCheckedAt == nil || *account.LastCheckedAt != 30 || account.LoginBuffer != "synthetic-buffer" || len(account.Credentials) != 2 {
				t.Fatal("migration changed legacy account data")
			}
		}
		var unknown int
		if err := db.sql.QueryRow(`SELECT COUNT(*) FROM wechat_accounts WHERE online_since IS NULL AND online_ended_at IS NULL AND online_basis=''`).Scan(&unknown); err != nil || unknown != 3 {
			t.Fatalf("migration fabricated history: count=%d err=%v", unknown, err)
		}
		if pass == 1 {
			before := time.Now().Unix()
			if err := db.SetAccountStatus(ctx, accounts[0].ID, "alive"); err != nil {
				t.Fatal(err)
			}
			observed := getOnlineAccount(t, db, accounts[0].ID)
			if observed.OnlineSince == nil || *observed.OnlineSince < before {
				t.Fatal("first observation backdated to legacy metadata")
			}
			assertOnlineInterval(t, observed, observed.OnlineSince, nil, "observed")
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Persisted observations survive reopening; migration does not reset them.
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	account, err := db.GetAccountByOpenID(ctx, "alive")
	if err != nil || account == nil || account.OnlineSince == nil || account.OnlineBasis != "observed" {
		t.Fatalf("observation lost after reopening: %v", err)
	}
}

func TestOnlineIntervalsStatusWriters(t *testing.T) {
	ctx := context.Background()
	for _, writer := range []string{"upsert", "status", "credential_status", "refresh"} {
		t.Run(writer, func(t *testing.T) {
			db := openOnlineTestDB(t)
			account, err := db.UpsertAccount(ctx, "synthetic-online", "buffer", nil, nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertOnlineInterval(t, account, nil, nil, "")
			write := func(status string) *WechatAccount {
				t.Helper()
				var err error
				switch writer {
				case "upsert":
					_, err = db.UpsertAccount(ctx, account.OpenID, "buffer", nil, nil, nil, nil, nil, &status)
				case "status":
					err = db.SetAccountStatus(ctx, account.ID, status)
				case "credential_status":
					err = db.SetAccountCredentialStatus(ctx, account.ID, "buffer", nil, status)
				case "refresh":
					expected := getOnlineAccount(t, db, account.ID)
					var applied bool
					applied, err = db.ApplyCredentialRefresh(ctx, expected, "buffer", nil, status)
					if err == nil && !applied {
						t.Fatal("current refresh rejected")
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				return getOnlineAccount(t, db, account.ID)
			}
			assertOnlineInterval(t, write("expired"), nil, nil, "")
			assertOnlineInterval(t, write("unknown"), nil, nil, "")
			assertOnlineInterval(t, write(StatusSessionOnly), nil, nil, "")
			before := time.Now().Unix()
			alive := write("alive")
			basis := "observed"
			if writer == "upsert" {
				basis = "login"
			}
			if alive.OnlineSince == nil || *alive.OnlineSince < before || *alive.OnlineSince > time.Now().Unix() {
				t.Fatal("successful status did not start an interval now")
			}
			assertOnlineInterval(t, alive, alive.OnlineSince, nil, basis)
			// Seed a distinct timestamp so same-second writes cannot hide resets.
			start := int64(100)
			if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_since=? WHERE id=?`, start, account.ID); err != nil {
				t.Fatal(err)
			}
			assertOnlineInterval(t, write("alive"), &start, nil, basis)
			assertOnlineInterval(t, write("unknown"), &start, nil, basis)
			assertOnlineInterval(t, write("alive"), &start, nil, basis)
			assertOnlineInterval(t, write(StatusSessionOnly), &start, nil, basis)
			before = time.Now().Unix()
			expired := write("expired")
			if expired.OnlineEndedAt == nil || *expired.OnlineEndedAt < before || *expired.OnlineEndedAt > time.Now().Unix() {
				t.Fatal("expiration did not close the known interval")
			}
			assertOnlineInterval(t, expired, &start, expired.OnlineEndedAt, basis)
			ended := int64(200)
			if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_ended_at=? WHERE id=?`, ended, account.ID); err != nil {
				t.Fatal(err)
			}
			assertOnlineInterval(t, write("expired"), &start, &ended, basis)
			assertOnlineInterval(t, write("unknown"), &start, &ended, basis)
			before = time.Now().Unix()
			recovered := write("alive")
			if recovered.OnlineSince == nil || *recovered.OnlineSince < before {
				t.Fatal("recovery bridged an expired interval")
			}
			assertOnlineInterval(t, recovered, recovered.OnlineSince, nil, basis)
		})
	}
}

func TestOnlineIntervalsRescanAndStaleRefresh(t *testing.T) {
	ctx := context.Background()
	db := openOnlineTestDB(t)
	status := "alive"
	account, err := db.UpsertAccount(ctx, "synthetic-rescan", "old-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_since=100 WHERE id=?`, account.ID); err != nil {
		t.Fatal(err)
	}
	stale := getOnlineAccount(t, db, account.ID)
	before := time.Now().Unix()
	rescanned, err := db.UpsertAccount(ctx, account.OpenID, "new-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	if rescanned.OnlineSince == nil || *rescanned.OnlineSince < before {
		t.Fatal("new scan did not start a login interval")
	}
	assertOnlineInterval(t, rescanned, rescanned.OnlineSince, nil, "login")
	if applied, err := db.ApplyCredentialRefresh(ctx, stale, "", nil, "expired"); err != nil || applied {
		t.Fatalf("stale expiration applied: %v, %v", applied, err)
	}
	assertOnlineInterval(t, getOnlineAccount(t, db, account.ID), rescanned.OnlineSince, nil, "login")
	if err := db.SetAccountStatus(ctx, account.ID, "expired"); err != nil {
		t.Fatal(err)
	}
	expired := getOnlineAccount(t, db, account.ID)
	if applied, err := db.ApplyCredentialRefresh(ctx, rescanned, "stale-buffer", nil, "alive"); err != nil || applied {
		t.Fatalf("stale recovery applied: %v, %v", applied, err)
	}
	assertOnlineInterval(t, getOnlineAccount(t, db, account.ID), expired.OnlineSince, expired.OnlineEndedAt, "login")
	// Updating credentials alone is not proof of being online.
	if err := db.SetAccountCredential(ctx, account.ID, "new-only-buffer", nil); err != nil {
		t.Fatal(err)
	}
	assertOnlineInterval(t, getOnlineAccount(t, db, account.ID), expired.OnlineSince, expired.OnlineEndedAt, "login")
}

func TestOnlineIntervalsRebindReplacesIdentityHistory(t *testing.T) {
	ctx := context.Background()
	for _, sameIdentity := range []bool{false, true} {
		name := "new_identity"
		if sameIdentity {
			name = "same_identity_rescan"
		}
		t.Run(name, func(t *testing.T) {
			db := openOnlineTestDB(t)
			alive := "alive"
			account, err := db.UpsertAccount(ctx, "old-identity", "old", nil, nil, nil, nil, nil, &alive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.sql.Exec(`UPDATE wechat_accounts SET online_since=100,online_ended_at=200 WHERE id=?`, account.ID); err != nil {
				t.Fatal(err)
			}
			stale := getOnlineAccount(t, db, account.ID)
			link, err := db.CreateAccountLink(ctx, "online-rebind", "update", account.ID, nil, account.OpenID, time.Now().Add(time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			newID := "new-identity"
			if sameIdentity {
				newID = account.OpenID
			}
			before := time.Now().Unix()
			updated, err := db.UpdateAccountFromLink(ctx, link, newID, "new", nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if updated.ID != account.ID || updated.OpenID != newID || updated.OnlineSince == nil || *updated.OnlineSince < before || *updated.OnlineSince > time.Now().Unix() {
				t.Fatal("rebind inherited old history or changed account slot")
			}
			assertOnlineInterval(t, updated, updated.OnlineSince, nil, "login")
			if _, err := db.UpdateAccountFromLink(ctx, link, newID, "again", nil, nil, nil, nil); err == nil {
				t.Fatal("consumed link accepted twice")
			}
			if applied, err := db.ApplyCredentialRefresh(ctx, stale, "", nil, "expired"); err != nil || applied {
				t.Fatalf("old identity refresh applied: %v %v", applied, err)
			}
			assertOnlineInterval(t, getOnlineAccount(t, db, account.ID), updated.OnlineSince, nil, "login")
		})
	}
}

func TestOnlineIntervalsMergeUsesCurrentSourceHistory(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"unknown", "login", "observed", "closed", "now_expired"} {
		t.Run(mode, func(t *testing.T) {
			db := openOnlineTestDB(t)
			alive := "alive"
			source, err := db.UpsertAccount(ctx, "source-identity", "source-buffer", nil, nil, nil, nil, map[string]any{"synthetic": true}, &alive)
			if err != nil {
				t.Fatal(err)
			}
			target, err := db.UpsertAccount(ctx, "target-identity", "target-buffer", nil, nil, nil, nil, nil, &alive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_since=100,online_ended_at=200 WHERE id=?`, target.ID); err != nil {
				t.Fatal(err)
			}
			target = getOnlineAccount(t, db, target.ID)
			// Modify only observation fields after taking the caller snapshot.
			// The merge must read them again within its transaction.
			var since, ended *int64
			basis, status := mode, "alive"
			start, stop := int64(300), int64(400)
			switch mode {
			case "unknown":
				basis = ""
			case "closed":
				since, ended, basis, status = &start, &stop, "observed", "unknown"
			case "now_expired":
				since, ended, basis, status = &start, &stop, "observed", "expired"
			default:
				since = &start
			}
			if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_since=?,online_ended_at=?,online_basis=?,status=? WHERE id=?`, nullableInt(since), nullableInt(ended), basis, status, source.ID); err != nil {
				t.Fatal(err)
			}
			merged, err := db.MergeAccountAuthorization(ctx, source, target)
			if mode == "now_expired" {
				if err == nil {
					t.Fatal("merge accepted source that expired since snapshot")
				}
				assertOnlineInterval(t, getOnlineAccount(t, db, target.ID), target.OnlineSince, target.OnlineEndedAt, target.OnlineBasis)
				assertOnlineInterval(t, getOnlineAccount(t, db, source.ID), since, ended, basis)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if merged.ID != target.ID || merged.OpenID != source.OpenID {
				t.Fatal("merge identity mismatch")
			}
			assertOnlineInterval(t, merged, since, ended, basis)
			if _, err := db.GetAccount(ctx, source.ID); err != sql.ErrNoRows {
				t.Fatalf("source not removed: %v", err)
			}
			if applied, err := db.ApplyCredentialRefresh(ctx, target, "stale", nil, "expired"); err != nil || applied {
				t.Fatalf("old target refresh applied: %v %v", applied, err)
			}
			assertOnlineInterval(t, getOnlineAccount(t, db, target.ID), since, ended, basis)
		})
	}
}

func TestOnlineIntervalsIdentityWriteRollsBack(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"rebind", "merge"} {
		t.Run(operation, func(t *testing.T) {
			db := openOnlineTestDB(t)
			alive := "alive"
			target, err := db.UpsertAccount(ctx, "rollback-target", "target", nil, nil, nil, nil, nil, &alive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.sql.Exec(`UPDATE wechat_accounts SET online_since=100,online_ended_at=200 WHERE id=?`, target.ID); err != nil {
				t.Fatal(err)
			}
			target = getOnlineAccount(t, db, target.ID)
			if err := db.PutSession(ctx, target.ID, nil, map[string]any{"test": true}, time.Now().Add(time.Hour).Unix(), ""); err != nil {
				t.Fatal(err)
			}
			// Fail after the identity/interval UPDATE, proving transactional rollback.
			if _, err := db.sql.Exec(`CREATE TRIGGER fail_online_cleanup BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'synthetic cleanup failure'); END`); err != nil {
				t.Fatal(err)
			}
			if operation == "rebind" {
				link, err := db.CreateAccountLink(ctx, "rollback-link", "update", target.ID, nil, target.OpenID, time.Now().Add(time.Hour).Unix())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.UpdateAccountFromLink(ctx, link, "new-rollback", "new", nil, nil, nil, nil); err == nil {
					t.Fatal("expected cleanup error")
				}
				if _, err := db.GetAccountLink(ctx, link.ID); err != nil {
					t.Fatal("rollback consumed link", err)
				}
			} else {
				source, err := db.UpsertAccount(ctx, "rollback-source", "source", nil, nil, nil, nil, map[string]any{"test": true}, &alive)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.MergeAccountAuthorization(ctx, source, target); err == nil {
					t.Fatal("expected cleanup error")
				}
				assertOnlineInterval(t, getOnlineAccount(t, db, source.ID), source.OnlineSince, source.OnlineEndedAt, source.OnlineBasis)
			}
			current := getOnlineAccount(t, db, target.ID)
			if current.OpenID != target.OpenID || current.LoginBuffer != target.LoginBuffer {
				t.Fatal("rollback changed identity")
			}
			assertOnlineInterval(t, current, target.OnlineSince, target.OnlineEndedAt, target.OnlineBasis)
		})
	}
}
