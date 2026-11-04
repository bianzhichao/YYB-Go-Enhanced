package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func TestUpsertAccountForAuthKeyAtomicBinding(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "enroll.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := db.CreateAuthKey(ctx, "ordinary", "synthetic", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := "alive"
	account, err := db.UpsertAccountForAuthKey(ctx, ScanKeyEnrollment{OwnerKeyID: key.ID}, "synthetic-enroll", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := db.GetAuthKey(ctx, key.ID)
	if err != nil || len(bound.AccountIDs) != 1 || bound.AccountIDs[0] != account.ID {
		t.Fatal(bound, err)
	}
}
func TestUpsertAccountForAuthKeyRollbackAndExistingGrant(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "enroll.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := db.CreateAuthKey(ctx, "ordinary", "synthetic", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := "alive"
	reject := ScanKeyEnrollment{OwnerKeyID: 999999}
	if _, err = db.UpsertAccountForAuthKey(ctx, reject, "synthetic-rejected", "buffer", nil, nil, nil, nil, nil, &status); err == nil {
		t.Fatal("expected ownership rejection")
	}
	if _, err = db.GetAccountByOpenID(ctx, "synthetic-rejected"); err == nil {
		t.Fatal("rejected scan persisted account")
	}
	bound, err := db.GetAuthKey(ctx, key.ID)
	if err != nil || len(bound.AccountIDs) != 0 {
		t.Fatal(bound, err)
	}
	// A key-created account may be refreshed only while its grant still exists.
	account, err := db.UpsertAccountForAuthKey(ctx, ScanKeyEnrollment{OwnerKeyID: key.ID}, "synthetic-existing", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.sql.ExecContext(ctx, `DELETE FROM auth_key_accounts WHERE key_id=? AND account_id=?`, key.ID, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpsertAccountForAuthKey(ctx, ScanKeyEnrollment{OwnerKeyID: key.ID, RequireExistingGrant: true}, account.OpenID, "new-buffer", nil, nil, nil, nil, nil, &status); err == nil {
		t.Fatal("unbound existing account was enrolled")
	}
	fresh, err := db.GetAccount(ctx, account.ID)
	if err != nil || fresh.LoginBuffer != "buffer" {
		t.Fatal("rejected refresh changed account", fresh, err)
	}
}
func TestConcurrentExclusiveScanEnrollmentOneOwner(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "enroll.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	one, err := db.CreateAuthKey(ctx, "one", "synthetic-one", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	two, err := db.CreateAuthKey(ctx, "two", "synthetic-two", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []int64{one.ID, two.ID} {
		wg.Add(1)
		go func(keyID int64) {
			defer wg.Done()
			<-start
			_, e := db.UpsertAccountForAuthKey(ctx, ScanKeyEnrollment{OwnerKeyID: keyID}, "synthetic-race", "buffer", nil, nil, nil, nil, nil, nil)
			errs <- e
		}(id)
	}
	close(start)
	wg.Wait()
	close(errs)
	success, failure := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else {
			failure++
		}
	}
	if success != 1 || failure != 1 {
		t.Fatalf("success=%d failure=%d", success, failure)
	}
	owners, err := db.ExclusiveAccountOwners(ctx)
	if err != nil || len(owners) != 1 || owners[1] != one.ID && owners[1] != two.ID {
		t.Fatal(owners, err)
	}
	keys, err := db.ListAuthKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bound := 0
	for _, key := range keys {
		bound += len(key.AccountIDs)
	}
	if bound != 1 {
		t.Fatal("duplicate or missing binding", keys)
	}
}
func TestCreateStaticProxyProfileForAuthKeyAtomicGrant(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ordinary, err := db.CreateAuthKey(ctx, "ordinary", "synthetic", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := db.CreateStaticProxyProfileForAuthKey(ctx, ordinary.ID, "proxy", "http", "http://192.0.2.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := db.GetAuthKey(ctx, ordinary.ID)
	if err != nil || len(updated.ProxyIDs) != 1 || updated.ProxyIDs[0] != profile.ID {
		t.Fatal(updated, err)
	}
	exclusive, err := db.CreateAuthKey(ctx, "exclusive", "synthetic-exclusive", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateStaticProxyProfileForAuthKey(ctx, exclusive.ID, "denied", "http", "http://192.0.2.2:8080"); err == nil {
		t.Fatal("exclusive key created proxy profile")
	}
	var count int
	if err = db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxy_provider_profiles WHERE name='denied'`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}
