package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMerchantLedgerCRUDAndFilters(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := db.EnsureMerchant(ctx); err != nil {
			t.Fatal(err)
		}
	}
	bills := []Bill{{OpenID: "owner-a", Nickname: "", MchId: "m", AppId: "wx", Package: "p"}, {OpenID: "owner-b", Nickname: "", MchId: "m", AppId: "wx", Package: "p"}, {OpenID: "owner-a", Nickname: "nick", MchId: "m", AppId: "wx", Package: "p"}}
	for i := range bills {
		if err := db.InsertBill(ctx, &bills[i]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.ListBills(ctx, "owner-a", "")
	if err != nil || len(got) != 2 {
		t.Fatalf("filter leaked or failed: %v %v", got, err)
	}
	got, err = db.ListBills(ctx, "owner-a", "nick")
	if err != nil || len(got) != 1 {
		t.Fatalf("combined filters: %v %v", got, err)
	}
	if err := db.UpdateBillStatus(ctx, bills[0].ID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateBillStatus(ctx, bills[0].ID, "fail"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("done must not become fail: %v", err)
	}
	if err := db.UpdateBillStatus(ctx, bills[1].ID, "fake"); err == nil {
		t.Fatal("invalid status accepted")
	}
	b, err := db.GetBill(ctx, bills[0].ID)
	if err != nil || b.Status != "done" || b.Amount != 0 {
		t.Fatalf("local record %v %v", b, err)
	}
	users, err := db.ListBillUsers(ctx)
	if err != nil || len(users) != 3 {
		t.Fatalf("users %v %v", users, err)
	}
	n, err := db.DeleteBillsByStatuses(ctx, []string{"done", "fail"})
	if err != nil || n != 1 {
		t.Fatalf("cleanup %d %v", n, err)
	}
	if err := db.DeleteBill(ctx, bills[1].ID); err != nil {
		t.Fatal(err)
	}
	got, err = db.ListBills(ctx, "", "")
	if err != nil || len(got) != 1 {
		t.Fatalf("remaining %v %v", got, err)
	}
}

func TestMerchantMigratesLegacyColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = legacy.ExecContext(ctx, `CREATE TABLE bills (id INTEGER PRIMARY KEY AUTOINCREMENT,order_no TEXT NOT NULL,description TEXT NOT NULL,amount REAL NOT NULL DEFAULT 0,created_at TEXT NOT NULL,package TEXT NOT NULL,icon_class TEXT DEFAULT 'green',status TEXT DEFAULT 'pending')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}
	// Opening an existing database performs the additive migration itself.
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b := Bill{OpenID: "known", Package: "p"}
	if err := db.InsertBill(ctx, &b); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetBill(ctx, b.ID)
	if err != nil || got.OpenID != "known" {
		t.Fatalf("migration %v %v", got, err)
	}
}
