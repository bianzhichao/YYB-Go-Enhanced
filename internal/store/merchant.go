package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const billSchema = `
CREATE TABLE IF NOT EXISTS bills (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	order_no TEXT NOT NULL,
	description TEXT NOT NULL,
	amount REAL NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	package TEXT NOT NULL,
	icon_class TEXT DEFAULT 'green',
	status TEXT DEFAULT 'pending',
	openid TEXT DEFAULT '',
	nickname TEXT DEFAULT '',
	mch_id TEXT DEFAULT '',
	app_id TEXT DEFAULT ''
);
`

type Bill struct {
	ID        int64   `json:"id"`
	OrderNo   string  `json:"orderNo"`
	Desc      string  `json:"desc"`
	Amount    float64 `json:"-"`
	CreatedAt string  `json:"createdAt"`
	Package   string  `json:"package"`
	IconClass string  `json:"iconClass"`
	Status    string  `json:"status"`
	OpenID    string  `json:"openid"`
	Nickname  string  `json:"nickname"`
	MchId     string  `json:"mchId"`
	AppId     string  `json:"appid"`
}

type BillUser struct {
	OpenID   string `json:"openid"`
	Nickname string `json:"nickname"`
}

// EnsureMerchant creates the local ledger in the application's existing database.
// These records are operator-maintained; no payment settlement is performed.
func (db *DB) EnsureMerchant(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, billSchema); err != nil {
		return err
	}
	rows, err := db.sql.QueryContext(ctx, "PRAGMA table_info(bills)")
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def any
		if err := rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, column := range []string{"openid", "nickname", "mch_id", "app_id"} {
		if !columns[column] {
			if _, err := db.sql.ExecContext(ctx, "ALTER TABLE bills ADD COLUMN "+column+" TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	return nil
}
func (db *DB) ListBills(ctx context.Context, openid, nickname string) ([]Bill, error) {
	var rows *sql.Rows
	var err error

	if openid != "" || nickname != "" {
		rows, err = db.sql.QueryContext(ctx,
			"SELECT id, order_no, description, amount, created_at, package, icon_class, status, openid, nickname, mch_id, app_id FROM bills WHERE (? = '' OR openid = ?) AND (? = '' OR nickname = ?) ORDER BY created_at DESC",
			openid, openid, nickname, nickname,
		)
	} else {
		rows, err = db.sql.QueryContext(ctx,
			"SELECT id, order_no, description, amount, created_at, package, icon_class, status, openid, nickname, mch_id, app_id FROM bills ORDER BY created_at DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bills := make([]Bill, 0)
	for rows.Next() {
		var b Bill
		if err := rows.Scan(&b.ID, &b.OrderNo, &b.Desc, &b.Amount, &b.CreatedAt, &b.Package, &b.IconClass, &b.Status, &b.OpenID, &b.Nickname, &b.MchId, &b.AppId); err != nil {
			return nil, err
		}
		bills = append(bills, b)
	}
	return bills, rows.Err()
}

func (db *DB) GetBill(ctx context.Context, id int64) (*Bill, error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT id, order_no, description, amount, created_at, package, icon_class, status, openid, nickname, mch_id, app_id FROM bills WHERE id = ?", id)
	var b Bill
	if err := row.Scan(&b.ID, &b.OrderNo, &b.Desc, &b.Amount, &b.CreatedAt, &b.Package, &b.IconClass, &b.Status, &b.OpenID, &b.Nickname, &b.MchId, &b.AppId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &b, nil
}

func (db *DB) UpdateBillStatus(ctx context.Context, id int64, status string) error {
	if !validBillStatus(status) {
		return fmt.Errorf("invalid local bill status")
	}
	result, err := db.sql.ExecContext(ctx, "UPDATE bills SET status = ? WHERE id = ? AND NOT (status = 'done' AND ? = 'fail')", status, id, status)
	if err == nil {
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return sql.ErrNoRows
		}
	}
	return err
}

func (db *DB) DeleteBill(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM bills WHERE id = ?", id)
	return err
}

func (db *DB) DeleteBillsByStatuses(ctx context.Context, statuses []string) (int64, error) {
	if len(statuses) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(statuses))
	args := make([]any, len(statuses))
	for i, s := range statuses {
		placeholders[i] = "?"
		args[i] = s
	}
	query := "DELETE FROM bills WHERE status IN (" + strings.Join(placeholders, ",") + ")"
	result, err := db.sql.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) ListBillUsers(ctx context.Context) ([]BillUser, error) {
	rows, err := db.sql.QueryContext(ctx, "SELECT DISTINCT openid, nickname FROM bills ORDER BY nickname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]BillUser, 0)
	for rows.Next() {
		var u BillUser
		if err := rows.Scan(&u.OpenID, &u.Nickname); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (db *DB) InsertBill(ctx context.Context, b *Bill) error {
	if b == nil {
		return fmt.Errorf("bill is required")
	}
	if b.Amount < 0 || math.IsNaN(b.Amount) || math.IsInf(b.Amount, 0) {
		return fmt.Errorf("invalid amount")
	}
	if b.Status != "" && !validBillStatus(b.Status) {
		return fmt.Errorf("invalid local bill status")
	}
	now := time.Now().Format("2006-01-02 15:04")
	if b.CreatedAt == "" {
		b.CreatedAt = now
	}
	if b.Status == "" {
		b.Status = "pending"
	}
	if b.IconClass == "" {
		b.IconClass = "green"
	}
	if b.Desc == "" {
		b.Desc = "收款账单"
	}

	result, err := db.sql.ExecContext(ctx,
		"INSERT INTO bills (order_no, description, amount, created_at, package, icon_class, status, openid, nickname, mch_id, app_id) VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
		b.OrderNo, b.Desc, b.CreatedAt, b.Package, b.IconClass, b.Status, b.OpenID, b.Nickname, b.MchId, b.AppId,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	b.ID = id
	return nil
}

func validBillStatus(status string) bool {
	switch status {
	case "pending", "processing", "done", "fail":
		return true
	}
	return false
}
