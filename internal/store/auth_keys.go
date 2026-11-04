package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuthKey is an automation credential. Empty bindings grant no resources.
// ProxyIDs identify target proxy_provider_profiles, not source proxy row IDs.
type AuthKey struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	AccountIDs []int64 `json:"account_ids"`
	ProxyIDs   []int64 `json:"proxy_ids"`
	Exclusive  bool    `json:"exclusive"`
	Enabled    bool    `json:"enabled"`
	CreatedAt  int64   `json:"created_at"`
	UpdatedAt  int64   `json:"updated_at"`
}

func HashAuthKey(raw string) string { s := sha256.Sum256([]byte(raw)); return hex.EncodeToString(s[:]) }

func (db *DB) EnsureAuthKeys(ctx context.Context) error {
	_, err := db.sql.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS auth_keys (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
 exclusive INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_key_accounts (
 key_id INTEGER NOT NULL REFERENCES auth_keys(id) ON DELETE CASCADE,
 account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
 PRIMARY KEY(key_id,account_id)
);
CREATE TABLE IF NOT EXISTS auth_key_proxies (
 key_id INTEGER NOT NULL REFERENCES auth_keys(id) ON DELETE CASCADE,
 proxy_id INTEGER NOT NULL REFERENCES proxy_provider_profiles(id) ON DELETE CASCADE,
 PRIMARY KEY(key_id,proxy_id)
);
CREATE TABLE IF NOT EXISTS exclusive_account_owners (
 account_id INTEGER PRIMARY KEY REFERENCES wechat_accounts(id) ON DELETE CASCADE,
 key_id INTEGER NOT NULL REFERENCES auth_keys(id) ON DELETE RESTRICT
);`)
	return err
}

func (db *DB) CreateAuthKey(ctx context.Context, name, raw string, accounts, proxies []int64, exclusiveMode ...bool) (*AuthKey, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.TrimSpace(raw) == "" {
		return nil, errors.New("name and key are required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	exclusive := len(exclusiveMode) > 0 && exclusiveMode[0]
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, `INSERT INTO auth_keys(name,key_hash,exclusive,created_at,updated_at) VALUES(?,?,?,?,?)`, name, HashAuthKey(raw), exclusive, now, now)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err = bindAuthKey(ctx, tx, id, accounts, proxies, exclusive); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetAuthKey(ctx, id)
}

func bindAuthKey(ctx context.Context, tx *sql.Tx, id int64, accounts, proxies []int64, exclusive bool) error {
	seen := map[int64]bool{}
	for _, accountID := range accounts {
		if accountID <= 0 {
			return errors.New("account ids must be positive")
		}
		if seen[accountID] {
			continue
		}
		seen[accountID] = true
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT key_id FROM exclusive_account_owners WHERE account_id=?`, accountID).Scan(&owner)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if owner != 0 && owner != id {
			return fmt.Errorf("account %d has an exclusive owner", accountID)
		}
		if exclusive {
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO exclusive_account_owners(account_id,key_id) VALUES(?,?)`, accountID, id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM auth_key_accounts WHERE account_id=? AND key_id<>?`, accountID, id); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO auth_key_accounts(key_id,account_id) VALUES(?,?)`, id, accountID); err != nil {
			return err
		}
	}
	seen = map[int64]bool{}
	for _, proxyID := range proxies {
		if proxyID <= 0 {
			return errors.New("proxy ids must be positive")
		}
		if seen[proxyID] {
			continue
		}
		seen[proxyID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_key_proxies(key_id,proxy_id) VALUES(?,?)`, id, proxyID); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetAuthKeyByHash(ctx context.Context, hash string) (*AuthKey, error) {
	return db.getAuthKey(ctx, `key_hash=?`, hash)
}
func (db *DB) GetAuthKey(ctx context.Context, id int64) (*AuthKey, error) {
	return db.getAuthKey(ctx, `id=?`, id)
}
func (db *DB) getAuthKey(ctx context.Context, where string, arg any) (*AuthKey, error) {
	k := &AuthKey{AccountIDs: []int64{}, ProxyIDs: []int64{}}
	err := db.sql.QueryRowContext(ctx, `SELECT id,name,exclusive,enabled,created_at,updated_at FROM auth_keys WHERE `+where, arg).Scan(&k.ID, &k.Name, &k.Exclusive, &k.Enabled, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	k.AccountIDs, err = db.authKeyIDs(ctx, `SELECT account_id FROM auth_key_accounts WHERE key_id=? ORDER BY account_id`, k.ID)
	if err != nil {
		return nil, err
	}
	k.ProxyIDs, err = db.authKeyIDs(ctx, `SELECT proxy_id FROM auth_key_proxies WHERE key_id=? ORDER BY proxy_id`, k.ID)
	return k, err
}
func (db *DB) authKeyIDs(ctx context.Context, query string, id int64) ([]int64, error) {
	rows, err := db.sql.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var n int64
		if err = rows.Scan(&n); err != nil {
			return nil, err
		}
		ids = append(ids, n)
	}
	return ids, rows.Err()
}
func (db *DB) ListAuthKeys(ctx context.Context) ([]*AuthKey, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id FROM auth_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	for rows.Next() {
		var n int64
		if err = rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	keys := []*AuthKey{}
	for _, id := range ids {
		k, err := db.GetAuthKey(ctx, id)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}
func (db *DB) UpdateAuthKey(ctx context.Context, id int64, name, raw string, accounts, proxies []int64) (*AuthKey, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("name is required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exclusive bool
	if err = tx.QueryRowContext(ctx, `SELECT exclusive FROM auth_keys WHERE id=?`, id).Scan(&exclusive); err != nil {
		return nil, err
	}
	if exclusive {
		rows, err := tx.QueryContext(ctx, `SELECT account_id FROM exclusive_account_owners WHERE key_id=?`, id)
		if err != nil {
			return nil, err
		}
		kept := map[int64]bool{}
		for _, n := range accounts {
			kept[n] = true
		}
		removed := false
		for rows.Next() {
			var n int64
			if err = rows.Scan(&n); err != nil {
				rows.Close()
				return nil, err
			}
			if !kept[n] {
				removed = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if removed {
			return nil, errors.New("delete owned accounts before removing exclusive ownership")
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_key_accounts WHERE key_id=?`, id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_key_proxies WHERE key_id=?`, id); err != nil {
		return nil, err
	}
	if err = bindAuthKey(ctx, tx, id, accounts, proxies, exclusive); err != nil {
		return nil, err
	}
	if raw == "" {
		_, err = tx.ExecContext(ctx, `UPDATE auth_keys SET name=?,updated_at=? WHERE id=?`, strings.TrimSpace(name), time.Now().Unix(), id)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE auth_keys SET name=?,key_hash=?,updated_at=? WHERE id=?`, strings.TrimSpace(name), HashAuthKey(raw), time.Now().Unix(), id)
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetAuthKey(ctx, id)
}
func (db *DB) SetAuthKeyEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE auth_keys SET enabled=?,updated_at=? WHERE id=?`, enabled, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
func (db *DB) DeleteAuthKey(ctx context.Context, id int64) error {
	// The FK refuses deleting an exclusive owner until its accounts are deleted.
	res, err := db.sql.ExecContext(ctx, `DELETE FROM auth_keys WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
func (db *DB) ExclusiveAccountOwners(ctx context.Context) (map[int64]int64, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT account_id,key_id FROM exclusive_account_owners`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := map[int64]int64{}
	for rows.Next() {
		var a, k int64
		if err = rows.Scan(&a, &k); err != nil {
			return nil, err
		}
		owners[a] = k
	}
	return owners, rows.Err()
}
