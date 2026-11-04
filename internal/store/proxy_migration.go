package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrProxyMigrationConflict = errors.New("proxy migration snapshot changed")

// ProxyMigrationItem carries the exact account and setting used for planning.
// RegionCode is a target-provider code verified by the caller; names stay intact.
type ProxyMigrationItem struct {
	Account    *WechatAccount
	Setting    *AccountProxySetting
	RegionCode string
}

// MigrateAccountProxyProfiles commits the entire planned batch and its session
// invalidation together. Skipped accounts must not be included by the caller.
func (db *DB) MigrateAccountProxyProfiles(ctx context.Context, from, to *ProxyProviderProfile, items []ProxyMigrationItem) error {
	if from == nil || to == nil || from.ID <= 0 || to.ID <= 0 || from.ID == to.ID {
		return ErrProxyMigrationConflict
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, expected := range []*ProxyProviderProfile{from, to} {
		var current ProxyProviderProfile
		err := tx.QueryRowContext(ctx, `SELECT id,name,provider,proxy_type,api_url,created_at,updated_at FROM proxy_provider_profiles WHERE id=?`, expected.ID).Scan(&current.ID, &current.Name, &current.Provider, &current.ProxyType, &current.APIURL, &current.CreatedAt, &current.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProxyMigrationConflict
		}
		if err != nil {
			return err
		}
		if current != *expected {
			return ErrProxyMigrationConflict
		}
	}
	seen := make(map[int64]bool, len(items))
	for _, item := range items {
		if item.Account == nil || item.Setting == nil || item.Account.ID != item.Setting.AccountID || seen[item.Account.ID] || item.Setting.Mode != "api" || item.Setting.ProviderProfileID == nil || *item.Setting.ProviderProfileID != from.ID {
			return ErrProxyMigrationConflict
		}
		seen[item.Account.ID] = true
		current, err := scanAccountRows(tx.QueryRowContext(ctx, selectAccountSQL+" WHERE id=?", item.Account.ID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProxyMigrationConflict
		}
		if err != nil {
			return err
		}
		if !current.SameAuthorization(item.Account) || current.LoginBuffer != item.Account.LoginBuffer {
			return ErrProxyMigrationConflict
		}
		old := item.Setting
		// A strictly increasing version prevents a same-second old lease from matching.
		updated := time.Now().Unix()
		if updated <= old.UpdatedAt {
			updated = old.UpdatedAt + 1
		}
		result, err := tx.ExecContext(ctx, `UPDATE account_proxy_settings SET provider_profile_id=?,proxy_type=?,region_code=?,updated_at=?
WHERE account_id=? AND mode=? AND proxy_type=? AND static_proxy=? AND api_url=? AND provider_profile_id=? AND region_code=? AND region_province=? AND region_city=? AND refresh_ahead_seconds=? AND protocol_proxy_mode=? AND created_at=? AND updated_at=?`,
			to.ID, to.ProxyType, item.RegionCode, updated, old.AccountID, old.Mode, old.ProxyType, old.StaticProxy, old.APIURL, *old.ProviderProfileID, old.RegionCode, old.RegionProvince, old.RegionCity, old.RefreshAheadSeconds, old.ProtocolProxyMode, old.CreatedAt, old.UpdatedAt)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrProxyMigrationConflict
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE wechat_account_id=?", old.AccountID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
