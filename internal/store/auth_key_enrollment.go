package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ScanKeyEnrollment is fixed when a QR session is created. ExistingGuard must
// perform read-only checks against the separate Web ownership store; it must
// not query this DB while its single connection is held by the transaction.
type ScanKeyEnrollment struct {
	OwnerKeyID           int64
	RequireExistingGrant bool
	ExistingGuard        func(accountID int64) error
}

// UpsertAccountForAuthKey preserves the existing scan upsert's free-ID and
// observed interval rules, while committing account and key grants together.
func (db *DB) UpsertAccountForAuthKey(ctx context.Context, enrollment ScanKeyEnrollment, openid, loginBuffer string, alias, nickname, avatar *string, userInfo map[string]any, credentials map[string]any, status *string) (*WechatAccount, error) {
	openid = strings.TrimSpace(openid)
	if openid == "" {
		return nil, errors.New("openid is required")
	}
	now := time.Now().Unix()
	userJSON, err := marshalNullable(userInfo)
	if err != nil {
		return nil, err
	}
	credJSON, err := marshalNullable(credentials)
	if err != nil {
		return nil, err
	}
	// Keep the lookup, lowest-free-ID calculation and write in one transaction.
	// Otherwise two simultaneous successful scans can both select the same gap.
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Reuse the lowest free account slot. This keeps a single account at ID 1
	// after it is deleted and scanned again, while preserving existing IDs.
	var exclusive bool
	if enrollment.OwnerKeyID < 0 {
		return nil, errors.New("invalid owner key")
	}
	if enrollment.OwnerKeyID > 0 {
		var enabled bool
		if err = tx.QueryRowContext(ctx, `SELECT exclusive,enabled FROM auth_keys WHERE id=?`, enrollment.OwnerKeyID).Scan(&exclusive, &enabled); err != nil {
			return nil, err
		}
		if !enabled {
			return nil, errors.New("enrollment key is disabled")
		}
	}
	var existingID int64
	var existingBuffer string
	var existingCredentials sql.NullString
	intervalStatus := ""
	if status != nil {
		intervalStatus = *status
	}
	err = tx.QueryRowContext(ctx, "SELECT id, login_buffer, credentials FROM wechat_accounts WHERE openid=?", openid).Scan(&existingID, &existingBuffer, &existingCredentials)
	if err == nil {
		var owner int64
		ownerErr := tx.QueryRowContext(ctx, `SELECT key_id FROM exclusive_account_owners WHERE account_id=?`, existingID).Scan(&owner)
		if ownerErr != nil && !errors.Is(ownerErr, sql.ErrNoRows) {
			return nil, ownerErr
		}
		if owner > 0 && owner != enrollment.OwnerKeyID {
			return nil, errors.New("account has another exclusive owner")
		}
		if enrollment.RequireExistingGrant && enrollment.OwnerKeyID > 0 {
			var bound int
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_key_accounts WHERE key_id=? AND account_id=?`, enrollment.OwnerKeyID, existingID).Scan(&bound); err != nil {
				return nil, err
			}
			if bound != 1 {
				return nil, errors.New("existing account is not bound to enrollment key")
			}
		}
		if enrollment.ExistingGuard != nil {
			if err = enrollment.ExistingGuard(existingID); err != nil {
				return nil, err
			}
		}
		if qqBrowserBridgeDowngrade(existingCredentials, credJSON) {
			return nil, ErrQQBrowserBridgeDowngrade
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE wechat_accounts SET `+accountOnlineIntervalSQL+`login_buffer=?, alias=?, nickname=?, avatar=?, user_info=?, credentials=?, status=?, updated_at=? WHERE id=?`,
			append(onlineIntervalArgs(intervalStatus, "login", existingBuffer != loginBuffer || existingCredentials != credJSON, now),
				loginBuffer, nullableString(alias), nullableString(nickname), nullableString(avatar),
				userJSON, credJSON, nullableString(status), now, existingID)...,
		)
	} else if errors.Is(err, sql.ErrNoRows) {
		rows, queryErr := tx.QueryContext(ctx, "SELECT id FROM wechat_accounts ORDER BY id")
		if queryErr != nil {
			return nil, queryErr
		}
		nextID := int64(1)
		for rows.Next() {
			var id int64
			if scanErr := rows.Scan(&id); scanErr != nil {
				_ = rows.Close()
				return nil, scanErr
			}
			if id < nextID {
				continue
			}
			if id == nextID {
				nextID++
				continue
			}
			break
		}
		if queryErr = rows.Err(); queryErr != nil {
			_ = rows.Close()
			return nil, queryErr
		}
		_ = rows.Close()
		var onlineSince any
		onlineBasis := ""
		if intervalStatus == "alive" {
			onlineSince, onlineBasis = now, "login"
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO wechat_accounts
			(id, openid, login_buffer, alias, nickname, avatar, user_info, credentials, status, created_at, updated_at, online_since, online_basis)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			nextID, openid, loginBuffer, nullableString(alias), nullableString(nickname), nullableString(avatar),
			userJSON, credJSON, nullableString(status), now, now, onlineSince, onlineBasis,
		)
	} else {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if enrollment.OwnerKeyID > 0 {
		var accountID int64
		if err = tx.QueryRowContext(ctx, "SELECT id FROM wechat_accounts WHERE openid=?", openid).Scan(&accountID); err != nil {
			return nil, err
		}
		if err = bindAuthKey(ctx, tx, enrollment.OwnerKeyID, []int64{accountID}, nil, exclusive); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetAccountByOpenID(ctx, openid)
}

// CreateStaticProxyProfileForAuthKey maps the source's ordinary-key node
// creation to a target static provider profile. Its grant commits atomically.
func (db *DB) CreateStaticProxyProfileForAuthKey(ctx context.Context, keyID int64, name, proxyType, proxyURL string) (*ProxyProviderProfile, error) {
	if keyID <= 0 || strings.TrimSpace(name) == "" || proxyURL == "" {
		return nil, errors.New("key, name and proxy are required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exclusive, enabled bool
	if err = tx.QueryRowContext(ctx, `SELECT exclusive,enabled FROM auth_keys WHERE id=?`, keyID).Scan(&exclusive, &enabled); err != nil {
		return nil, err
	}
	if !enabled || exclusive {
		return nil, errors.New("only an enabled ordinary key can create a proxy profile")
	}
	now := time.Now().Unix()
	result, err := tx.ExecContext(ctx, `INSERT INTO proxy_provider_profiles(name,provider,proxy_type,api_url,created_at,updated_at) VALUES(?,'static',?,?,?,?)`, strings.TrimSpace(name), proxyType, proxyURL, now, now)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err = bindAuthKey(ctx, tx, keyID, nil, []int64{id}, false); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetProxyProviderProfile(ctx, id)
}
