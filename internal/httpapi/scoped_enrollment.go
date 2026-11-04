package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"yyb_go/internal/proxysource"
	"yyb_go/internal/store"
)

// scopedEnrollment belongs to the QR session, not to a confirm request body.
// It contains no bearer secret. Creator and browser identity remain fixed.
type scopedEnrollment struct {
	OwnerKeyID    int64
	CreatorKeyID  int64
	BrowserUserID int64
}

func (a *App) prepareScopedEnrollment(w http.ResponseWriter, r *http.Request, requested *int64) (*scopedEnrollment, error) {
	if r.Header.Get("Authorization") != "" {
		if !a.authorizeProtocol(w, r) {
			return nil, errors.New("invalid protocol credential")
		}
	}
	principal, _ := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	enrollment := &scopedEnrollment{}
	if principal.Key != nil {
		enrollment.CreatorKeyID = principal.Key.ID
		enrollment.OwnerKeyID = principal.Key.ID
	}
	user := a.browserUser(r)
	if user != nil {
		enrollment.BrowserUserID = user.ID
	}
	if requested != nil {
		if *requested < 0 {
			return nil, errors.New("invalid owner_key_id")
		}
		if principal.Key != nil && *requested != principal.Key.ID {
			return nil, errors.New("scoped key can only enroll to itself")
		}
		// Ordinary browser users cannot hand their account to an unrelated API key.
		if user != nil && user.Role != "admin" && *requested > 0 {
			return nil, errors.New("admin required to choose an API key owner")
		}
		enrollment.OwnerKeyID = *requested
	}
	if user != nil && user.Role != "admin" && enrollment.OwnerKeyID > 0 {
		return nil, errors.New("scoped enrollment requires admin or key-only access")
	}
	if enrollment.OwnerKeyID > 0 {
		key, err := a.db.GetAuthKey(r.Context(), enrollment.OwnerKeyID)
		if err != nil || !key.Enabled {
			return nil, errors.New("enrollment key unavailable")
		}
	}
	return enrollment, nil
}

// checkScopedEnrollment applies to image/poll/cancel/confirm, before any upstream
// action. Only its original creator can operate a scoped session.
func (a *App) checkScopedEnrollment(w http.ResponseWriter, r *http.Request, enrollment *scopedEnrollment) error {
	if enrollment == nil {
		return nil
	}
	if r.Header.Get("Authorization") != "" {
		if !a.authorizeProtocol(w, r) {
			return errors.New("invalid protocol credential")
		}
	}
	principal, _ := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	creator := int64(0)
	if principal.Key != nil {
		creator = principal.Key.ID
	}
	if creator != enrollment.CreatorKeyID {
		return errors.New("QR session belongs to another key")
	}
	user := a.browserUser(r)
	userID := int64(0)
	if user != nil {
		userID = user.ID
	}
	if userID != enrollment.BrowserUserID {
		return errors.New("QR session belongs to another browser user")
	}
	if enrollment.OwnerKeyID > 0 {
		key, err := a.db.GetAuthKey(r.Context(), enrollment.OwnerKeyID)
		if err != nil || !key.Enabled {
			return errors.New("enrollment key unavailable")
		}
	}
	return nil
}

// enrollmentScanContext is internal only; never accept it from request JSON.
type enrollmentScanContext struct{}
type enrollmentScanPolicy struct{ enrollment store.ScanKeyEnrollment }

func (a *App) scopedScanContext(w http.ResponseWriter, r *http.Request, enrollment *scopedEnrollment) (context.Context, error) {
	if err := a.checkScopedEnrollment(w, r, enrollment); err != nil {
		return nil, err
	}
	if enrollment == nil {
		return r.Context(), nil
	}
	user := a.browserUser(r)
	policy := store.ScanKeyEnrollment{OwnerKeyID: enrollment.OwnerKeyID, RequireExistingGrant: enrollment.CreatorKeyID > 0}
	policy.ExistingGuard = func(accountID int64) error {
		if a.auth == nil || user != nil && user.Role == "admin" {
			return nil
		}
		owner, err := a.auth.AccountOwner(r.Context(), accountID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("Web account ownership unavailable")
		}
		if user != nil {
			if err == nil && owner == user.ID {
				return nil
			}
			return errors.New("account does not belong to this browser user")
		}
		// Key-only enrollment of existing accounts is additionally guarded by a
		// live existing key grant in the same account-write transaction.
		if enrollment.CreatorKeyID > 0 {
			return nil
		}
		return nil
	}
	return context.WithValue(r.Context(), enrollmentScanContext{}, enrollmentScanPolicy{enrollment: policy}), nil
}

func (a *App) scopedEnrollmentProxyAllowed(r *http.Request, body accountProxyIn, spec proxysource.Spec) error {
	principal, ok := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	if !ok || principal.Key == nil || spec.Mode == "direct" {
		return nil
	}
	if body.ProviderProfileID == nil {
		return errors.New("scoped key QR proxy must use a bound provider profile")
	}
	for _, id := range principal.Key.ProxyIDs {
		if id == *body.ProviderProfileID {
			return nil
		}
	}
	return errors.New("QR proxy profile is not bound to this API key")
}

func (a *App) saveScannedAccount(ctx context.Context, openid, buffer string, alias, nickname, avatar *string, userInfo, credentials map[string]any, status *string) (*store.WechatAccount, error) {
	if policy, ok := ctx.Value(enrollmentScanContext{}).(enrollmentScanPolicy); ok {
		return a.db.UpsertAccountForAuthKey(ctx, policy.enrollment, openid, buffer, alias, nickname, avatar, userInfo, credentials, status)
	}
	// Even a main-token scan cannot overwrite an exclusively owned account.
	return a.db.UpsertAccountForAuthKey(ctx, store.ScanKeyEnrollment{}, openid, buffer, alias, nickname, avatar, userInfo, credentials, status)
}

// handleScopedProxyEnrollment adds only source-proven static node creation.
// Provider APIs and source numeric node IDs are not guessed or imported.
func (a *App) handleScopedProxyEnrollment(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeProtocol(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "POST required")
		return
	}
	principal, _ := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	if principal.Key == nil || principal.Key.Exclusive {
		writeError(w, 403, "ordinary scoped key required")
		return
	}
	if user := a.browserUser(r); user != nil && user.Role != "admin" {
		writeError(w, 403, "admin or key-only access required")
		return
	}
	body, ok := decodeProxyProfile(w, r)
	if !ok {
		return
	}
	if body.Provider != "static" {
		writeError(w, 400, "only static profile enrollment is supported")
		return
	}
	profile, err := a.db.CreateStaticProxyProfileForAuthKey(r.Context(), principal.Key.ID, body.Name, body.ProxyType, body.APIURL)
	if err != nil {
		writeError(w, 400, "proxy profile enrollment failed")
		return
	}
	writeJSON(w, 200, profile)
}
