package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"

	"net/http"
	"strconv"
	"strings"

	"yyb_go/internal/store"
)

type scopedProtocolContext struct{}
type scopedProtocolPrincipal struct {
	Key    *store.AuthKey
	Owners map[int64]int64
}

// authorizeProtocolKey replaces the token-only check. It marks protocol requests,
// allowing exclusive business ownership to coexist with console administration.
func (a *App) authorizeProtocolKey(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal); ok {
		return true
	}
	expected := strings.TrimSpace(a.cfg.ProtocolToken)
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	principal := scopedProtocolPrincipal{}
	main := subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
	if !main {
		key, err := a.db.GetAuthKeyByHash(r.Context(), store.HashAuthKey(provided))
		// Preserve the original opt-in token behavior until scoped keys exist.
		// After a key is created, an unknown/revoked bearer must not turn into
		// unrestricted access merely because ProtocolToken is empty.
		if errors.Is(err, sql.ErrNoRows) && expected == "" {
			keys, listErr := a.db.ListAuthKeys(r.Context())
			if listErr != nil {
				writeError(w, 500, "protocol ACL unavailable")
				return false
			}
			main = len(keys) == 0
		}
		if !main && (err != nil || !key.Enabled) {
			writeError(w, http.StatusUnauthorized, "invalid protocol token")
			return false
		}
		if !main {
			principal.Key = key
		}
	}
	owners, err := a.db.ExclusiveAccountOwners(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "protocol ACL unavailable")
		return false
	}
	principal.Owners = owners
	*r = *r.WithContext(context.WithValue(r.Context(), scopedProtocolContext{}, principal))
	return true
}

// scopedAccountAllowed applies only to business protocol calls. The caller must
// also apply the existing browser ownership policy; neither policy replaces it.
func (a *App) scopedAccountAllowed(r *http.Request, id int64) bool {
	principal, ok := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	if !ok {
		return true
	}
	if owner := principal.Owners[id]; owner > 0 {
		return principal.Key != nil && principal.Key.ID == owner
	}
	if principal.Key == nil {
		return true
	}
	for _, allowed := range principal.Key.AccountIDs {
		if allowed == id {
			return true
		}
	}
	return false
}

// checkScopedProxy must run before proxy resolution or credential repair. The
// target has reusable provider profiles; unregistered per-account proxy strings
// cannot be safely mapped from source node IDs and are denied to scoped keys.
func (a *App) checkScopedProxy(ctx context.Context, accountID int64) error {
	return a.checkScopedProxyMode(ctx, accountID, true)
}

// Credential traffic follows the account proxy even when business traffic is
// explicitly direct; check it independently before login/refresh resolution.
func (a *App) checkScopedAccountProxy(ctx context.Context, accountID int64) error {
	return a.checkScopedProxyMode(ctx, accountID, false)
}

func (a *App) checkScopedProxyMode(ctx context.Context, accountID int64, business bool) error {
	principal, ok := ctx.Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	if !ok || principal.Key == nil {
		return nil
	}
	setting, err := a.db.GetAccountProxySetting(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		if strings.TrimSpace(a.cfg.TCPProxy) == "" {
			return nil
		}
		return errors.New("scoped key cannot use an unbound default proxy")
	}
	if err != nil {
		return err
	}
	if (business && setting.ProtocolProxyMode == "direct") || (setting.ProviderProfileID == nil && setting.Mode == "direct") {
		return nil
	}
	if setting.ProviderProfileID != nil {
		for _, id := range principal.Key.ProxyIDs {
			if id == *setting.ProviderProfileID {
				return nil
			}
		}
	}
	return errors.New("proxy is not bound to this API key")
}

func (a *App) handleAuthKeys(w http.ResponseWriter, r *http.Request) {
	// A protocol key never grants administrative rights, even with AuthDriver=none.
	user := a.browserUser(r)
	if a.auth == nil || user == nil {
		writeError(w, http.StatusUnauthorized, "admin browser session required")
		return
	}
	if user.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin required")
		return
	}
	idText := r.URL.Query().Get("id")
	var id int64
	if idText != "" {
		var err error
		id, err = strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, 400, "invalid id")
			return
		}
	}
	if r.Method == http.MethodGet {
		keys, err := a.db.ListAuthKeys(r.Context())
		if err != nil {
			writeError(w, 500, "key lookup failed")
			return
		}
		writeJSON(w, 200, keys)
		return
	}
	if r.Method == http.MethodDelete {
		if id <= 0 {
			writeError(w, 400, "id is required")
			return
		}
		if err := a.db.DeleteAuthKey(r.Context(), id); err != nil {
			writeError(w, 409, "key cannot be deleted; delete exclusive accounts first")
			return
		}
		writeJSON(w, 200, map[string]any{"deleted": true})
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, 405, "method not allowed")
		return
	}
	var body struct {
		Name       string  `json:"name"`
		AccountIDs []int64 `json:"account_ids"`
		ProxyIDs   []int64 `json:"proxy_ids"`
		Exclusive  bool    `json:"exclusive"`
		Enabled    *bool   `json:"enabled"`
		Rotate     bool    `json:"rotate"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	// Generated keys are disclosed only in the create/rotate response.
	raw := ""
	if r.Method == http.MethodPost || body.Rotate {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			writeError(w, 500, "key generation failed")
			return
		}
		raw = "yyb_" + hex.EncodeToString(buf)
	}
	var key *store.AuthKey
	var err error
	if r.Method == http.MethodPost {
		key, err = a.db.CreateAuthKey(r.Context(), body.Name, raw, body.AccountIDs, body.ProxyIDs, body.Exclusive)
	} else {
		if id <= 0 {
			writeError(w, 400, "id is required")
			return
		}
		key, err = a.db.UpdateAuthKey(r.Context(), id, body.Name, raw, body.AccountIDs, body.ProxyIDs)
	}
	if err != nil {
		writeError(w, 400, "invalid key or conflicting bindings")
		return
	}
	if body.Enabled != nil {
		if err = a.db.SetAuthKeyEnabled(r.Context(), key.ID, *body.Enabled); err != nil {
			writeError(w, 500, "key state update failed")
			return
		}
		key.Enabled = *body.Enabled
	}
	out := map[string]any{"key": key}
	if raw != "" {
		out["key_value"] = raw
	}
	writeJSON(w, 200, out)
}
