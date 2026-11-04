package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"yyb_go/internal/store"
)

// Register after requireBrowserSession in App.Handler:
// router.POST("/api/proxy-accounts/migrate", gin.WrapF(a.handleProxyAccountMigrate))
// IDs belong exclusively to proxy_provider_profiles, not legacy proxy nodes.
type proxyMigrationRequest struct {
	FromProviderProfileID int64   `json:"from_provider_profile_id"`
	ToProviderProfileID   int64   `json:"to_provider_profile_id"`
	AccountIDs            []int64 `json:"account_ids,omitempty"`
}
type proxyMigrationResultItem struct {
	AccountID  int64  `json:"account_id"`
	RegionCode string `json:"region_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}
type proxyMigrationResult struct {
	Migrated []proxyMigrationResultItem `json:"migrated"`
	Skipped  []proxyMigrationResultItem `json:"skipped"`
}

func (a *App) handleProxyAccountMigrate(w http.ResponseWriter, r *http.Request) {
	// Revalidate the browser cookie, including when called outside route middleware.
	// Auth-disabled installations and protocol API keys cannot authorize this write.
	if a.auth == nil {
		writeError(w, 401, "admin browser session required")
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		writeError(w, 401, "admin browser session required")
		return
	}
	user, _, err := a.auth.UserBySession(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, 401, "admin browser session required")
		return
	}
	if user.Role != "admin" {
		writeError(w, 403, "admin required")
		return
	}
	if _, scoped := r.Context().Value(scopedProtocolContext{}).(scopedProtocolPrincipal); scoped {
		writeError(w, 403, "protocol key cannot authorize proxy migration")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var body proxyMigrationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, 400, "invalid migration JSON")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "expected one JSON object")
		return
	}
	if body.FromProviderProfileID <= 0 || body.ToProviderProfileID <= 0 || body.FromProviderProfileID == body.ToProviderProfileID || len(body.AccountIDs) > 1000 {
		writeError(w, 400, "distinct from_provider_profile_id and to_provider_profile_id are required; at most 1000 account_ids")
		return
	}
	from, err := a.db.GetProxyProviderProfile(r.Context(), body.FromProviderProfileID)
	if err != nil {
		writeError(w, 400, "source provider profile not found")
		return
	}
	to, err := a.db.GetProxyProviderProfile(r.Context(), body.ToProviderProfileID)
	if err != nil {
		writeError(w, 400, "target provider profile not found")
		return
	}
	targetProvider := migrationProvider(to.Provider)
	if targetProvider != "ipzan" && targetProvider != "juliang" {
		writeError(w, 400, "target must be a supported dynamic provider profile")
		return
	}
	// Validate stored target config without fetching a proxy or using an account.
	if _, err := proxyProfileURLForRegion(to, "", "", ""); err != nil {
		writeError(w, 400, "invalid target provider profile")
		return
	}
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, 500, "account lookup failed")
		return
	}
	selected := make(map[int64]bool, len(body.AccountIDs))
	for _, id := range body.AccountIDs {
		if id <= 0 || selected[id] {
			writeError(w, 400, "account_ids must be unique positive IDs")
			return
		}
		selected[id] = true
	}
	known := make(map[int64]bool, len(accounts))
	result := proxyMigrationResult{Migrated: []proxyMigrationResultItem{}, Skipped: []proxyMigrationResultItem{}}
	plans := make([]store.ProxyMigrationItem, 0)
	catalog := &proxyMigrationCatalog{fetch: a.fetchProxyAreas, cache: map[string]proxyMigrationAreas{}}
	for _, account := range accounts {
		if len(selected) > 0 && !selected[account.ID] {
			continue
		}
		known[account.ID] = true
		setting, err := a.db.GetAccountProxySetting(r.Context(), account.ID)
		if errors.Is(err, sql.ErrNoRows) {
			if selected[account.ID] {
				result.Skipped = append(result.Skipped, proxyMigrationResultItem{AccountID: account.ID, Reason: "source_profile_mismatch"})
			}
			continue
		}
		if err != nil {
			writeError(w, 500, "proxy setting lookup failed")
			return
		}
		if setting.ProviderProfileID == nil || *setting.ProviderProfileID != from.ID {
			if selected[account.ID] {
				result.Skipped = append(result.Skipped, proxyMigrationResultItem{AccountID: account.ID, Reason: "source_profile_mismatch"})
			}
			continue
		}
		reason := ""
		code := ""
		if setting.Mode != "api" {
			reason = "not_dynamic"
		} else {
			code, reason = catalog.remap(r.Context(), from, to, setting)
		}
		if reason == "" {
			if _, err := proxyProfileURLForRegion(to, code, setting.RegionProvince, setting.RegionCity); err != nil {
				reason = "invalid_target_region"
			}
		}
		if reason != "" {
			result.Skipped = append(result.Skipped, proxyMigrationResultItem{AccountID: account.ID, Reason: reason})
			continue
		}
		plans = append(plans, store.ProxyMigrationItem{Account: account, Setting: setting, RegionCode: code})
	}
	for _, id := range body.AccountIDs {
		if !known[id] {
			result.Skipped = append(result.Skipped, proxyMigrationResultItem{AccountID: id, Reason: "account_not_found"})
		}
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Account.ID < plans[j].Account.ID })
	// Serialize with lease extraction. Hold all locks until commit + invalidation;
	// sorted acquisition prevents simultaneous batches deadlocking each other.
	held := make([]chan struct{}, 0, len(plans))
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			<-held[i]
		}
	}()
	for _, plan := range plans {
		lock := a.proxyLeaseLockFor(plan.Account.ID)
		select {
		case lock <- struct{}{}:
			held = append(held, lock)
		case <-r.Context().Done():
			writeError(w, http.StatusRequestTimeout, "migration cancelled")
			return
		}
	}
	if len(plans) > 0 {
		if err := a.db.MigrateAccountProxyProfiles(r.Context(), from, to, plans); err != nil {
			if errors.Is(err, store.ErrProxyMigrationConflict) {
				writeError(w, 409, "migration inputs changed; reload and retry")
			} else {
				writeError(w, 500, "proxy migration rolled back")
			}
			return
		}
	}
	for _, plan := range plans {
		a.invalidateProxyLease(plan.Account.ID)
		result.Migrated = append(result.Migrated, proxyMigrationResultItem{AccountID: plan.Account.ID, RegionCode: plan.RegionCode})
	}
	writeJSON(w, 200, result)
}

func migrationProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return "ipzan"
	}
	return provider
}

type proxyMigrationAreas struct {
	areas []proxyArea
	err   error
}
type proxyMigrationCatalog struct {
	fetch func(context.Context, string) ([]proxyArea, error)
	cache map[string]proxyMigrationAreas
}

func (c *proxyMigrationCatalog) areas(ctx context.Context, endpoint string) ([]proxyArea, error) {
	if result, ok := c.cache[endpoint]; ok {
		return result.areas, result.err
	}
	areas, err := c.fetch(ctx, endpoint)
	c.cache[endpoint] = proxyMigrationAreas{areas: areas, err: err}
	return areas, err
}

// Exact full-name, unique catalog matches only. No suffix stripping, province
// fallback for a missing city, guessed administrative code or copied region table.
func migrationExactArea(areas []proxyArea, name string) (string, bool) {
	code := ""
	count := 0
	for _, area := range areas {
		if strings.TrimSpace(area.Name) == name {
			code = area.Code
			count++
		}
	}
	return code, count == 1 && len(code) == 6 && digitsOnly(code)
}
func (c *proxyMigrationCatalog) remap(ctx context.Context, from, to *store.ProxyProviderProfile, setting *store.AccountProxySetting) (string, string) {
	source, target := migrationProvider(from.Provider), migrationProvider(to.Provider)
	province, city := strings.TrimSpace(setting.RegionProvince), strings.TrimSpace(setting.RegionCity)
	if province == "" {
		return "", "missing_region"
	}
	if source == target && (source == "ipzan" || source == "juliang") {
		code := strings.TrimSpace(setting.RegionCode)
		if code == "" || code == "all" {
			return "", "missing_region_code"
		}
		if source == "ipzan" && (len(code) != 6 || !digitsOnly(code)) {
			return "", "invalid_source_region_code"
		}
		return code, ""
	}
	if target != "ipzan" {
		return "", "target_region_catalog_unavailable"
	}
	provinces, err := c.areas(ctx, ipzanProvinceAreasEndpoint)
	if err != nil {
		return "", "region_catalog_unavailable"
	}
	provinceCode, ok := migrationExactArea(provinces, province)
	if !ok {
		return "", "province_not_unique_exact_match"
	}
	if city == "" {
		return provinceCode, ""
	}
	cities, err := c.areas(ctx, ipzanCityAreasEndpoint+url.QueryEscape(provinceCode))
	if err != nil {
		return "", "region_catalog_unavailable"
	}
	code, ok := migrationExactArea(cities, city)
	if !ok {
		return "", "city_not_unique_exact_match"
	}
	return code, ""
}
