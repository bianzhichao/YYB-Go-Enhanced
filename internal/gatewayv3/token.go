package gatewayv3

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Token management
// ═══════════════════════════════════════════════════════════════

// RefreshFunc is a custom token refresh function. It receives host and session
// and must return a valid GatewayToken. Typically backed by operateWXData.
type RefreshFunc func(host, session string) (*GatewayToken, error)

// TokenManager handles token lifecycle.
type TokenManager struct {
	host      string
	session   string
	current   *GatewayToken
	refresher RefreshFunc
}

func newTokenManager(host, session string) *TokenManager {
	return &TokenManager{
		host:    host,
		session: session,
	}
}

// SetRefresher sets the token refresh function. Must be called before
// GetToken, otherwise refresh will return an error.
func (tm *TokenManager) SetRefresher(f RefreshFunc) {
	tm.refresher = f
}

// SetToken sets a pre-generated token, bypassing the RefreshFunc.
func (tm *TokenManager) SetToken(token *GatewayToken) {
	tm.current = token
}

// GetToken returns a valid token, refreshing if necessary.
func (tm *TokenManager) GetToken() (*GatewayToken, error) {
	if tm.current != nil && !tm.current.IsExpired() {
		return tm.current, nil
	}
	return tm.refreshToken()
}

// GetTokenSync returns the current token or nil if expired/unavailable.
func (tm *TokenManager) GetTokenSync() *GatewayToken {
	if tm.current != nil && !tm.current.IsExpired() {
		return tm.current
	}
	return nil
}

// refreshToken delegates to the configured RefreshFunc.
func (tm *TokenManager) refreshToken() (*GatewayToken, error) {
	if tm.refresher == nil {
		return nil, fmt.Errorf("token refresher not set")
	}
	token, err := tm.refresher(tm.host, tm.session)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	tm.current = token
	return token, nil
}

// NormalizeToken normalizes a raw token map (from /__wx__/auth or operateWXData)
// into a GatewayToken. Exported for use by custom RefreshFunc implementations.
func NormalizeToken(raw map[string]any) *GatewayToken {
	return normalizeToken(raw)
}

// normalizeToken normalizes a raw token from /__wx__/auth or operateWXData.
// Handles flat format, nested {data: {...}}, and nested {data: "<json>"} formats.
func normalizeToken(raw map[string]any) *GatewayToken {
	// operateWXData wraps the result in "data" — either as a map or a JSON string
	if data, ok := raw["data"].(map[string]any); ok {
		raw = data
	} else if dataStr, ok := raw["data"].(string); ok && dataStr != "" {
		var parsed map[string]any
		if json.Unmarshal([]byte(dataStr), &parsed) == nil {
			raw = parsed
		}
	}

	var timestampMs int64
	var expiresIn int

	if iat, ok := raw["iat"]; ok {
		if v, ok := toInt64(iat); ok {
			timestampMs = v * 1000
		}
		if exp, ok := raw["exp"]; ok {
			if v, ok := toInt64(exp); ok {
				expiresIn = int(v) - int(timestampMs/1000)
			}
		}
	} else {
		if v, ok := toInt64(raw["timestamp"]); ok {
			timestampMs = v
		}
		if v, ok := raw["expires_in"]; ok {
			expiresIn = toInt(v)
		}
	}

	exp := calcExpiry(timestampMs, expiresIn)

	return &GatewayToken{
		Key:       toString(raw["key"]),
		Token:     toString(raw["token"]),
		RID:       toString(raw["rid"]),
		Exp:       exp,
		Timestamp: timestampMs,
		ExpiresIn: expiresIn,
	}
}

// calcExpiry computes token expiry with 80% proactive refresh.
func calcExpiry(timestampMs int64, expiresInSec int) int64 {
	nowMs := time.Now().UnixMilli()
	eightyPctMs := int64(float64(expiresInSec) * 0.8 * 1000)
	if expiresInSec <= 0 {
		return 0
	}
	if timestampMs == 0 {
		timestampMs = nowMs
	}
	return timestampMs + eightyPctMs
}

// ═══════════════════════════════════════════════════════════════
// operateWXData payload helpers
// ═══════════════════════════════════════════════════════════════

// BuildCliReqID builds a cli_req_id in the format "{ts_ms}_{random}".
func BuildCliReqID(tsMs int64) string {
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return fmt.Sprintf("%d", tsMs)
	}
	return fmt.Sprintf("%d_%d", tsMs, nonce.Int64())
}

// BuildAuthPayload builds the operateWXData payload for token refresh.
// domain is the service domain (e.g. "a1d5ae6e7-wx621112590b635086.sh.wxcloudrun.com").
func BuildAuthPayload(domain string) map[string]any {
	tsMs := time.Now().UnixMilli()
	qbaseReq := map[string]any{
		"system": "HarmonyOS",
		"scene":  3,
		"domain": domain,
	}
	qbaseReqJSON, _ := json.Marshal(qbaseReq)

	return map[string]any{
		"api_name": "qbase_commapi",
		"data": map[string]any{
			"qbase_api_name": "tcbapi_get_service_info",
			"qbase_req":      string(qbaseReqJSON),
			"cli_req_id":     BuildCliReqID(tsMs),
		},
		"operate_directly": true,
		"env":              float64(1),
	}
}

// -- type helpers --

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func toInt(v any) int {
	if n, ok := toInt64(v); ok {
		return int(n)
	}
	return 0
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if n, ok := toInt64(v); ok {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%v", v)
}
