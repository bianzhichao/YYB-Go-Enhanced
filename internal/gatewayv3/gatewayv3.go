package gatewayv3

import (
	"encoding/json"
	"fmt"
)

// ═══════════════════════════════════════════════════════════════
// Constants (gatewayV3.js)
// ═══════════════════════════════════════════════════════════════

const (
	LibBuildTS       = 1784279218415       // L18121 x-wx-lib-build-ts
	AcceptEncryption = 3                   // L18119 x-wx-accept-encryption
	AuthPath         = "/__wx__/auth"      // L18116
	CallPath         = "/__wx__/call"      // L18186
	KeepalivePath    = "/__wx__/keepalive" // L18256
	AESBlockSize     = 16                  // IV and block size for AES-CBC
	MaxResponseBytes = 8 << 20             // Maximum wire/decompressed response size: 8 MiB.
)

// GatewayToken holds the authentication token returned by /__wx__/auth.
type GatewayToken struct {
	Key       string `json:"key"`        // base64 AES-256 key
	Token     string `json:"token"`      // auth token string
	RID       string `json:"rid"`        // request ID (server-issued)
	Exp       int64  `json:"exp"`        // absolute expiry timestamp (ms)
	Timestamp int64  `json:"timestamp"`  // issued-at timestamp (ms)
	ExpiresIn int    `json:"expires_in"` // validity duration (seconds)
}

// IsExpired returns true if the token is past its expiry.
func (t *GatewayToken) IsExpired() bool {
	return t == nil || t.Exp <= nowMs()
}

// CallResult holds the result of a V3 gateway call.
type CallResult struct {
	Data       json.RawMessage   `json:"data"`       // response body (pre-parsed if JSON)
	StatusCode int               `json:"statusCode"` // HTTP status
	Header     map[string]string `json:"header"`     // response headers
	CallID     string            `json:"callID"`     // gateway call ID
	ErrMsg     string            `json:"errMsg"`     // "gateway.request:ok" or error
	Stats      CallStats         `json:"stats"`      // performance stats
}

// CallStats holds performance timing data.
type CallStats struct {
	Protocol             string `json:"protocol"`
	Domain               string `json:"domain"`
	CallID               string `json:"callid"`
	GetServiceEndpoint   int64  `json:"getServiceEndpoint"`
	RequestBodyBytes     int    `json:"requestBodyBytes"`
	RequestStartTs       int64  `json:"requestStartTs"`
	RequestSuccessTs     int64  `json:"requestSuccessTs"`
	HTTPRequest          int64  `json:"httpRequest"`
	ResponseBodyBytes    int    `json:"responseBodyBytes"`
	ResponseProcessEndTs int64  `json:"responseProcessEndTs"`
	StatusCode           int    `json:"statusCode"`
	Ret                  int    `json:"ret"`
	Backend              string `json:"backend,omitempty"`
}

// GatewayError is an error with an associated error code.
type GatewayError struct {
	Msg  string
	Code int
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("gateway.request: %s (errCode=%d)", e.Msg, e.Code)
}

func newGatewayError(msg string, code int) *GatewayError {
	return &GatewayError{Msg: msg, Code: code}
}
