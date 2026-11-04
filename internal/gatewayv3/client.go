package gatewayv3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// GatewayV3Client — public API
// ═══════════════════════════════════════════════════════════════

// Client is the main WeChat Gateway V3 client.
type Client struct {
	Host     string
	Session  string
	Timeout  time.Duration
	tokenMgr *TokenManager
	http     *http.Client
}

// NewClient creates a new Gateway V3 client.
func NewClient(host, session string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}
	return &Client{
		Host:     host,
		Session:  session,
		Timeout:  timeout,
		tokenMgr: newTokenManager(host, session),
		http:     httpClient,
	}
}

// SetRefresher sets a custom token refresh function on the underlying TokenManager.
// When set, refreshToken will call this function instead of the default HTTP /__wx__/auth.
func (c *Client) SetRefresher(f RefreshFunc) {
	c.tokenMgr.SetRefresher(f)
}

// SetToken sets a pre-generated token, bypassing the RefreshFunc.
// GetToken will return this token as long as it is not expired.
func (c *Client) SetToken(token *GatewayToken) {
	c.tokenMgr.SetToken(token)
}

// SetHTTPClient injects the application's proxy-aware, redirect-disabled client.
func (c *Client) SetHTTPClient(client *http.Client) { c.http = client }

// GetToken returns a valid gateway token (with rid).
func (c *Client) GetToken() (*GatewayToken, error) {
	return c.tokenMgr.GetToken()
}

// Call makes a V3 gateway call.
func (c *Client) Call(path, method string, data any, headers map[string]string) (*CallResult, error) {
	return c.CallContext(context.Background(), path, method, data, headers)
}

func (c *Client) CallContext(ctx context.Context, path, method string, data any, headers map[string]string) (*CallResult, error) {
	stats := CallStats{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stats.GetServiceEndpoint = 0

	t1 := time.Now()
	token, err := c.tokenMgr.GetToken()
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	if token == nil || token.Token == "" || token.Key == "" {
		return nil, fmt.Errorf("incomplete gateway token")
	}
	stats.GetServiceEndpoint = time.Since(t1).Milliseconds()

	key, err := base64.StdEncoding.DecodeString(token.Key)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}

	mergedHeaders := map[string]string{}
	for k, v := range headers {
		mergedHeaders[k] = v
	}
	mergedHeaders["X-WX-HTTP-HOST"] = c.Host
	mergedHeaders["X-WX-HTTP-PATH"] = path

	wire, callID, err := v3EncodeRequest(key, mergedHeaders, method, data, path)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	stats.RequestBodyBytes = len(wire)
	stats.CallID = callID
	stats.RequestStartTs = time.Now().UnixMilli()
	stats.Protocol = "v3/unknown"

	target := url.URL{Scheme: "https", Host: c.Host, Path: CallPath}
	target.RawQuery = url.Values{"token": {token.Token}, "callid": {callID}, "devtools_ignore": {"true"}}.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", target.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-WX-EV", "3")
	req.Header.Set("X-WX-RID", token.RID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, newGatewayError("gateway network request failed", -9999)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, newGatewayError(fmt.Sprintf("read body: %v", err), -9999)
	}
	if len(rawBody) > MaxResponseBytes {
		return nil, newGatewayError("gateway response too large", -9999)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newGatewayError(fmt.Sprintf("gateway HTTP %d", resp.StatusCode), resp.StatusCode)
	}

	stats.RequestSuccessTs = time.Now().UnixMilli()
	stats.HTTPRequest = stats.RequestSuccessTs - stats.RequestStartTs
	stats.ResponseBodyBytes = len(rawBody)

	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if contentType != "application/octet-stream" {
		var errJSON struct {
			Ret    int    `json:"ret"`
			ErrMsg string `json:"errmsg"`
		}
		if json.Unmarshal(rawBody, &errJSON) == nil && errJSON.Ret != 0 {
			return nil, newGatewayError(errJSON.ErrMsg, errJSON.Ret)
		}
		return nil, newGatewayError(
			fmt.Sprintf("unexpected content-type '%s'", contentType),
			-9999,
		)
	}

	decoded, err := v3DecodeResponse(key, rawBody)
	if err != nil {
		return nil, newGatewayError(
			fmt.Sprintf("gateway decode failed: %v", err),
			-9999,
		)
	}

	stats.ResponseProcessEndTs = time.Now().UnixMilli()
	stats.StatusCode = decoded.StatusCode
	stats.Ret = 0

	body := decoded.Body
	bodyStr := decoded.BodyString
	if len(body) == 0 && bodyStr != "" {
		body = []byte(bodyStr)
	}

	result := &CallResult{
		StatusCode: decoded.StatusCode,
		Header:     decoded.Header,
		CallID:     callID,
		ErrMsg:     "gateway.request:ok",
		Stats:      stats,
	}

	if len(body) > 0 {
		if json.Valid(body) {
			result.Data = body
		} else {
			encoded, _ := json.Marshal(string(body))
			result.Data = encoded
		}
	}

	return result, nil
}
