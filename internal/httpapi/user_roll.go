package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func (a *App) invokeGetA8Key(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.GetA8Key(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxy, fallback, acc)
}
func (a *App) handleGetA8Key(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getA8Key") {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpOperateWXData), true, a.invokeGetA8Key, func(appID string, payload map[string]any) error {
		if !validGatewayAppID(appID) {
			return fmt.Errorf("invalid app_id")
		}
		_, _, _, err := protocol.NormalizeA8KeyPayload(payload)
		return err
	})
}

type userRollFetch func(context.Context, map[string]any, string) (map[string]any, error)

func (a *App) handleUserRollList(w http.ResponseWriter, r *http.Request) {
	a.handleUserRollCall(w, r, a.invokeGetA8Key, requestUserRoll)
}
func (a *App) handleUserRollCall(w http.ResponseWriter, r *http.Request, a8call wxappCall, fetch userRollFetch) {
	if !a.authorizeProtocol(w, r) {
		return
	}
	if !acceptWXAppRoute(w, r, "/wxapp/userRollList") {
		return
	}
	var body wxappRequest
	if decodeOptionalJSON(r, &body) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	proxyCtx, proxyErr := withRequestProxy(r.Context(), body.ProxyURL)
	if proxyErr != nil {
		writeError(w, 400, proxyErr.Error())
		return
	}
	r = r.WithContext(proxyCtx)
	target, biz, _, err := protocol.NormalizeA8KeyPayload(body.Payload)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, err = userRollURL(target); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if body.AppID == "" {
		body.AppID = "wxd44977328b36e647"
	}
	if !validGatewayAppID(body.AppID) {
		writeError(w, 400, "invalid app_id")
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	plannedCtx, _, _, err := a.wxappProxyPlan(r.Context(), acc.ID)
	if err != nil {
		writeError(w, 403, "request proxy is not allowed")
		return
	}
	r = r.WithContext(plannedCtx)
	payload := make(map[string]any, len(body.Payload)+2)
	for key, value := range body.Payload {
		payload[key] = value
	}
	payload["target_url"] = target
	payload["biz_username"] = biz
	if _, exists := payload["scene"]; !exists {
		payload["scene"] = 0
	}
	proxy := ""
	call := func(ctx context.Context, account *store.WechatAccount, appID string, data map[string]any, value string, fallback bool) (map[string]any, error) {
		proxy = value
		return a8call(ctx, account, appID, data, value, fallback)
	}
	raw, err := a.invokeWXApp(withWXOperationContext(r.Context(), eventlog.OpOperateWXData), acc, body.AppID, payload, call)
	if err != nil {
		writeProtocolCallError(w, err)
		return
	}
	// Keep the business GET outside credential recovery and its retries.
	result, err := fetch(r.Context(), raw, proxy)
	if err != nil {
		writeError(w, 502, "userRollList request failed")
		return
	}
	writeJSON(w, 200, map[string]any{"openid": acc.OpenID, "result": result})
}
func userRollURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return nil, fmt.Errorf("target_url must be an HTTPS WeChat/Tenpay URL")
	}
	host := strings.ToLower(u.Hostname())
	if host != "weixin.qq.com" && !strings.HasSuffix(host, ".weixin.qq.com") && host != "tenpay.com" && !strings.HasSuffix(host, ".tenpay.com") {
		return nil, fmt.Errorf("target_url must use a WeChat/Tenpay hostname")
	}
	return u, nil
}
func requestUserRoll(ctx context.Context, result map[string]any, proxy string) (map[string]any, error) {
	transport, err := protocol.NewHTTPTransport(proxy, false)
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return fetchUserRoll(ctx, client, result)
}
func fetchUserRoll(ctx context.Context, client *http.Client, result map[string]any) (map[string]any, error) {
	full, _ := result["full_url"].(string)
	u, err := userRollURL(full)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/7.0.12")
	if cookie, ok := result["cookie"].(string); ok {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userRollList request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	const limit = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(raw) > limit {
		return nil, fmt.Errorf("invalid or oversized response")
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	return data, nil
}
