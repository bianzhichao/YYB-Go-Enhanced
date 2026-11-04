package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

type oauthProtocolRequest struct {
	Ref            string         `json:"ref"`
	OpenID         string         `json:"openid"`
	AppID          string         `json:"app_id"`
	LegacyAppID    string         `json:"appid"`
	Payload        map[string]any `json:"payload"`
	Proxy          *string        `json:"proxyUrl"`
	OAuthURL       string         `json:"oauth_url"`
	RedirectURI    string         `json:"redirect_uri"`
	Scope          string         `json:"scope"`
	State          string         `json:"state"`
	ComponentAppID string         `json:"component_appid"`
	ForcePopup     bool           `json:"forcePopup"`
	Scene          any            `json:"scene"`
	BundleID       string         `json:"bundleid"`
	ArticleURL     string         `json:"article_url"`
	TargetURL      string         `json:"target_url"`
	BizUsername    string         `json:"biz_username"`
}

func (body *oauthProtocolRequest) normalize() {
	body.Ref = runtimeFirstNonEmpty(body.Ref, body.OpenID)
	body.AppID = runtimeFirstNonEmpty(body.AppID, body.LegacyAppID)
}
func (a *App) handleOauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/oauthAuthorize") || !a.authorizeProtocol(w, r) {
		return
	}
	var body oauthProtocolRequest
	if decodeOptionalJSON(r, &body) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	body.normalize()
	if body.Payload == nil {
		body.Payload = map[string]any{"redirect_uri": body.RedirectURI, "scope": body.Scope, "state": body.State, "component_appid": body.ComponentAppID, "forcePopup": body.ForcePopup}
		if body.Scene != nil {
			body.Payload["scene"] = body.Scene
		}
		if body.OAuthURL != "" {
			body.Payload = map[string]any{"target_url": body.OAuthURL}
			if body.AppID == "" {
				if u, e := url.Parse(body.OAuthURL); e == nil {
					body.AppID = u.Query().Get("appid")
				}
			}
		}
	}
	if _, _, err := protocol.NormalizeOAuthAuthorize(body.AppID, body.Payload); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ctx, proxyErr := withRequestProxy(r.Context(), body.Proxy)
	if proxyErr != nil {
		writeError(w, 400, proxyErr.Error())
		return
	}
	request := r.Clone(ctx)
	raw, err := json.Marshal(wxappRequest{Ref: body.Ref, AppID: body.AppID, Payload: body.Payload})
	if err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(raw))
	a.callWXApp(w, withWXOperation(request, eventlog.OpOperateWXData), true, a.invokeOauthAuthorize, func(appID string, payload map[string]any) error {
		_, _, err := protocol.NormalizeOAuthAuthorize(appID, payload)
		return err
	})
}
func (a *App) invokeOauthAuthorize(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.OauthAuthorize(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxy, fallback, acc)
}

func oauthHTTPClient(proxy string, timeout time.Duration) (*http.Client, error) {
	transport, err := protocol.NewHTTPTransport(proxy, false)
	if err != nil {
		return nil, fmt.Errorf("OAuth proxy setup failed")
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: transport, Timeout: timeout, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// oauthHTTPOnce bounds every response and never follows a redirect. Errors omit
// signed URLs, cookies, tickets and response bodies.
func oauthHTTPOnce(ctx context.Context, client *http.Client, method, endpoint, body string, headers http.Header) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("OAuth request creation failed")
	}
	req.Header = headers.Clone()
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := bounded.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("OAuth upstream connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("OAuth upstream HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, resp.StatusCode, fmt.Errorf("OAuth unreadable or oversized response")
	}
	return raw, resp.StatusCode, nil
}

var qrUUIDPattern = regexp.MustCompile(`uuid\s*:\s*"([A-Za-z0-9_-]{1,128})"`)
var oauthRedirectPattern = regexp.MustCompile(`window\.wx_redirecturl\s*=\s*['"]([^'"\r\n]+)['"]`)

func getQRConnectUUID(ctx context.Context, client *http.Client, appID, bundleID string) (string, error) {
	endpoint := "https://open.weixin.qq.com/connect/app/qrconnect?" + url.Values{"appid": {appID}, "bundleid": {bundleID}, "scope": {"snsapi_userinfo"}, "state": {""}, "pass_ticket": {""}}.Encode()
	raw, _, err := oauthHTTPOnce(ctx, client, http.MethodGet, endpoint, "", http.Header{"User-Agent": {"Mozilla/5.0 MicroMessenger/7.0.20 WindowsWechat"}})
	if err != nil {
		return "", err
	}
	match := qrUUIDPattern.FindSubmatch(raw)
	if len(match) != 2 {
		return "", fmt.Errorf("QR connect UUID missing")
	}
	return string(match[1]), nil
}
func confirmOAuthURL(raw, uuid string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "open.weixin.qq.com" || u.Path != "/connect/confirm" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid OAuth confirmation URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Get("uuid") != uuid || len(q["uuid"]) != 1 {
		return nil, fmt.Errorf("OAuth confirmation UUID mismatch")
	}
	for _, key := range []string{"pass_ticket", "key", "uin"} {
		if q.Get(key) == "" || len(q[key]) != 1 {
			return nil, fmt.Errorf("OAuth confirmation credentials missing")
		}
	}
	return u, nil
}
func postConfirmReply(ctx context.Context, client *http.Client, fullURL, uuid string) (map[string]any, error) {
	u, err := confirmOAuthURL(fullURL, uuid)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	form := url.Values{"pass_ticket": {q.Get("pass_ticket")}, "key": {q.Get("key")}, "uin": {q.Get("uin")}, "uuid": {uuid}, "snsapi_userinfo": {"on"}, "allow": {"allow"}}
	raw, status, err := oauthHTTPOnce(ctx, client, http.MethodPost, "https://open.weixin.qq.com/connect/confirm_reply", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Referer": {fullURL}, "Origin": {"https://open.weixin.qq.com"}})
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) == nil {
		for _, key := range []string{"errcode", "ret"} {
			if v, ok := result[key]; ok {
				var code int64
				if json.Unmarshal(v, &code) != nil || code != 0 {
					return nil, fmt.Errorf("OAuth confirmation rejected")
				}
			}
		}
	}
	return map[string]any{"status": status}, nil
}
func getOAuthCode(ctx context.Context, client *http.Client, uuid string) (string, error) {
	raw, _, err := oauthHTTPOnce(ctx, client, http.MethodGet, "https://long.open.weixin.qq.com/connect/l/qrconnect?"+url.Values{"uuid": {uuid}, "f": {"url"}, "_": {fmt.Sprint(time.Now().UnixMilli())}}.Encode(), "", nil)
	if err != nil {
		return "", err
	}
	match := oauthRedirectPattern.FindSubmatch(raw)
	if len(match) != 2 {
		return "", fmt.Errorf("OAuth authorization pending or code unavailable")
	}
	u, err := url.Parse(string(match[1]))
	if err != nil || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", fmt.Errorf("invalid OAuth code redirect")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Get("code") == "" || len(q["code"]) != 1 || len(q.Get("code")) > 4096 {
		return "", fmt.Errorf("OAuth code missing")
	}
	return q.Get("code"), nil
}
func (a *App) handleThirdAppAuthorize(w http.ResponseWriter, r *http.Request) {
	a.handleThirdAppAuthorizeCall(w, r, a.invokeGetA8Key, nil)
}
func (a *App) handleThirdAppAuthorizeCall(w http.ResponseWriter, r *http.Request, a8call wxappCall, testClient *http.Client) {
	if !acceptWXAppRoute(w, r, "/wxapp/thirdAppAuthorize") || !a.authorizeProtocol(w, r) {
		return
	}
	var body oauthProtocolRequest
	if decodeOptionalJSON(r, &body) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	body.normalize()
	if !runtimeAppIDValid(body.AppID) || strings.TrimSpace(body.BundleID) == "" || len(body.BundleID) > 512 {
		writeError(w, 400, "valid app_id and bundleid are required")
		return
	}
	requestCtx, proxyErr := withRequestProxy(r.Context(), body.Proxy)
	if proxyErr != nil {
		writeError(w, 400, proxyErr.Error())
		return
	}
	ctx, cancel := context.WithTimeout(requestCtx, 90*time.Second)
	defer cancel()
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	plannedCtx, proxy, _, err := a.wxappProxyPlan(ctx, acc.ID)
	if err != nil {
		writeError(w, 502, "OAuth proxy lookup failed")
		return
	}
	ctx = plannedCtx
	client := testClient
	if client == nil {
		client, err = oauthHTTPClient(proxy, 35*time.Second)
		if err != nil {
			writeError(w, 502, err.Error())
			return
		}
		defer client.CloseIdleConnections()
	}
	uuid, err := getQRConnectUUID(ctx, client, body.AppID, body.BundleID)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	// A8Key resolves the signed confirmation URL; GET/consent/long-poll are kept
	// outside the recoverable callback and each executed at most once.
	result, err := a.invokeWXApp(withWXOperationContext(ctx, eventlog.OpOperateWXData), acc, "wxd44977328b36e647", map[string]any{"target_url": "https://open.weixin.qq.com/connect/confirm?" + url.Values{"uuid": {uuid}}.Encode(), "scene": 4}, func(ctx context.Context, account *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
		out, err := a8call(ctx, account, appID, payload, proxy, false)
		return out, protocol.MarkNoRetry(err)
	})
	if err != nil {
		writeProtocolCallError(w, err)
		return
	}
	fullURL, _ := result["full_url"].(string)
	if _, err = confirmOAuthURL(fullURL, uuid); err != nil {
		writeError(w, 502, err.Error())
		return
	}
	if _, _, err = oauthHTTPOnce(ctx, client, http.MethodGet, fullURL, "", nil); err != nil {
		writeError(w, 502, err.Error())
		return
	}
	confirmation, err := postConfirmReply(ctx, client, fullURL, uuid)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	code, err := getOAuthCode(ctx, client, uuid)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"openid": acc.OpenID, "code": code, "confirmResult": confirmation})
}
