package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func articleExtURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 16384 || u.Scheme != "https" || u.Host != "mp.weixin.qq.com" || u.User != nil || u.Fragment != "" || (u.Path != "/s" && !strings.HasPrefix(u.Path, "/s/")) {
		return nil, fmt.Errorf("article URL must use HTTPS mp.weixin.qq.com/s")
	}
	return u, nil
}
func (a *App) handleGetAppMsgExt(w http.ResponseWriter, r *http.Request) {
	a.handleAppMsgExtCall(w, r, a.invokeGetA8Key, appMsgExtFromA8Key)
}
func (a *App) handleAppMsgExtCall(w http.ResponseWriter, r *http.Request, a8call wxappCall, fetch userRollFetch) {
	if !acceptWXAppRoute(w, r, "/wxapp/getAppMsgExt") || !a.authorizeProtocol(w, r) {
		return
	}
	var body oauthProtocolRequest
	if decodeOptionalJSON(r, &body) != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	body.normalize()
	if body.AppID == "" {
		body.AppID = "wxd44977328b36e647"
	}
	if !runtimeAppIDValid(body.AppID) {
		writeError(w, 400, "invalid app_id")
		return
	}
	if body.Payload == nil {
		body.Payload = map[string]any{}
	}
	target, _ := body.Payload["target_url"].(string)
	if target == "" {
		target = runtimeFirstNonEmpty(body.TargetURL, body.ArticleURL)
		body.Payload["target_url"] = target
	}
	if body.BizUsername != "" {
		body.Payload["biz_username"] = body.BizUsername
	}
	if _, err := articleExtURL(target); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, _, _, err := protocol.NormalizeA8KeyPayload(body.Payload); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	requestCtx, proxyErr := withRequestProxy(r.Context(), body.Proxy)
	if proxyErr != nil {
		writeError(w, 400, proxyErr.Error())
		return
	}
	ctx, cancel := context.WithTimeout(requestCtx, 60*time.Second)
	defer cancel()
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	proxyValue := ""
	result, err := a.invokeWXApp(withWXOperationContext(ctx, eventlog.OpOperateWXData), acc, body.AppID, body.Payload, func(ctx context.Context, account *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
		proxyValue = proxy
		out, err := a8call(ctx, account, appID, payload, proxy, false)
		return out, protocol.MarkNoRetry(err)
	})
	if err != nil {
		writeProtocolCallError(w, err)
		return
	}
	out, err := fetch(ctx, result, proxyValue)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"openid": acc.OpenID, "result": out})
}
func appMsgExtFromA8Key(ctx context.Context, result map[string]any, proxy string) (map[string]any, error) {
	client, err := oauthHTTPClient(proxy, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	return requestAppMsgExt(ctx, client, result)
}
func requestAppMsgExt(ctx context.Context, client *http.Client, result map[string]any) (map[string]any, error) {
	fullURL, _ := result["full_url"].(string)
	u, err := articleExtURL(fullURL)
	if err != nil {
		return nil, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid article query")
	}
	for _, key := range []string{"pass_ticket", "__biz", "mid", "sn", "idx"} {
		if q.Get(key) == "" || len(q[key]) != 1 {
			return nil, fmt.Errorf("article authorization parameters missing")
		}
	}
	cookie, _ := result["cookie"].(string)
	if len(cookie) > 16384 || strings.ContainsAny(cookie, "\r\n") {
		return nil, fmt.Errorf("invalid article cookie")
	}
	headers := http.Header{"User-Agent": {"Mozilla/5.0 MicroMessenger/7.0.12"}}
	if cookie != "" {
		headers.Set("Cookie", cookie)
	}
	article, getStatus, err := oauthHTTPOnce(ctx, client, http.MethodGet, fullURL, "", headers)
	if err != nil {
		return nil, err
	}
	values := url.Values{"f": {"json"}, "mock": {""}, "fasttmplajax": {"1"}, "uin": {""}, "key": {""}, "pass_ticket": {q.Get("pass_ticket")}, "wxtoken": {""}, "devicetype": {"UnifiedPCWindows"}, "clientversion": {"80101"}, "__biz": {q.Get("__biz")}, "appmsg_token": {""}, "x5": {"0"}, "wx_header": {"1"}}
	data := url.Values{"r": {""}, "__biz": {q.Get("__biz")}, "appmsg_type": {"9"}, "mid": {q.Get("mid")}, "sn": {q.Get("sn")}, "idx": {q.Get("idx")}, "scene": {"126"}, "title": {""}, "ct": {fmt.Sprint(time.Now().Unix())}, "devicetype": {"UnifiedPCWindows"}, "version": {"80101"}, "is_need_ticket": {"0"}, "is_need_ad": {"0"}, "is_need_reward": {"0"}, "both_ad": {"0"}, "reward_uin_count": {"0"}, "msg_daily_idx": {"1"}, "is_original": {"0"}, "is_only_read": {"1"}, "pass_ticket": {q.Get("pass_ticket")}, "is_temp_url": {"0"}, "item_show_type": {"0"}, "more_read_type": {"0"}, "appmsg_like_type": {"2"}, "is_pay_subscribe": {"0"}, "pay_subscribe_uin_count": {"0"}, "has_red_packet_cover": {"0"}}
	// Use the final article cookies received by the client jar. Do not replace
	// global transports or forward credentials to any other host.
	if client.Jar != nil {
		cookies := client.Jar.Cookies(u)
		if len(cookies) > 0 {
			parts := make([]string, 0, len(cookies))
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			headers.Set("Cookie", strings.Join(parts, "; "))
		}
	}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, status, err := oauthHTTPOnce(ctx, client, http.MethodPost, "https://mp.weixin.qq.com/mp/getappmsgext?"+values.Encode(), data.Encode(), headers)
	if err != nil {
		return nil, err
	}
	var reply map[string]any
	if json.Unmarshal(raw, &reply) != nil || reply == nil {
		return nil, fmt.Errorf("AppMsgExt response is not a JSON object")
	}
	if base, ok := reply["base_resp"].(map[string]any); ok {
		if ret, exists := base["ret"]; exists && ret != float64(0) {
			return nil, fmt.Errorf("AppMsgExt upstream rejected request")
		}
	}
	first := func(keys ...string) any {
		for _, key := range keys {
			if v, ok := reply[key]; ok {
				return v
			}
		}
		return nil
	}
	preview := string(article)
	if len(preview) > 4096 {
		preview = preview[:4096]
	}
	list, _ := reply["more_read_list"].([]any)
	return map[string]any{"status": true, "message": "成功", "data": map[string]any{"article_body_preview": preview, "full_url": fullURL, "get_status_code": getStatus, "status_code": status, "raw": string(raw), "json": reply, "like_count": first("like_num", "old_like_num", "appmsgstat_like_num"), "share_count": first("share_count", "appmsgstat_share_num"), "is_recommended": len(list) > 0, "is_recommended_source": "more_read_list.length"}}, nil
}
