package httpapi

import (
	"context"
	"net/http"
	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func (a *App) handleCheckShortUrl(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/checkShortUrl") {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpOperateWXData), true, a.invokeCheckShortUrl, protocol.ValidateCheckShortURL)
}
func (a *App) handleWxaAttrSync(w http.ResponseWriter, r *http.Request) {
	// The source alias called a handler that rejected its own alias path.
	switch r.URL.Path {
	case "/wxapp/wxaAttrSync", "/wxapp/wxaAppSync":
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !acceptWXAppRoute(w, r, r.URL.Path) {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpOperateWXData), true, a.invokeWxaAttrSync, protocol.ValidateWxaAttrSync)
}
func (a *App) handleWxaAppSync(w http.ResponseWriter, r *http.Request) { a.handleWxaAttrSync(w, r) }
func (a *App) handleGetWxaCDNDownloadUrl(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getWxaCDNDownloadUrl") {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpOperateWXData), true, a.invokeGetWxaCDNDownloadUrl, protocol.ValidateWxaCDNDownloadURL)
}
func (a *App) invokeCheckShortUrl(ctx context.Context, acc *store.WechatAccount, _ string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.CheckShortUrl(ctx, acc.LoginBuffer, payload, acc.ID, proxy, fallback, acc)
}
func (a *App) invokeWxaAttrSync(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.WxaAttrSync(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxy, fallback, acc)
}
func (a *App) invokeGetWxaCDNDownloadUrl(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.GetWxaCDNDownloadUrl(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxy, fallback, acc)
}
