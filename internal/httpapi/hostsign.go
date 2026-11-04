package httpapi

import (
	"context"
	"net/http"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/store"
)

// handleGetHostSign implements the verifyplugin / HostSign compatibility API
// on top of the target account, pacing and circuit-breaker pipeline. The body
// uses the standard wxappRequest shape (ref + app_id + payload); payload
// normalization and validation happen inside protocol.GetHostSign.
func (a *App) handleGetHostSign(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getHostSign") {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpOperateWXData), false, a.invokeGetHostSign)
}

func (a *App) invokeGetHostSign(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxyValue string, fallbackDirect bool) (map[string]any, error) {
	return a.pool.GetHostSign(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxyValue, fallbackDirect)
}
