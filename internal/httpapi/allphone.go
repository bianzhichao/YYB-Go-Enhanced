package httpapi

import (
	"context"
	"net/http"
	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

func (a *App) handleGetAllPhone(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/wxapp/getAllPhone", "/wx/getallphonenumber":
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !acceptWXAppRoute(w, r, r.URL.Path) {
		return
	}
	a.callWXApp(w, withWXOperation(r, eventlog.OpGetPhoneNumber), false, a.invokeGetAllPhone, protocol.ValidateGetAllPhone)
}
func (a *App) invokeGetAllPhone(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any, proxy string, fallback bool) (map[string]any, error) {
	return a.pool.GetAllPhone(ctx, acc.LoginBuffer, appID, acc.ID, proxy, fallback, acc)
}
