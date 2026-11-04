package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"yyb_go/internal/eventlog"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

// handleGetHostSign implements the verifyplugin / HostSign compatibility API
// on top of the target account, pacing and circuit-breaker pipeline. The body
// uses the standard wxappRequest shape (ref + app_id + payload); payload
// validation happens before account resolution or proxy acquisition.
func (a *App) handleGetHostSign(w http.ResponseWriter, r *http.Request) {
	a.handleHostSignCall(w, r, a.invokeGetHostSign)
}

func (a *App) handleHostSignCall(w http.ResponseWriter, r *http.Request, call wxappCall) {
	if r.URL.Path != "/wxapp/getHostSign" && r.URL.Path != "/Wxapp/GetHostSign" && r.URL.Path != "/api/Wxapp/GetHostSign" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !acceptWXAppRoute(w, r, r.URL.Path) {
		return
	}
	if !a.authorizeProtocol(w, r) {
		return
	}
	var body struct {
		wxappRequest
		LegacyAppID string  `json:"appid"`
		OpenID      string  `json:"openid"`
		Data        any     `json:"data"`
		Plugins     any     `json:"plugins"`
		Provider    string  `json:"provider"`
		Version     any     `json:"inner_version"`
		ProxyURL    *string `json:"proxyUrl"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Ref == "" {
		body.Ref = strings.TrimSpace(body.OpenID)
	}
	if body.AppID == "" {
		body.AppID = strings.TrimSpace(body.LegacyAppID)
	}
	proxyCtx, proxyErr := withRequestProxy(r.Context(), body.ProxyURL)
	if proxyErr != nil {
		writeError(w, http.StatusBadRequest, proxyErr.Error())
		return
	}
	r = r.WithContext(proxyCtx)
	if body.Data != nil {
		body.Payload = map[string]any{"data": body.Data}
	} else if body.Payload == nil && body.Plugins != nil {
		body.Payload = map[string]any{"plugins": body.Plugins}
	} else if body.Payload == nil && body.Provider != "" {
		body.Payload = map[string]any{"provider": body.Provider, "inner_version": body.Version}
	}
	raw, err := json.Marshal(body.wxappRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	request := r.Clone(r.Context())
	request.Body = io.NopCloser(bytes.NewReader(raw))
	a.callWXApp(w, withWXOperation(request, eventlog.OpOperateWXData), true, call, validateHostSign)
}

func validateHostSign(appID string, payload map[string]any) error {
	if len(appID) != 18 || !strings.HasPrefix(appID, "wx") || strings.IndexFunc(appID[2:], func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') }) >= 0 {
		return fmt.Errorf("getHostSign: invalid app_id")
	}
	_, err := protocol.NormalizeHostSignPayload(payload)
	return err
}

func (a *App) invokeGetHostSign(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, proxyValue string, fallbackDirect bool) (map[string]any, error) {
	return a.pool.GetHostSign(ctx, acc.LoginBuffer, appID, payload, acc.ID, proxyValue, fallbackDirect, acc)
}
