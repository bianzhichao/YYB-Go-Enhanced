package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

type runtimePayRequest struct {
	ProxyURL      *string `json:"proxyUrl"`
	Ref           string  `json:"ref"`
	OpenID        string  `json:"openid"`
	AppID         string  `json:"appid"`
	AppIDAlt      string  `json:"app_id"`
	Package       string  `json:"package"`
	PaySign       string  `json:"paySign"`
	NonceStr      string  `json:"nonceStr"`
	TimeStamp     string  `json:"timeStamp"`
	SignType      string  `json:"signType"`
	RuntimeTicket string  `json:"runtimeTicket"`
}

func isRuntimePayRoute(path string) bool {
	switch path {
	case "/wxapp/getRuntimeSession", "/wxapp/getPayQRCode", "/Wxapp/JSGetSessionid", "/api/Wxapp/JSGetSessionid":
		return true
	default:
		return false
	}
}

func (r *runtimePayRequest) validate(payment bool) error {
	r.Ref = runtimeFirstNonEmpty(r.Ref, r.OpenID)
	r.AppID = runtimeFirstNonEmpty(r.AppIDAlt, r.AppID)
	if r.Ref == "" || !runtimeAppIDValid(r.AppID) {
		return fmt.Errorf("ref and a valid appid are required")
	}
	if !payment {
		return nil
	}
	if r.SignType == "" {
		r.SignType = "MD5" // Source default. Must match the merchant-provided paySign; never recompute it here.
	}
	if r.SignType != "MD5" && r.SignType != "RSA" && r.SignType != "HMAC-SHA256" {
		return fmt.Errorf("unsupported signType")
	}
	for _, item := range []struct{ name, value string }{
		{"package", r.Package}, {"paySign", r.PaySign}, {"nonceStr", r.NonceStr}, {"timeStamp", r.TimeStamp},
	} {
		if strings.TrimSpace(item.value) == "" || len(item.value) > 8192 {
			return fmt.Errorf("%s must be a non-empty string (max 8192 bytes)", item.name)
		}
	}
	if _, err := strconv.ParseUint(r.TimeStamp, 10, 64); err != nil {
		return fmt.Errorf("timeStamp must be a decimal timestamp string")
	}
	if len(r.RuntimeTicket) > 8192 {
		return fmt.Errorf("runtimeTicket is too long")
	}
	return nil
}

func runtimeFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func runtimeAppIDValid(appID string) bool {
	return len(appID) == 18 && strings.HasPrefix(appID, "wx") && strings.IndexFunc(appID[2:], func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') }) < 0
}

func (a *App) handleGetRuntimeSession(w http.ResponseWriter, r *http.Request) {
	a.handleRuntimePayCall(w, r, false, a.invokeRuntimeSession, a.createRuntimePayQRCode)
}
func (a *App) handleGetPayQRCode(w http.ResponseWriter, r *http.Request) {
	a.handleRuntimePayCall(w, r, true, a.invokeRuntimeSession, a.createRuntimePayQRCode)
}

type runtimeQRCall func(context.Context, runtimePayRequest, string, string) (map[string]any, error)

func (a *App) handleRuntimePayCall(w http.ResponseWriter, r *http.Request, payment bool, sessionCall wxappCall, qrCall runtimeQRCall) {
	if !isRuntimePayRoute(r.URL.Path) {
		writeError(w, 404, "not found")
		return
	}
	if !a.authorizeProtocol(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, 405, "method not allowed")
		return
	}
	var body runtimePayRequest
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := body.validate(payment); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ctx, err := withRequestProxy(r.Context(), body.ProxyURL)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	r = r.WithContext(ctx)
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
	// Only session lookup runs through the recoverable protocol pipeline. The
	// potentially accepted payment UUID request is issued outside it, once.
	requestProxyValue := ""
	trackedSessionCall := func(ctx context.Context, account *store.WechatAccount, appID string, payload map[string]any, proxy string, fallback bool) (map[string]any, error) {
		requestProxyValue = proxy
		return sessionCall(ctx, account, appID, payload, proxy, fallback)
	}
	result, err := a.invokeWXApp(r.Context(), acc, body.AppID, nil, trackedSessionCall)
	if err != nil {
		var expired accountExpiredError
		if errors.As(err, &expired) {
			writeAccountExpired(w, expired)
		} else {
			writeProtocolCallError(w, err)
		}
		return
	}
	sessionID, _ := result["session_id"].(string)
	if sessionID == "" {
		writeError(w, 502, "experimental getRuntimeSession returned no session_id")
		return
	}
	if payment {
		result, err = qrCall(r.Context(), body, sessionID, requestProxyValue)
		if err != nil {
			writeError(w, 502, err.Error())
			return
		}
	}
	writeJSON(w, 200, result)
}
func (a *App) invokeRuntimeSession(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any, proxyValue string, fallbackDirect bool) (map[string]any, error) {
	return a.pool.GetRuntimeSession(ctx, acc.LoginBuffer, appID, acc.ID, proxyValue, fallbackDirect, acc)
}
func marshalRuntimeString(value any) (string, error) {
	raw, err := json.Marshal(value)
	return string(raw), err
}

// Preserve the source's nested JSON wire shape, using encoding/json rather
// than string interpolation. Only merchant-supplied payment fields are used.
func buildRuntimePayBody(body runtimePayRequest, sessionID string) ([]byte, error) {
	args, err := marshalRuntimeString(map[string]any{
		"adUxInfo": "", "grantMessageQuota": true,
		"signType": body.SignType, "provider": "wxpay", "package": body.Package,
		"timeStamp": body.TimeStamp, "nonceStr": body.NonceStr, "paySign": body.PaySign,
		"cookie": "busid=wxapp; appid=" + body.AppID + ";; busid=wxapp; sessionid=;; busid=wxapp; scene=1001;; busid=wxapp; scene_note=",
	})
	if err != nil {
		return nil, err
	}
	invoke, err := marshalRuntimeString(map[string]any{
		"miniprogramAppID": body.AppID, "args": args, "isBridgedJsApi": true,
		"name": "requestPayment", "jsapiType": "appservice", "transitiveData": "",
	})
	if err != nil {
		return nil, err
	}
	requestData := map[string]any{
		"invokeData": invoke, "pathType": 1, "runtimeSessionId": sessionID,
		"rumtimeAppid": body.AppID, // Spelling is inherited from the supplied source, not corrected speculatively.
	}
	if body.RuntimeTicket != "" {
		requestData["runtimeTicket"] = body.RuntimeTicket
	}
	// The source hard-codes runtimeTicket="Test"; do not manufacture that ticket.
	data, err := marshalRuntimeString(requestData)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"appid": body.AppID, "req_data": data})
}

func (a *App) createRuntimePayQRCode(ctx context.Context, body runtimePayRequest, sessionID, proxyValue string) (map[string]any, error) {
	timeout := a.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second // Same default as App.Config, in seconds.
	}
	transport, err := protocol.NewHTTPTransport(proxyValue, false)
	if err != nil {
		return nil, fmt.Errorf("getPayQRCode: proxy setup failed")
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	if proxyValue == "" {
		// Respect the existing WXAPI proxy-off setting, including environments
		// that happen to define HTTP_PROXY. Do not change global transports.
		direct := http.DefaultTransport.(*http.Transport).Clone()
		direct.Proxy = nil
		client.Transport = direct
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return requestRuntimePayQRCode(ctx, client, body, sessionID)
}

func requestRuntimePayQRCode(ctx context.Context, client *http.Client, body runtimePayRequest, sessionID string) (map[string]any, error) {
	payload, err := buildRuntimePayBody(body, sessionID)
	if err != nil {
		return nil, fmt.Errorf("getPayQRCode: request encoding failed")
	}
	endpoint := "https://open.weixin.qq.com/wxaruntime/getuuid?" + url.Values{"session_id": {sessionID}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("getPayQRCode: request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Exactly one UUID POST. Do not blindly repeat a potentially accepted request.
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("getPayQRCode: %s", ctx.Err())
		}
		// url.Error includes session_id; never return/log its full text.
		return nil, fmt.Errorf("getPayQRCode: upstream connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getPayQRCode: upstream HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, fmt.Errorf("getPayQRCode: unreadable or oversized response")
	}
	var reply struct {
		UUID    string `json:"uuid"`
		ErrCode int64  `json:"errcode"`
		Ret     int64  `json:"ret"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return nil, fmt.Errorf("getPayQRCode: upstream response is not valid JSON")
	}
	if reply.ErrCode != 0 || reply.Ret != 0 {
		return nil, fmt.Errorf("getPayQRCode: upstream errcode=%d ret=%d", reply.ErrCode, reply.Ret)
	}
	if strings.TrimSpace(reply.UUID) == "" || len(reply.UUID) > 4096 {
		return nil, fmt.Errorf("getPayQRCode: upstream returned no valid uuid")
	}
	return map[string]any{
		"qrcode_url": "https://api.weixin.qq.com/wxaruntime/readqrcode?" + url.Values{"uuid": {reply.UUID}}.Encode(),
		"uuid":       reply.UUID, "experimental": true,
	}, nil
}
