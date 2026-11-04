package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	"yyb_go/internal/eventlog"
	"yyb_go/internal/gatewayv3"
	"yyb_go/internal/protocol"
	"yyb_go/internal/store"
)

const gatewayRequestLimit = 8 << 20

type gatewayProxyRequest struct {
	// Reserved compatibility field; request overrides are rejected until the
	// target exposes a separate scoped business-proxy policy.
	ProxyURL *string `json:"proxyUrl"`
	Ref      string  `json:"ref"`
	OpenID   string  `json:"openid"`
	AppID    string  `json:"app_id"`
	AppIDAlt string  `json:"appid"`
	Host     string  `json:"host"`
	Path     string  `json:"path"`
	Method   string  `json:"method"`
	Headers  any     `json:"headers"`
	Payload  any     `json:"payload"`
}

type gatewayCall func(context.Context, gatewayProxyRequest, *gatewayv3.GatewayToken, string, map[string]string) (*gatewayv3.CallResult, error)

func (a *App) handleGatewayProxy(w http.ResponseWriter, r *http.Request) {
	a.handleGatewayCall(w, r, a.invokeOperateWXData, callGatewayV3)
}

func (a *App) handleGatewayCall(w http.ResponseWriter, r *http.Request, authCall wxappCall, call gatewayCall) {
	if !a.authorizeProtocol(w, r) {
		return
	}
	if r.URL.Path != "/wxapp/gatewayv3" && r.URL.Path != "/wx/gatewayv3" {
		writeError(w, 404, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, gatewayRequestLimit)
	var body gatewayProxyRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeGatewayDecodeError(w, err)
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		writeGatewayDecodeError(w, err)
		return
	}
	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		ref = strings.TrimSpace(body.OpenID)
	}
	appID := strings.TrimSpace(body.AppID)
	if appID == "" {
		appID = strings.TrimSpace(body.AppIDAlt)
	}
	headers, err := body.validate()
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if ref == "" || !validGatewayAppID(appID) {
		writeError(w, 400, "ref and valid app_id are required")
		return
	}
	// Request-only proxy override needs a separate login/business transport seam.
	// Do not silently apply it to credential acquisition in the target pipeline.
	if body.ProxyURL != nil {
		writeError(w, 400, "proxyUrl override is not supported; configure the account proxy")
		return
	}
	acc, ok := a.resolveAccountRef(w, r, ref)
	if !ok {
		return
	}
	proxy := ""
	auth := func(ctx context.Context, account *store.WechatAccount, app string, payload map[string]any, value string, fallback bool) (map[string]any, error) {
		proxy = value
		return authCall(ctx, account, app, payload, value, fallback)
	}
	r = withWXOperation(r, eventlog.OpOperateWXData)
	raw, err := a.invokeWXApp(withWXOperationContext(r.Context(), eventlog.OpOperateWXData), acc, appID, gatewayv3.BuildAuthPayload(body.Host), auth)
	if err != nil {
		var expired accountExpiredError
		switch {
		case errors.As(err, &expired):
			writeAccountExpired(w, expired)
		case writeIfCircuitOpen(w, err):
		case writeIfAppIDDenied(w, err):
		default:
			writeGatewayError(w, err)
		}
		return
	}
	token := gatewayv3.NormalizeToken(raw)
	key, err := base64.StdEncoding.DecodeString(token.Key)
	if err != nil || len(key) != 32 || strings.TrimSpace(token.Token) == "" || token.IsExpired() || !httpguts.ValidHeaderFieldValue(token.RID) {
		writeError(w, 502, "gateway token is incomplete or expired")
		return
	}
	// Business call deliberately stays outside invokeWXApp's credential retry.
	result, err := call(r.Context(), body, token, proxy, headers)
	if err != nil || result == nil {
		writeGatewayError(w, err)
		return
	}
	status := http.StatusOK
	if result.StatusCode < 200 || result.StatusCode >= 400 {
		status = http.StatusBadGateway
	}
	data := map[string]any{"openid": acc.OpenID, "result": result}
	if status != http.StatusOK {
		writeRawJSON(w, status, apiEnvelope{Code: status, Msg: "gateway upstream HTTP failure", Data: data})
		return
	}
	writeJSON(w, status, data)
}

func validGatewayAppID(s string) bool {
	return len(s) == 18 && strings.HasPrefix(s, "wx") && strings.IndexFunc(s[2:], func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') }) < 0
}

func newGatewayHTTPClient(proxy string) (*http.Client, error) {
	transport, err := protocol.NewHTTPTransport(proxy, false)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func callGatewayV3(ctx context.Context, body gatewayProxyRequest, token *gatewayv3.GatewayToken, proxy string, headers map[string]string) (*gatewayv3.CallResult, error) {
	client, err := newGatewayHTTPClient(proxy)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	gateway := gatewayv3.NewClient(body.Host, "", 15*time.Second)
	gateway.SetHTTPClient(client)
	gateway.SetToken(token)
	return gateway.CallContext(ctx, body.Path, body.Method, body.Payload, headers)
}
func (b *gatewayProxyRequest) validate() (map[string]string, error) {
	b.Host = strings.ToLower(strings.TrimSpace(b.Host))
	b.Path = strings.TrimSpace(b.Path)
	b.Method = strings.ToUpper(strings.TrimSpace(b.Method))
	if b.Method == "" {
		b.Method = "POST"
	}
	// This bridge targets cloud-run gateways, not arbitrary server-side URLs.
	if len(b.Host) > 253 || !strings.HasSuffix(b.Host, ".wxcloudrun.com") || strings.ContainsAny(b.Host, "/:@?#\\ \r\n") {
		return nil, fmt.Errorf("host must be a wxcloudrun.com service hostname, without scheme or port")
	}
	for _, label := range strings.Split(b.Host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, fmt.Errorf("invalid host")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, fmt.Errorf("invalid host")
			}
		}
	}
	u, err := url.ParseRequestURI(b.Path)
	if err != nil || !strings.HasPrefix(b.Path, "/") || strings.HasPrefix(b.Path, "//") || u.Host != "" || u.Fragment != "" || strings.ContainsAny(b.Path, "\\#\r\n") {
		return nil, fmt.Errorf("path must be an absolute service path")
	}
	switch b.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return nil, fmt.Errorf("unsupported method")
	}
	headers := map[string]string{}
	if b.Headers != nil {
		var raw []byte
		if text, ok := b.Headers.(string); ok {
			raw = []byte(text)
		} else {
			raw, err = json.Marshal(b.Headers)
			if err != nil {
				return nil, fmt.Errorf("invalid headers")
			}
		}
		if len(raw) == 0 || json.Unmarshal(raw, &headers) != nil || headers == nil {
			return nil, fmt.Errorf("headers must be a string-to-string JSON object")
		}
	}
	for k, v := range headers {
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) ||
			strings.HasPrefix(strings.ToLower(k), "x-wx-") || strings.EqualFold(k, "host") {
			return nil, fmt.Errorf("invalid or reserved header")
		}
	}
	return headers, nil
}

func writeGatewayDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, 413, "gateway request too large")
		return
	}
	writeError(w, 400, "invalid JSON")
}

func writeGatewayError(w http.ResponseWriter, err error) {
	message := "response unavailable or invalid"
	var gateway *gatewayv3.GatewayError
	switch {
	case errors.As(err, &gateway):
		message = fmt.Sprintf("gateway error %d", gateway.Code)
	case errors.Is(err, context.Canceled):
		message = "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		message = "request timeout"
	}
	// Exclude upstream signed URLs, keys, cookies and account/proxy credentials.
	writeError(w, http.StatusBadGateway, "upstream request failed: "+message)
}
