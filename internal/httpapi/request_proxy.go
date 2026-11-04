package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"yyb_go/internal/protocol"
)

type requestProxyKey struct{}
type requestProxy struct{ value string }
type resolvedProxyPlanKey struct{}
type resolvedProxyPlan struct {
	accountID int64
	proxy     string
	fallback  bool
}

// nil includes both omitted and JSON null. Empty string explicitly means
// business direct egress, without changing QR/login or saved account settings.
func withRequestProxy(ctx context.Context, raw *string) (context.Context, error) {
	if raw == nil {
		return ctx, nil
	}
	value, err := normalizeRequestProxy(*raw)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, requestProxyKey{}, requestProxy{value}), nil
}
func normalizeRequestProxy(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if !strings.Contains(value, "://") {
		value = "socks5://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.Hostname() == "" {
		return "", fmt.Errorf("proxyUrl must be a valid proxy URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		u.Scheme = "socks5"
	case "http", "http-connect":
		u.Scheme = "http-connect"
	default:
		return "", fmt.Errorf("proxyUrl supports socks5/socks5h/http/http-connect")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("proxyUrl requires a valid port")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("proxyUrl must not include a path, query or fragment")
	}
	u.Path, u.RawPath = "", ""
	return u.String(), nil
}

// wxappProxyPlan retains the account's existing authentication route and ACL.
// A scoped key can select direct business egress or its own bound profile's
// current node; it cannot use proxyUrl to introduce an unbound proxy.
func (a *App) wxappProxyPlan(ctx context.Context, accountID int64) (context.Context, string, bool, error) {
	if plan, ok := ctx.Value(resolvedProxyPlanKey{}).(resolvedProxyPlan); ok && plan.accountID == accountID {
		return ctx, plan.proxy, plan.fallback, nil
	}
	override, ok := ctx.Value(requestProxyKey{}).(requestProxy)
	if !ok {
		proxy, fallback, err := a.resolveWXAppProxy(ctx, accountID)
		if err != nil {
			return nil, "", false, err
		}
		resolved := context.WithValue(ctx, resolvedProxyPlanKey{}, resolvedProxyPlan{accountID: accountID, proxy: proxy, fallback: fallback})
		return resolved, proxy, fallback, nil
	}
	authProxy, authFallback, err := a.resolveAccountProxy(ctx, accountID)
	if err != nil {
		return nil, "", false, err
	}
	principal, scoped := ctx.Value(scopedProtocolContext{}).(scopedProtocolPrincipal)
	if scoped && principal.Key != nil && override.value != "" {
		normalized, err := normalizeRequestProxy(authProxy)
		if err != nil || normalized != override.value {
			return nil, "", false, fmt.Errorf("request proxy is not bound to this API key")
		}
	}
	resolved := protocol.WithRequestProxies(ctx, authProxy, authFallback, override.value)
	resolved = context.WithValue(resolved, resolvedProxyPlanKey{}, resolvedProxyPlan{accountID: accountID, proxy: override.value, fallback: false})
	return resolved, override.value, false, nil
}

func requestProxySchema() map[string]any {
	return map[string]any{
		"type": "string", "nullable": true,
		"description": "仅本次业务出口：省略/null沿用账号设置；空字符串直连；URL使用指定代理。登录/刷新/扫码代理和账号绑定保持不变，业务失败不回落直连。scoped key仅可使用绑定profile当前节点或业务直连。",
	}
}
