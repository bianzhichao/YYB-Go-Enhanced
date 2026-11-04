package protocol

import (
	"context"
	"testing"
)

func TestRequestProxyRoutesAndCacheIsolation(t *testing.T) {
	ctx := WithRequestProxies(context.Background(), "socks5://auth:1080", true, "socks5://business:1081")
	auth, fallback := requestAuthenticationProxy(ctx, "wrong", false)
	business, directFallback := requestBusinessProxy(ctx, auth, fallback)
	if auth != "socks5://auth:1080" || !fallback || business != "socks5://business:1081" || directFallback {
		t.Fatalf("routes mixed: auth=%q/%t business=%q/%t", auth, fallback, business, directFallback)
	}
	configuredKey := requestSessionKey(context.Background(), auth)
	proxyKey := requestSessionKey(ctx, auth)
	directCtx := withRequestAuthRoute(ctx, "", false)
	directKey := requestSessionKey(directCtx, "")
	if configuredKey == proxyKey || proxyKey == directKey || requestSessionKey(ctx, auth) != proxyKey {
		t.Fatal("request session namespaces were not isolated/stable")
	}
	if got, fb := requestBusinessProxy(ctx, "", true); got != "socks5://business:1081" || fb {
		t.Fatalf("business override fell back: %q %t", got, fb)
	}
}

func TestRequestProxyEmptyStringIsExplicitDirect(t *testing.T) {
	ctx := WithRequestProxies(context.Background(), "socks5://auth:1080", true, "")
	if got, fallback := requestBusinessProxy(ctx, "socks5://old:1082", true); got != "" || fallback {
		t.Fatalf("explicit direct was not strict: %q %t", got, fallback)
	}
}
