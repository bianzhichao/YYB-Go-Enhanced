package protocol

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"yyb_go/internal/store"
)

type requestProxiesKey struct{}
type requestProxies struct {
	auth, business string
	authFallback   bool
}

// WithRequestProxies separates the saved account's authentication route from
// one request's business route. The value is never written into account settings.
func WithRequestProxies(ctx context.Context, auth string, authFallback bool, business string) context.Context {
	return context.WithValue(ctx, requestProxiesKey{}, requestProxies{auth: auth, business: business, authFallback: authFallback})
}

func withRequestAuthRoute(ctx context.Context, auth string, fallback bool) context.Context {
	if p, ok := ctx.Value(requestProxiesKey{}).(requestProxies); ok {
		p.auth, p.authFallback = auth, fallback
		return context.WithValue(ctx, requestProxiesKey{}, p)
	}
	return ctx
}
func requestAuthenticationProxy(ctx context.Context, proxy string, fallback bool) (string, bool) {
	if p, ok := ctx.Value(requestProxiesKey{}).(requestProxies); ok {
		return p.auth, p.authFallback
	}
	return proxy, fallback
}
func requestSessionKey(ctx context.Context, auth string) string {
	if p, ok := ctx.Value(requestProxiesKey{}).(requestProxies); ok {
		digest := sha256.Sum256([]byte(auth + "\x00" + p.business))
		return fmt.Sprintf("request-proxy:v1:%x", digest)
	}
	return auth
}
func requestBusinessProxy(ctx context.Context, proxy string, fallback bool) (string, bool) {
	if p, ok := ctx.Value(requestProxiesKey{}).(requestProxies); ok {
		return p.business, false
	}
	return proxy, fallback
}

// A failed override is terminal for this business call. Authentication keeps
// its existing login fallback, but no business request is replayed directly.
func (p *Pool) runRequestProxy(ctx context.Context, loginBuffer string, accountID int64, op func(context.Context, WmpfSession) (map[string]any, error), expected ...*store.WechatAccount) (map[string]any, error) {
	plan := ctx.Value(requestProxiesKey{}).(requestProxies)
	st, err := p.state(ctx, loginBuffer, accountID, plan.auth, plan.authFallback, expected...)
	if err != nil && plan.auth != "" && plan.authFallback && !IsNoRetry(err) {
		var recovery *CodeSessionRecoveryError
		if !errors.As(err, &recovery) && !errors.Is(err, store.ErrAccountAuthorizationChanged) {
			directCtx := withRequestAuthRoute(ctx, "", false)
			st, err = p.state(directCtx, loginBuffer, accountID, "", false, expected...)
			ctx = directCtx
		}
	}
	if err != nil {
		return nil, err
	}
	st.FallbackDirect = false
	result, err := op(ctx, st)
	// Preserve typed application rejections for the existing code recovery path;
	// generic transport failures must not trigger HTTP credential refresh replay.
	if err != nil && !IsApplicationRequestRejection(err) {
		err = MarkNoRetry(err)
	}
	return result, err
}
