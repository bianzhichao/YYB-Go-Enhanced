package protocol

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/oauth"
	"yyb_go/internal/store"
)

// NormalizeOAuthAuthorize validates the dedicated CGI 1254 operation. It does
// not perform browser redirects or claim that user consent has been granted.
func NormalizeOAuthAuthorize(appID string, payload map[string]any) (string, int32, error) {
	if !hostSignProvider.MatchString(appID) {
		return "", 0, fmt.Errorf("oauthAuthorize: invalid app_id")
	}
	scene, err := metadataInt(payload, "scene")
	if err != nil || scene < 0 {
		return "", 0, fmt.Errorf("oauthAuthorize: invalid scene")
	}
	text := func(key string) string { s, _ := payload[key].(string); return s }
	if raw := text("target_url"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 8192 || u.Scheme != "https" || u.Host != "open.weixin.qq.com" || u.User != nil || u.Path != "/connect/oauth2/authorize" {
			return "", 0, fmt.Errorf("invalid OAuth authorize URL")
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil || q.Get("appid") != appID || len(q["appid"]) != 1 || len(q["redirect_uri"]) != 1 || q.Get("response_type") != "code" {
			return "", 0, fmt.Errorf("OAuth URL requires matching appid, redirect_uri and response_type=code")
		}
		if _, err = oauth.Build(oauth.Request{AppID: appID, RedirectURI: q.Get("redirect_uri"), Scope: q.Get("scope"), State: q.Get("state"), ComponentAppID: q.Get("component_appid")}); err != nil {
			return "", 0, fmt.Errorf("invalid OAuth URL parameters")
		}
		return raw, scene, nil
	}
	component := text("component_appid")
	if component == "" {
		component = text("componentAppid")
	}
	built, err := oauth.Build(oauth.Request{AppID: appID, RedirectURI: text("redirect_uri"), Scope: text("scope"), State: text("state"), ComponentAppID: component})
	if err != nil {
		return "", 0, err
	}
	target := built.FullURL
	force := false
	switch v := payload["forcePopup"].(type) {
	case bool:
		force = v
	case string:
		force = v == "" || v == "1" || v == "true"
	}
	if force {
		target = strings.TrimSuffix(target, "#wechat_redirect") + "&forcePopup#wechat_redirect"
	}
	return target, scene, nil
}
func buildOauthAuthorizeRequest(st AppSession, appID, target, biz, referrer string, scene int32, device []byte) ([]byte, error) {
	if !hostSignProvider.MatchString(appID) || len(device) == 0 {
		return nil, fmt.Errorf("oauthAuthorize: invalid app/device")
	}
	body := pbLen(1, sessionInfo(uint32(st.UIN), unifiedPCWindows, device))
	body = append(body, pbLen(2, []byte(target))...)
	body = append(body, pbLen(3, []byte(biz))...)
	body = append(body, pbLen(4, []byte(referrer))...)
	body = append(body, pbVar(5, uint64(scene))...)
	return buildJSAPIPlaintext(st.UIN, appID, []byte("/ilink/ilinkapp/mm/bizoauth/oauth_authorize"), 1254, body, st.HostAppID, device), nil
}
func parseOauthAuthorizeResponse(raw []byte) (map[string]any, error) {
	fields, err := runtimeWireFields(raw)
	if err != nil {
		return nil, fmt.Errorf("oauthAuthorize: malformed response")
	}
	if b, ok := fields[1]; ok && b.kind == protowire.BytesType {
		if base, e := runtimeWireFields(b.bytes); e == nil {
			if ret, ok := base[1]; ok && ret.kind == protowire.VarintType && int32(ret.number) != 0 {
				return nil, fmt.Errorf("oauthAuthorize: upstream ret=%d", int32(ret.number))
			}
		}
	}
	field, ok := fields[2]
	if !ok || field.kind != protowire.BytesType {
		return nil, fmt.Errorf("oauthAuthorize: missing user_info")
	}
	ui, err := runtimeWireFields(field.bytes)
	if err != nil {
		return nil, fmt.Errorf("oauthAuthorize: malformed user_info")
	}
	out := map[string]any{}
	for number, key := range map[protowire.Number]string{4: "biz_nickname", 5: "state", 6: "redirect_uri", 16: "avatar_url", 17: "session_id"} {
		if f, ok := ui[number]; ok && f.kind == protowire.BytesType {
			out[key] = string(f.bytes)
		}
	}
	if f, ok := ui[10]; ok && f.kind == protowire.VarintType {
		out["is_authorized"] = f.number != 0
	}
	for _, item := range []struct {
		number  protowire.Number
		key     string
		strings map[protowire.Number]string
	}{{3, "scope_info", map[protowire.Number]string{1: "scope", 2: "description"}}, {11, "profile", map[protowire.Number]string{2: "nickname", 3: "avatar_url"}}, {19, "auth_prompt", map[protowire.Number]string{1: "title", 2: "subtitle"}}} {
		if f, ok := ui[item.number]; ok {
			if f.kind != protowire.BytesType {
				return nil, fmt.Errorf("oauthAuthorize: malformed nested response")
			}
			nested, e := runtimeWireFields(f.bytes)
			if e != nil {
				return nil, fmt.Errorf("oauthAuthorize: malformed nested response")
			}
			m := map[string]any{}
			for n, key := range item.strings {
				if v, ok := nested[n]; ok && v.kind == protowire.BytesType {
					m[key] = string(v.bytes)
				}
			}
			if item.number == 3 {
				if v, ok := nested[3]; ok && v.kind == protowire.VarintType {
					m["scope_type"] = v.number
				}
			}
			out[item.key] = m
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oauthAuthorize: unrecognized user_info")
	}
	return out, nil
}
func (p *Pool) OauthAuthorize(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, proxy string, fallback bool, expected ...*store.WechatAccount) (map[string]any, error) {
	target, scene, err := NormalizeOAuthAuthorize(appID, payload)
	if err != nil {
		return nil, MarkNoRetry(err)
	}
	out, err := p.run(ctx, loginBuffer, accountID, proxy, false, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := buildOauthAuthorizeRequest(st.Session, appID, target, "", "", scene, st.Device.SessDevice)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		packet, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		_, response, err := p.sendEnvelope(ctx, st, packet)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		result, err := parseOauthAuthorizeResponse(response)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		result["full_url"] = target
		return result, nil
	}, expected...)
	return out, MarkNoRetry(err)
}
