package protocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/store"
)

// These commands and field numbers follow 应用宝测试/internal/protocol/ilink.go
// and its wxapp_pb schema. They use the maintained session and transport.
const (
	checkShortLinkCmdID    = 4428
	wxaAttrSyncCmdID       = 1151
	wxaCDNDownloadURLCmdID = 1139
)

func metadataInt(payload map[string]any, key string) (int32, error) {
	v, ok := payload[key]
	if !ok {
		return 0, nil
	}
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case int:
		n = float64(x)
	case int32:
		n = float64(x)
	case int64:
		n = float64(x)
	case json.Number:
		var err error
		n, err = x.Float64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an int32", key)
		}
	default:
		return 0, fmt.Errorf("%s must be an int32", key)
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < math.MinInt32 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be an int32", key)
	}
	return int32(n), nil
}

func metadataString(payload map[string]any, key string) (string, error) {
	v, ok := payload[key]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func ValidateCheckShortURL(_ string, payload map[string]any) error {
	s, err := metadataString(payload, "shortLink")
	if err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("shortLink is required")
	}
	return nil
}
func ValidateWxaAttrSync(appID string, payload map[string]any) error {
	if !hostSignProvider.MatchString(appID) {
		return fmt.Errorf("invalid app_id")
	}
	for _, key := range []string{"userName", "field5", "syncKey"} {
		if _, err := metadataString(payload, key); err != nil {
			return err
		}
	}
	if s, _ := metadataString(payload, "syncKey"); s != "" {
		if _, err := base64.StdEncoding.DecodeString(s); err != nil {
			return fmt.Errorf("syncKey must be base64")
		}
	}
	_, err := metadataInt(payload, "field6")
	return err
}
func ValidateWxaCDNDownloadURL(appID string, payload map[string]any) error {
	if !hostSignProvider.MatchString(appID) {
		return fmt.Errorf("invalid app_id")
	}
	for _, key := range []string{"versionMd5", "moduleName"} {
		if _, err := metadataString(payload, key); err != nil {
			return err
		}
	}
	n, err := metadataInt(payload, "version")
	if err != nil {
		return err
	}
	if n < 0 {
		return fmt.Errorf("version must be non-negative")
	}
	return nil
}

func metadataBaseReq(session AppSession, device []byte) []byte {
	out := pbLen(1, sessionKeyLiteral)
	out = append(out, pbVar(2, uint64(uint32(session.UIN)))...)
	out = append(out, pbLen(3, device)...)
	out = append(out, pbVar(4, clientVersion)...)
	out = append(out, pbLen(5, unifiedPCWindows)...)
	return append(out, pbVar(6, 5)...)
}
func buildCheckShortLinkRequest(session AppSession, shortLink string, device []byte) ([]byte, error) {
	if err := ValidateCheckShortURL("", map[string]any{"shortLink": shortLink}); err != nil {
		return nil, err
	}
	body := pbLen(1, metadataBaseReq(session, device))
	body = append(body, pbLen(2, []byte(shortLink))...)
	body = append(body, pbVar(3, 1)...)
	return buildJSAPIPlaintext(session.UIN, "", []byte("/cgi-bin/mmbiz-bin/wxaapp/wxaapp_checkshortlink"), checkShortLinkCmdID, body, session.HostAppID, device), nil
}
func buildWxaAttrSyncRequest(session AppSession, appID, userName string, syncKey []byte, field5 string, field6 int32, device []byte) ([]byte, error) {
	body := pbLen(1, metadataBaseReq(session, device))
	body = append(body, pbLen(2, []byte(userName))...)
	if syncKey != nil {
		body = append(body, pbLen(3, syncKey)...)
	}
	body = append(body, pbLen(4, []byte(appID))...)
	body = append(body, pbLen(5, []byte(field5))...)
	body = append(body, pbVar(6, uint64(int64(field6)))...)
	return buildJSAPIPlaintext(session.UIN, appID, []byte("/cgi-bin/mmbiz-bin/wxaattr/wxaattrsync"), wxaAttrSyncCmdID, body, session.HostAppID, device), nil
}
func buildGetWxaCDNDownloadUrlRequest(session AppSession, appID string, version int32, versionMd5, moduleName string, device []byte) ([]byte, error) {
	body := pbLen(1, metadataBaseReq(session, device))
	body = append(body, pbLen(3, []byte(appID))...)
	body = append(body, pbVar(4, uint64(version))...)
	body = append(body, pbLen(5, []byte(versionMd5))...)
	var mode uint64
	if moduleName != "" {
		mode = 4
	}
	body = append(body, pbVar(6, mode)...)
	body = append(body, pbLen(8, []byte(moduleName))...)
	return buildJSAPIPlaintext(session.UIN, appID, []byte("/cgi-bin/mmbiz-bin/wxaapp/getwxacdndownloadurl"), wxaCDNDownloadURLCmdID, body, session.HostAppID, device), nil
}

type metadataFields map[protowire.Number][]any

type metadataUpstreamError int32

func (e metadataUpstreamError) Error() string {
	return fmt.Sprintf("metadata upstream ret=%d", int32(e))
}

func parseMetadataFields(raw []byte) (metadataFields, error) {
	out := metadataFields{}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty metadata response")
	}
	for len(raw) > 0 {
		n, kind, size := protowire.ConsumeTag(raw)
		if size < 0 || n < 1 {
			return nil, fmt.Errorf("invalid metadata protobuf tag")
		}
		raw = raw[size:]
		var value any
		switch kind {
		case protowire.BytesType:
			var b []byte
			b, size = protowire.ConsumeBytes(raw)
			value = b
		case protowire.VarintType:
			var v uint64
			v, size = protowire.ConsumeVarint(raw)
			value = v
		default:
			size = protowire.ConsumeFieldValue(n, kind, raw)
		}
		if size < 0 {
			return nil, fmt.Errorf("truncated metadata protobuf")
		}
		raw = raw[size:]
		if value != nil {
			out[n] = append(out[n], value)
		}
	}
	return out, nil
}
func (f metadataFields) bytes(n protowire.Number) []byte {
	v := f[n]
	if len(v) == 0 {
		return nil
	}
	b, _ := v[len(v)-1].([]byte)
	return b
}
func (f metadataFields) number(n protowire.Number) uint64 {
	v := f[n]
	if len(v) == 0 {
		return 0
	}
	u, _ := v[len(v)-1].(uint64)
	return u
}
func metadataResponse(raw []byte) (metadataFields, map[string]any, error) {
	fields, err := parseMetadataFields(raw)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{}
	if base := fields.bytes(1); base != nil {
		f, err := parseMetadataFields(base)
		if len(base) == 0 {
			f = metadataFields{}
			err = nil
		}
		if err != nil {
			return nil, nil, err
		}
		ret := int32(f.number(1))
		out["ret"] = ret
		if ret != 0 {
			return nil, nil, metadataUpstreamError(ret)
		}
		if msg := f.bytes(2); len(msg) > 0 {
			m, e := parseMetadataFields(msg)
			if e != nil {
				return nil, nil, e
			}
			out["errMsg"] = string(m.bytes(1))
		}
	}
	return fields, out, nil
}
func parseCheckShortLinkResponse(resp []byte) (map[string]any, error) {
	fields, out, err := metadataResponse(resp)
	if err != nil {
		return nil, err
	}
	if data := fields.bytes(2); data != nil {
		inner, meta, e := metadataResponse(data)
		if e != nil {
			return nil, e
		}
		if ret, ok := meta["ret"]; ok {
			out["innerRet"] = ret
		}
		out["appid"] = string(inner.bytes(2))
		out["path"] = string(inner.bytes(3))
		out["appName"] = string(inner.bytes(7))
		out["versionType"] = int32(inner.number(5))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unrecognized short link response")
	}
	return out, nil
}
func metadataKeyValues(fields metadataFields) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	for _, v := range fields[3] {
		raw, ok := v.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid metadata key/value")
		}
		kv, err := parseMetadataFields(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"key": string(kv.bytes(1)), "value": string(kv.bytes(2))})
	}
	return out, nil
}
func parseWxaAttrSyncResponse(code, resp []byte) (map[string]any, error) {
	var last error
	for _, raw := range [][]byte{code, resp} {
		fields, out, err := metadataResponse(raw)
		if err != nil {
			var upstream metadataUpstreamError
			if errors.As(err, &upstream) {
				return nil, err
			}
			last = err
			continue
		}
		// An envelope with unrelated fields is not a WxaAttrSyncResponse.
		if fields.bytes(1) == nil && fields.bytes(2) == nil && len(fields[3]) == 0 {
			last = fmt.Errorf("unrecognized attr sync response")
			continue
		}
		kv, e := metadataKeyValues(fields)
		if e != nil {
			return nil, e
		}
		if syncKey := fields.bytes(2); syncKey != nil {
			out["syncKey"] = base64.StdEncoding.EncodeToString(syncKey)
			if inner, e := parseMetadataFields(syncKey); e == nil {
				kv, e = metadataKeyValues(inner)
				if e != nil {
					return nil, e
				}
			}
		}
		out["keyValues"] = kv
		return out, nil
	}
	return nil, last
}
func metadataDownloadURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
func parseGetWxaCDNDownloadUrlResponse(code, resp []byte) (map[string]any, error) {
	fields, out, err := metadataResponse(resp)
	var upstream metadataUpstreamError
	if errors.As(err, &upstream) {
		return nil, err
	}
	if err == nil && fields.bytes(1) != nil {
		if s := string(fields.bytes(3)); s != "" {
			if !metadataDownloadURL(s) {
				return nil, fmt.Errorf("invalid CDN URL")
			}
			out["downloadUrl"] = s
			return out, nil
		}
		return out, nil
	}
	if err == nil {
		if s := string(fields.bytes(3)); metadataDownloadURL(s) {
			out["downloadUrl"] = s
			return out, nil
		}
	}
	if s := string(code); metadataDownloadURL(s) {
		return map[string]any{"downloadUrl": s}, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unrecognized CDN download response")
}

func (p *Pool) runMetadata(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string, fallbackDirect bool, build func(WmpfSession) ([]byte, error), parse func([]byte, []byte) (map[string]any, error), expected ...*store.WechatAccount) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := build(st)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		packet, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, MarkNoRetry(err)
		}
		code, resp, err := p.sendEnvelope(ctx, st, packet)
		if err != nil {
			return nil, err
		}
		return parseMetadataResult(parse, code, resp)
	}, expected...)
}

// A decoded business rejection or malformed response is not evidence of an
// expired session. It must not cause a new login and another business request.
func parseMetadataResult(parse func([]byte, []byte) (map[string]any, error), code, resp []byte) (map[string]any, error) {
	result, err := parse(code, resp)
	if err != nil {
		return nil, MarkNoRetry(err)
	}
	return result, nil
}
func (p *Pool) CheckShortUrl(ctx context.Context, loginBuffer string, payload map[string]any, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	if err := ValidateCheckShortURL("", payload); err != nil {
		return nil, MarkNoRetry(err)
	}
	shortLink, _ := metadataString(payload, "shortLink")
	return p.runMetadata(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(st WmpfSession) ([]byte, error) {
		return buildCheckShortLinkRequest(st.Session, shortLink, st.Device.SessDevice)
	}, func(_, resp []byte) (map[string]any, error) { return parseCheckShortLinkResponse(resp) }, expected...)
}
func (p *Pool) WxaAttrSync(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	if err := ValidateWxaAttrSync(appID, payload); err != nil {
		return nil, MarkNoRetry(err)
	}
	userName, _ := metadataString(payload, "userName")
	key, _ := metadataString(payload, "syncKey")
	syncKey, _ := base64.StdEncoding.DecodeString(key)
	field5, _ := metadataString(payload, "field5")
	field6, _ := metadataInt(payload, "field6")
	return p.runMetadata(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(st WmpfSession) ([]byte, error) {
		return buildWxaAttrSyncRequest(st.Session, appID, userName, syncKey, field5, field6, st.Device.SessDevice)
	}, parseWxaAttrSyncResponse, expected...)
}
func (p *Pool) GetWxaCDNDownloadUrl(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	if err := ValidateWxaCDNDownloadURL(appID, payload); err != nil {
		return nil, MarkNoRetry(err)
	}
	version, _ := metadataInt(payload, "version")
	md5, _ := metadataString(payload, "versionMd5")
	module, _ := metadataString(payload, "moduleName")
	out, err := p.runMetadata(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(st WmpfSession) ([]byte, error) {
		return buildGetWxaCDNDownloadUrlRequest(st.Session, appID, version, md5, module, st.Device.SessDevice)
	}, parseGetWxaCDNDownloadUrlResponse, expected...)
	if err == nil {
		out["appId"] = appID
		out["moduleName"] = module
	}
	return out, err
}
