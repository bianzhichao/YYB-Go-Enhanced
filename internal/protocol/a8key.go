package protocol

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/store"
)

func a8Bytes(dst []byte, n protowire.Number, b []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(dst, n, protowire.BytesType), b)
}
func a8Var(dst []byte, n protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(dst, n, protowire.VarintType), v)
}

// NormalizeA8KeyPayload validates the dedicated 2909 CGI, not operateWxData.
func NormalizeA8KeyPayload(payload map[string]any) (string, string, int32, error) {
	target, _ := payload["target_url"].(string)
	if target == "" {
		target, _ = payload["targetUrl"].(string)
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", "", 0, fmt.Errorf("getA8Key: target_url must be an HTTP(S) URL")
	}
	biz, _ := payload["biz_username"].(string)
	if biz == "" {
		biz, _ = payload["bizUsername"].(string)
	}
	scene := int32(5)
	if v, ok := payload["scene"]; ok {
		var n int64
		switch value := v.(type) {
		case int:
			n = int64(value)
		case int32:
			n = int64(value)
		case int64:
			n = value
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < 0 || value > math.MaxInt32 {
				return "", "", 0, fmt.Errorf("getA8Key: invalid scene")
			}
			n = int64(value)
		default:
			return "", "", 0, fmt.Errorf("getA8Key: invalid scene")
		}
		if n < 0 || n > math.MaxInt32 {
			return "", "", 0, fmt.Errorf("getA8Key: invalid scene")
		}
		scene = int32(n)
	}
	return target, biz, scene, nil
}
func buildMPa8keyRequest(session AppSession, appID, target, biz string, scene int32) []byte {
	base := a8Bytes(nil, 1, sessionKeyLiteral)
	base = a8Var(base, 2, uint64(uint32(session.UIN)))
	base = a8Bytes(base, 3, session.DeviceID)
	base = a8Var(base, 4, uint64(clientVersion))
	base = a8Bytes(base, 5, unifiedPCWindows)
	base = a8Var(base, 6, 5)
	out := a8Bytes(nil, 1, base)
	out = a8Var(out, 2, 2)
	out = a8Bytes(out, 4, a8Bytes(nil, 1, []byte(appID)))
	out = a8Bytes(out, 7, a8Bytes(nil, 1, []byte(target)))
	out = a8Bytes(out, 8, []byte(biz))
	out = a8Var(out, 9, 0)
	out = a8Var(out, 10, uint64(scene))
	out = a8Bytes(out, 12, nil)
	out = a8Var(out, 14, 2)
	out = a8Var(out, 16, 0)
	out = a8Bytes(out, 17, []byte("WIFI"))
	out = a8Var(out, 18, 0)
	out = a8Var(out, 20, uint64(uint32(time.Now().Unix())))
	out = a8Bytes(out, 21, []byte(biz))
	out = a8Var(out, 22, 0)
	cookie := a8Var(nil, 1, uint64(len(session.Ticket)))
	cookie = a8Bytes(cookie, 2, session.Ticket)
	out = a8Bytes(out, 23, cookie)
	return a8Var(out, 25, 0)
}
func buildA8keyPacket(session AppSession, plain []byte) ([]byte, error) {
	encrypted, err := aesGCMEncryptLayout(session.SendKey, nil, lz4AllLiteral(plain))
	if err != nil {
		return nil, err
	}
	inner := buildShortlink(2909, 0, append(sessionWpkgHead(session.UIN, session.F9, session.DeviceID), encrypted...), defaultVer)
	path := []byte("/ilink/ilinkapp/mm/ilinkmpgeta8key")
	host := []byte("short.weixin.qq.com")
	env := make([]byte, 2)
	binary.BigEndian.PutUint16(env, uint16(len(path)))
	env = append(env, path...)
	env = binary.BigEndian.AppendUint16(env, uint16(len(host)))
	env = append(env, host...)
	env = binary.BigEndian.AppendUint32(env, uint32(len(inner)))
	env = append(env, inner...)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(env)))
	return append(out, env...), nil
}
func a8Fields(raw []byte) (map[protowire.Number]any, error) {
	fields := map[protowire.Number]any{}
	for len(raw) > 0 {
		n, k, t := protowire.ConsumeTag(raw)
		if t < 0 {
			return nil, fmt.Errorf("getA8Key: malformed protobuf")
		}
		raw = raw[t:]
		switch k {
		case protowire.BytesType:
			v, s := protowire.ConsumeBytes(raw)
			if s < 0 {
				return nil, fmt.Errorf("getA8Key: truncated protobuf")
			}
			fields[n] = v
			raw = raw[s:]
		case protowire.VarintType:
			v, s := protowire.ConsumeVarint(raw)
			if s < 0 {
				return nil, fmt.Errorf("getA8Key: invalid protobuf value")
			}
			fields[n] = v
			raw = raw[s:]
		default:
			s := protowire.ConsumeFieldValue(n, k, raw)
			if s < 0 {
				return nil, fmt.Errorf("getA8Key: invalid protobuf field")
			}
			raw = raw[s:]
		}
	}
	return fields, nil
}
func parseA8KeyResponse(extracted, response []byte) (map[string]any, error) {
	for _, candidate := range [][]byte{extracted, response} {
		if strings.HasPrefix(strings.TrimSpace(string(candidate)), "{") {
			var object map[string]any
			if json.Unmarshal(candidate, &object) != nil || object == nil {
				return nil, fmt.Errorf("getA8Key: invalid JSON")
			}
			ret, exists := object["ret"]
			if !exists {
				ret, exists = object["errcode"]
			}
			code, ok := ret.(float64)
			if !exists || !ok || code != 0 {
				return nil, fmt.Errorf("getA8Key: upstream rejected or omitted status")
			}
			full, _ := object["full_url"].(string)
			key, _ := object["a8key"].(string)
			if full == "" && key == "" {
				return nil, fmt.Errorf("getA8Key: missing URL/key")
			}
			return object, nil
		}
	}
	fields, err := a8Fields(response)
	if err != nil {
		return nil, err
	}
	base, _ := fields[1].([]byte)
	if len(base) == 0 {
		return nil, fmt.Errorf("getA8Key: missing status")
	}
	status, err := a8Fields(base)
	if err != nil {
		return nil, err
	}
	ret, ok := status[1].(uint64)
	if !ok || int32(ret) != 0 {
		return nil, fmt.Errorf("getA8Key: upstream status %d", int32(ret))
	}
	out := map[string]any{"ret": int32(0)}
	for field, name := range map[protowire.Number]string{2: "full_url", 3: "a8key"} {
		if b, ok := fields[field].([]byte); ok && len(b) > 0 {
			out[name] = string(b)
		}
	}
	if len(out) == 1 {
		return nil, fmt.Errorf("getA8Key: missing URL/key")
	}
	if code, ok := fields[4].(uint64); ok {
		out["action_code"] = int32(code)
	}
	if cookie, ok := fields[17].([]byte); ok {
		c, err := a8Fields(cookie)
		if err != nil {
			return nil, err
		}
		if b, ok := c[2].([]byte); ok && len(b) > 0 {
			out["cookie"] = hex.EncodeToString(b)
		}
	}
	return out, nil
}
func (p *Pool) GetA8Key(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	target, biz, scene, err := NormalizeA8KeyPayload(payload)
	if err != nil {
		return nil, err
	}
	if !hostSignProvider.MatchString(appID) {
		return nil, fmt.Errorf("getA8Key: invalid app_id")
	}
	return p.run(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		packet, err := buildA8keyPacket(st.Session, buildMPa8keyRequest(st.Session, appID, target, biz, scene))
		if err != nil {
			return nil, err
		}
		extracted, response, err := p.sendEnvelope(ctx, st, packet)
		if err != nil {
			return nil, err
		}
		result, err := parseA8KeyResponse(extracted, response)
		return result, MarkNoRetry(err)
	}, expected...)
}
