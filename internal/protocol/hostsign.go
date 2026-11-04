package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"yyb_go/internal/store"
)

// VerifyPlugin uses the existing authenticated transfer/session transport.
// Wire layout checked against luotron/yyb_go internal/protocol/hostsign.go.
const hostSignCommand = 1714

var hostSignProvider = regexp.MustCompile(`^wx[A-Za-z0-9]{16}$`)

// NormalizeHostSignPayload validates before any login, refresh or proxy request.
// Accept Data/data as JSON text/object, plugins, or provider + inner_version.
func NormalizeHostSignPayload(payload map[string]any) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("getHostSign: Data or payload is required")
	}
	value := any(payload)
	if v, ok := payload["data"]; ok {
		value = v
	}
	var raw []byte
	var err error
	if text, ok := value.(string); ok {
		raw = []byte(text)
	} else {
		raw, err = json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("getHostSign: invalid Data")
		}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, fmt.Errorf("getHostSign: Data must be a JSON object or JSON object string")
	}
	if _, ok := object["plugins"]; !ok {
		if _, ok := object["provider"]; !ok {
			return nil, fmt.Errorf("getHostSign: plugins is required")
		}
		raw, _ = json.Marshal(map[string]any{"plugins": []map[string]json.RawMessage{object}})
		_ = json.Unmarshal(raw, &object)
	}
	var plugins []map[string]json.RawMessage
	if json.Unmarshal(object["plugins"], &plugins) != nil || len(plugins) == 0 {
		return nil, fmt.Errorf("getHostSign: plugins must be a non-empty object array")
	}
	for i, plugin := range plugins {
		var provider string
		var version int64
		if json.Unmarshal(plugin["provider"], &provider) != nil || !hostSignProvider.MatchString(provider) {
			return nil, fmt.Errorf("getHostSign: plugins[%d].provider must be a plugin AppID", i)
		}
		v, exists := plugin["inner_version"]
		if !exists || bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &version) != nil || version < 0 {
			return nil, fmt.Errorf("getHostSign: plugins[%d].inner_version must be a non-negative integer", i)
		}
	}
	// Canonical JSON only; preserve all caller-supplied plugin fields.
	return json.Marshal(object)
}

func hostSignBytes(dst []byte, field protowire.Number, value []byte) []byte {
	dst = protowire.AppendTag(dst, field, protowire.BytesType)
	return protowire.AppendBytes(dst, value)
}

func buildHostSignRequest(uin int64, appID string, data, hostAppID, device []byte) ([]byte, error) {
	if !hostSignProvider.MatchString(appID) {
		return nil, fmt.Errorf("getHostSign: invalid host AppID")
	}
	if len(device) == 0 {
		device = randomSessDevice()
	}
	session := sessionInfo(uint32(uin), unifiedPCWindows, device)
	inner := hostSignBytes(nil, 1, session)
	inner = hostSignBytes(inner, 2, []byte(appID))
	inner = hostSignBytes(inner, 3, data)
	return buildJSAPIPlaintext(uin, appID, []byte("/cgi-bin/mmbiz-bin/wxaapp/verifyplugin"),
		hostSignCommand, inner, hostAppID, device), nil
}

func (p *Pool) GetHostSign(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	data, err := NormalizeHostSignPayload(payload)
	if err != nil {
		return nil, err
	}
	return p.run(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := buildHostSignRequest(st.Session.UIN, appID, data, st.Session.HostAppID, nil)
		if err != nil {
			return nil, err
		}
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		extracted, response, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return parseHostSignResponse(extracted, response)
	}, expected...)
}

// Only return recognized JSON, never dump session packets or fabricate signatures.
// Recursion and node budgets bound malformed/unknown protobuf processing.
func parseHostSignResponse(candidates ...[]byte) (map[string]any, error) {
	budget := 128
	for _, candidate := range candidates {
		result, found, err := findHostSignJSON(candidate, 0, &budget)
		if found || err != nil {
			return result, err
		}
	}
	return nil, fmt.Errorf("getHostSign: response has no recognized HostSign JSON")
}

func findHostSignJSON(raw []byte, depth int, budget *int) (map[string]any, bool, error) {
	if depth > 6 || *budget <= 0 || len(raw) == 0 {
		return nil, false, nil
	}
	(*budget)--
	text := bytes.TrimSpace(raw)
	// Some compatibility services expose a control-byte prefix; it is not JSON.
	if len(text) > 1 && text[0] == 0x19 {
		text = bytes.TrimSpace(text[1:])
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(text, &object) == nil && object != nil {
		for _, key := range []string{"errcode", "ret"} {
			if value, ok := object[key]; ok {
				var code int64
				if json.Unmarshal(value, &code) != nil {
					return nil, true, fmt.Errorf("getHostSign: invalid upstream %s", key)
				}
				if code != 0 {
					// Keep error code, not arbitrary raw text that may contain credentials.
					return nil, true, fmt.Errorf("getHostSign: upstream %s=%d", key, code)
				}
			}
		}
		list, ok := object["list"]
		if !ok {
			list, ok = object["plugins"]
		}
		if !ok {
			return nil, false, nil
		}
		var entries []map[string]any
		if json.Unmarshal(list, &entries) != nil || len(entries) == 0 {
			return nil, true, fmt.Errorf("getHostSign: upstream returned no plugin signatures")
		}
		for _, entry := range entries {
			sign, _ := entry["host_sign"].(string)
			if strings.TrimSpace(sign) == "" {
				return nil, true, fmt.Errorf("getHostSign: upstream plugin has no host_sign")
			}
		}
		return map[string]any{"raw_json": string(text), "list": entries}, true, nil
	}
	// Validate each wire field before descending; skip scalar fields without guessing.
	for len(raw) > 0 && *budget > 0 {
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			break
		}
		raw = raw[n:]
		if kind == protowire.BytesType {
			value, size := protowire.ConsumeBytes(raw)
			if size < 0 {
				break
			}
			result, found, err := findHostSignJSON(value, depth+1, budget)
			if found || err != nil {
				return result, found, err
			}
			raw = raw[size:]
		} else {
			size := protowire.ConsumeFieldValue(number, kind, raw)
			if size < 0 {
				break
			}
			raw = raw[size:]
		}
	}
	return nil, false, nil
}
