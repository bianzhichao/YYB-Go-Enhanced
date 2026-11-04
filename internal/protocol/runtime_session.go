package protocol

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/store"
)

// Experimental transport adaptation from 08_857/models/Wxapp/JSGetSessionid.go.
// The source uses CGI 3540 with BaseRequest(field 1) + AppID(field 2).
// Keep YYB's own PC session/device/transfer envelope; do not import iPad credentials.
const runtimeSessionCGI = 3540

func buildRuntimeSessionRequest(st AppSession, appID string, device []byte) ([]byte, error) {
	if !hostSignProvider.MatchString(appID) {
		return nil, fmt.Errorf("getRuntimeSession: invalid appid")
	}
	if len(device) == 0 {
		device = randomSessDevice()
	}
	inner := append(pbLen(1, sessionInfo(uint32(st.UIN), unifiedPCWindows, device)), pbLen(2, []byte(appID))...)
	return buildJSAPIPlaintext(st.UIN, appID,
		[]byte("/cgi-bin/mmbiz-bin/wxabusiness/getruntimesession"),
		runtimeSessionCGI, inner, st.HostAppID, device), nil
}

// GetRuntimeSession is experimental until a real YYB response confirms CGI 3540.
func (p *Pool) GetRuntimeSession(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	if !hostSignProvider.MatchString(appID) {
		return nil, fmt.Errorf("getRuntimeSession: invalid appid")
	}
	return p.run(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := buildRuntimeSessionRequest(st.Session, appID, st.Device.SessDevice)
		if err != nil {
			return nil, err
		}
		packet, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		_, response, err := p.sendEnvelope(ctx, st, packet)
		if err != nil {
			return nil, err
		}
		result, err := parseRuntimeSessionResponse(response)
		return result, MarkNoRetry(err)
	}, expected...)
}

type runtimeWireField struct {
	kind   protowire.Type
	bytes  []byte
	number uint64
}

// Parse bounded, complete protobuf messages. Unknown fields are never logged.
func runtimeWireFields(raw []byte) (map[protowire.Number]runtimeWireField, error) {
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return nil, fmt.Errorf("empty or oversized response")
	}
	fields := map[protowire.Number]runtimeWireField{}
	for len(raw) > 0 {
		if len(fields) >= 128 {
			return nil, fmt.Errorf("too many fields")
		}
		num, kind, size := protowire.ConsumeTag(raw)
		if size < 0 {
			return nil, fmt.Errorf("invalid field tag")
		}
		if _, duplicate := fields[num]; duplicate {
			return nil, fmt.Errorf("duplicate field")
		}
		raw = raw[size:]
		field := runtimeWireField{kind: kind}
		switch kind {
		case protowire.BytesType:
			field.bytes, size = protowire.ConsumeBytes(raw)
		case protowire.VarintType:
			field.number, size = protowire.ConsumeVarint(raw)
		default:
			size = protowire.ConsumeFieldValue(num, kind, raw)
		}
		if size < 0 {
			return nil, fmt.Errorf("truncated field")
		}
		fields[num] = field
		raw = raw[size:]
	}
	return fields, nil
}

func validRuntimeSessionToken(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4096 {
		return false
	}
	for _, b := range raw {
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || strings.ContainsRune("._~+/=-", rune(b))) {
			return false
		}
	}
	return true
}

func parseRuntimeSessionResponse(raw []byte) (map[string]any, error) {
	originalSize := len(raw)
	layout := "field2"
	for depth := 0; depth < 3; depth++ {
		fields, err := runtimeWireFields(raw)
		if err != nil {
			return nil, fmt.Errorf("getRuntimeSession: experimental parser: %s; response_bytes=%d", err, originalSize)
		}
		if base, ok := fields[1]; ok && base.kind == protowire.BytesType {
			if baseFields, err := runtimeWireFields(base.bytes); err == nil {
				if ret, ok := baseFields[1]; ok && ret.kind == protowire.VarintType && int32(ret.number) != 0 {
					return nil, fmt.Errorf("getRuntimeSession: upstream ret=%d; response_bytes=%d", int32(ret.number), originalSize)
				}
			}
		} else if base, ok := fields[1]; ok && base.kind == protowire.VarintType {
			// JSAPIBaseResponse is {errcode:1, errmsg:2}, not a runtime
			// session. Never mistake a short error string for a session ID.
			return nil, fmt.Errorf("getRuntimeSession: JSAPI errcode=%d, no recognized runtime session; response_bytes=%d", int32(base.number), originalSize)
		} else {
			return nil, fmt.Errorf("getRuntimeSession: missing base response in candidate layout; response_bytes=%d", originalSize)
		}
		value, ok := fields[2]
		if !ok || value.kind != protowire.BytesType {
			break
		}
		if validRuntimeSessionToken(value.bytes) {
			result := map[string]any{
				"session_id":      string(value.bytes),
				"experimental":    true,
				"response_layout": layout,
			}
			if opcode, ok := fields[3]; ok && opcode.kind == protowire.VarintType {
				result["opcode"] = opcode.number
			}
			return result, nil
		}
		// Existing YYB responses commonly wrap the upstream message in field 2.
		// This is a candidate layout, not evidence of live server compatibility.
		raw = value.bytes
		layout = "field2." + layout
	}
	return nil, fmt.Errorf("getRuntimeSession: unrecognized experimental response; response_bytes=%d", originalSize)
}
