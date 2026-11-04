package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/store"
)

// PhoneItem is an item returned by customphone/getallphone. The nested data
// field is preserved and its code is also exposed for source compatibility.
type PhoneItem struct {
	Mobile        string `json:"mobile"`
	ShowMobile    string `json:"show_mobile"`
	NeedAuth      bool   `json:"need_auth"`
	AllowSendSMS  bool   `json:"allow_send_sms"`
	EncryptedData string `json:"encryptedData"`
	IV            string `json:"iv"`
	CloudID       string `json:"cloud_id"`
	Data          string `json:"data"`
	Code          string `json:"code"`
}

func ValidateGetAllPhone(appID string, _ map[string]any) error {
	if !hostSignProvider.MatchString(appID) {
		return fmt.Errorf("invalid app_id")
	}
	return nil
}
func buildGetAllPhoneRequest(session AppSession, appID string, device []byte) ([]byte, error) {
	if err := ValidateGetAllPhone(appID, nil); err != nil {
		return nil, MarkNoRetry(err)
	}
	// The source literal is missing its final brace. Marshal the same intended
	// structure instead of sending malformed JSON.
	data, err := json.Marshal(map[string]any{"data": map[string]any{"with_credentials": true, "api_name": "webapi_getuserwxphone"}})
	if err != nil {
		return nil, err
	}
	body := pbLen(1, metadataBaseReq(session, device))
	body = append(body, pbLen(2, []byte(appID))...)
	body = append(body, pbLen(3, data)...)
	body = append(body, pbVar(6, 0)...)
	return buildJSAPIPlaintext(session.UIN, appID, []byte("/cgi-bin/mmbiz-bin/wxaapp/customphone/getallphone"), 2536, body, session.HostAppID, device), nil
}

func parseGetAllPhoneResponse(resp []byte) (map[string]any, error) {
	fields, out, err := metadataResponse(resp)
	if err != nil {
		return nil, err
	}
	if _, ok := out["ret"]; !ok {
		out["ret"] = int32(0)
	}
	out["err_msg"] = ""
	if msg, ok := out["errMsg"]; ok {
		out["err_msg"] = msg
	}
	delete(out, "errMsg")
	jsapi, err := parseMetadataFields(fields.bytes(2))
	if err != nil {
		return nil, fmt.Errorf("getAllPhone: missing or malformed JSAPI response")
	}
	ret := int32(jsapi.number(1))
	if ret != 0 {
		return nil, fmt.Errorf("getAllPhone: JSAPI ret=%d", ret)
	}
	out["jsapi_ret"] = ret
	for n, key := range map[protowire.Number]string{2: "jsapi_err_msg", 5: "appname", 6: "appicon_url", 7: "cancel_wording", 8: "allow_wording", 9: "apply_wording"} {
		out[key] = string(jsapi.bytes(n))
	}
	if raw := jsapi.bytes(4); raw != nil {
		scope, e := parseMetadataFields(raw)
		if e != nil {
			return nil, fmt.Errorf("getAllPhone: invalid scope")
		}
		out["scope"] = map[string]any{"scope": string(scope.bytes(1)), "desc": string(scope.bytes(2)), "authState": int32(scope.number(3)), "extDesc": string(scope.bytes(4)), "authDesc": string(scope.bytes(5))}
	} else {
		out["scope"] = nil
	}
	var data map[string]json.RawMessage
	if raw := jsapi.bytes(3); len(raw) == 0 || json.Unmarshal(raw, &data) != nil || data == nil {
		return nil, fmt.Errorf("getAllPhone: missing or malformed phone JSON")
	}
	all := make([]PhoneItem, 0)
	for _, key := range []string{"custom_phone_list", "wx_phone"} {
		raw, ok := data[key]
		if !ok {
			continue
		}
		raw = bytes.TrimSpace(raw)
		if bytes.Equal(raw, []byte("null")) {
			continue
		}
		var list []PhoneItem
		if len(raw) > 0 && raw[0] == '[' {
			if json.Unmarshal(raw, &list) != nil {
				return nil, fmt.Errorf("getAllPhone: invalid %s array", key)
			}
		} else if key == "wx_phone" && len(raw) > 0 && raw[0] == '{' {
			var item PhoneItem
			if json.Unmarshal(raw, &item) != nil {
				return nil, fmt.Errorf("getAllPhone: invalid wx_phone item")
			}
			list = []PhoneItem{item}
		} else {
			return nil, fmt.Errorf("getAllPhone: invalid %s shape", key)
		}
		for i := range list {
			if list[i].Data != "" {
				var nested struct {
					Code string `json:"code"`
				}
				if json.Unmarshal([]byte(list[i].Data), &nested) != nil {
					return nil, fmt.Errorf("getAllPhone: invalid nested phone data")
				}
				list[i].Code = nested.Code
			}
		}
		all = append(all, list...)
	}
	out["all_mobile"] = all
	return out, nil
}

func (p *Pool) GetAllPhone(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string, fallbackDirect bool, expected ...*store.WechatAccount) (map[string]any, error) {
	if err := ValidateGetAllPhone(appID, nil); err != nil {
		return nil, MarkNoRetry(err)
	}
	return p.runMetadata(ctx, loginBuffer, accountID, tcpProxy, fallbackDirect, func(st WmpfSession) ([]byte, error) {
		return buildGetAllPhoneRequest(st.Session, appID, st.Device.SessDevice)
	}, func(_, resp []byte) (map[string]any, error) { return parseGetAllPhoneResponse(resp) }, expected...)
}
