package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func phoneListFixture(data string) []byte {
	jsapi := append(pbVar(1, 0), pbLen(3, []byte(data))...)
	return append(pbLen(1, pbVar(1, 0)), pbLen(2, jsapi)...)
}
func TestAllPhoneListShapes(t *testing.T) {
	for _, wxPhone := range []string{`{"mobile":"synthetic-b","data":"{\"code\":\"test-code\"}"}`, `[{"mobile":"synthetic-b","data":"{\"code\":\"test-code\"}"}]`} {
		data := `{"custom_phone_list":[{"mobile":"synthetic-a","show_mobile":"masked","need_auth":true}],"wx_phone":` + wxPhone + `}`
		out, err := parseGetAllPhoneResponse(phoneListFixture(data))
		if err != nil {
			t.Fatal(err)
		}
		list := out["all_mobile"].([]PhoneItem)
		if len(list) != 2 || !list[0].NeedAuth || list[0].ShowMobile != "masked" || list[1].Code != "test-code" {
			t.Fatalf("items=%v", list)
		}
	}
	out, err := parseGetAllPhoneResponse(phoneListFixture(`{"custom_phone_list":[],"wx_phone":null}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(out)
	if !bytes.Contains(encoded, []byte(`"all_mobile":[]`)) {
		t.Fatalf("empty list is not JSON array: %s", encoded)
	}
}
func TestAllPhoneMalformedResponses(t *testing.T) {
	for _, raw := range [][]byte{nil, {0x12, 0xff}, pbLen(1, pbVar(1, 7)), append(pbLen(1, pbVar(1, 0)), pbLen(2, pbVar(1, 9))...), phoneListFixture(`not-json`), phoneListFixture(`{"wx_phone":1}`), phoneListFixture(`{"custom_phone_list":{}}`), phoneListFixture(`{"wx_phone":{"data":"not-json"}}`)} {
		if _, err := parseGetAllPhoneResponse(raw); err == nil {
			t.Fatalf("accepted invalid response %x", raw)
		}
	}
}
func TestAllPhoneRequestUsesValidJSONAndDevice(t *testing.T) {
	device := []byte("stable-device")
	raw, err := buildGetAllPhoneRequest(AppSession{UIN: 99}, "wx1234567890abcdef", device)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"data": map[string]any{"api_name": "webapi_getuserwxphone", "with_credentials": true}})
	if !bytes.Contains(raw, data) || !bytes.Contains(raw, device) || !bytes.Contains(raw, []byte("customphone/getallphone")) {
		t.Fatal("request missing JSON, device or endpoint")
	}
	var p *Pool
	if _, err := p.GetAllPhone(context.Background(), "", "bad", 0, "", false); err == nil {
		t.Fatal("invalid appid triggered pool")
	}
}
