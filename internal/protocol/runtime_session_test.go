package protocol

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestRuntimeSessionRequest(t *testing.T) {
	device := []byte("fixture-PC-device")
	raw, err := buildRuntimeSessionRequest(AppSession{UIN: 12345, HostAppID: []byte("fixture-host")},
		"wx3723729dc4ac916c", device)
	if err != nil {
		t.Fatal(err)
	}
	outer := pbParse(raw)
	if outer[7] != int64(3540) || string(outer[2].([]byte)) != "/cgi-bin/mmbiz-bin/wxabusiness/getruntimesession" {
		t.Fatal("wrong CGI/path")
	}
	fields, err := runtimeWireFields(outer[5].([]byte))
	if err != nil || len(fields) != 2 {
		t.Fatal("request must contain only BaseRequest and AppID")
	}
	inner := pbParse(outer[5].([]byte))
	session := pbParse(inner[1].([]byte))
	outerSession := pbParse(outer[1].([]byte))
	if string(inner[2].([]byte)) != "wx3723729dc4ac916c" || session[2] != int64(12345) || !bytes.Equal(session[3].([]byte), device) || !bytes.Equal(outerSession[3].([]byte), device) || !bytes.Equal(session[5].([]byte), unifiedPCWindows) {
		t.Fatalf("session or device mismatch: %v", session)
	}
}

func TestRuntimeSessionResponse(t *testing.T) {
	base := []byte{8, 0}
	direct := hostSignBytes(hostSignBytes(nil, 1, base), 2, []byte("fixture-session"))
	wrapped := hostSignBytes(hostSignBytes(nil, 1, base), 2, direct)
	for _, raw := range [][]byte{direct, wrapped} {
		result, err := parseRuntimeSessionResponse(raw)
		if err != nil || result["session_id"] != "fixture-session" || result["experimental"] != true {
			t.Fatalf("parse: %#v %v", result, err)
		}
	}
	errorBase := protowire.AppendVarint([]byte{8}, ^uint64(7)) // int32(-8)
	errorResponse := hostSignBytes(hostSignBytes(nil, 1, errorBase), 2, []byte("fixture-session"))
	jsapiError := hostSignBytes(errorBase, 2, []byte("blocked"))
	wrappedError := hostSignBytes(hostSignBytes(nil, 1, base), 2, jsapiError)
	jsapiOKButNotSession := hostSignBytes([]byte{8, 0}, 2, []byte("ok"))
	for _, raw := range [][]byte{nil, {255}, {18, 255}, errorResponse, wrappedError, jsapiOKButNotSession,
		hostSignBytes(nil, 2, []byte("no-base")), hostSignBytes(hostSignBytes(nil, 1, base), 2, []byte("user login blocked"))} {
		_, err := parseRuntimeSessionResponse(raw)
		if err == nil || strings.Contains(err.Error(), "fixture-session") {
			t.Fatalf("false success or secret disclosure: %v", err)
		}
	}
}
