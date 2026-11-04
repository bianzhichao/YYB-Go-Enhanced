package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDedicatedA8KeyRequestFields(t *testing.T) {
	session := AppSession{UIN: 12345, DeviceID: []byte("synthetic-device"), Ticket: []byte("synthetic-ticket")}
	raw := buildMPa8keyRequest(session, "wx1234567890abcdef", "https://example.com/callback", "synthetic-biz", 0)
	fields, err := a8Fields(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fields[2] != uint64(2) || fields[10] != uint64(0) || fields[14] != uint64(2) || fields[25] != uint64(0) || string(fields[17].([]byte)) != "WIFI" {
		t.Fatal(fields)
	}
	base, err := a8Fields(fields[1].([]byte))
	if err != nil || !bytes.Equal(base[3].([]byte), session.DeviceID) {
		t.Fatal(base, err)
	}
	cookie, err := a8Fields(fields[23].([]byte))
	if err != nil || cookie[1] != uint64(len(session.Ticket)) || !bytes.Equal(cookie[2].([]byte), session.Ticket) {
		t.Fatal(cookie, err)
	}
}
func TestDedicatedA8KeyPacketUses2909Route(t *testing.T) {
	session := AppSession{UIN: 1, DeviceID: []byte("synthetic"), SendKey: bytes.Repeat([]byte{1}, 32)}
	packet, err := buildA8keyPacket(session, []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint32(packet)) != len(packet)-4 {
		t.Fatal("bad length")
	}
	n := int(binary.BigEndian.Uint16(packet[4:]))
	if string(packet[6:6+n]) != "/ilink/ilinkapp/mm/ilinkmpgeta8key" {
		t.Fatal("wrong CGI")
	}
}
func TestDedicatedA8KeyParserAndErrors(t *testing.T) {
	reply := a8Bytes(nil, 1, a8Var(nil, 1, 0))
	reply = a8Bytes(reply, 2, []byte("https://weixin.qq.com/synthetic"))
	reply = a8Bytes(reply, 3, []byte("synthetic-key"))
	reply = a8Bytes(reply, 17, a8Bytes(a8Var(nil, 1, 2), 2, []byte{0xaa, 0xbb}))
	result, err := parseA8KeyResponse(nil, reply)
	if err != nil || result["cookie"] != "aabb" || result["a8key"] != "synthetic-key" {
		t.Fatal(result, err)
	}
	for _, bad := range [][]byte{nil, {0x0a, 0xff}, a8Bytes(nil, 1, a8Var(nil, 1, 7)), a8Bytes(nil, 1, a8Var(nil, 1, 0)), []byte(`{"ret":0}`), []byte(`{"ret":5,"full_url":"https://weixin.qq.com"}`)} {
		if _, err = parseA8KeyResponse(nil, bad); err == nil {
			t.Fatalf("accepted invalid response %x", bad)
		}
	}
	result, err = parseA8KeyResponse([]byte(`{"ret":0,"full_url":"https://weixin.qq.com/synthetic"}`), nil)
	if err != nil || result["full_url"] == nil {
		t.Fatal(result, err)
	}
}
func TestDedicatedA8KeyInputValidation(t *testing.T) {
	for _, payload := range []map[string]any{nil, {"target_url": "file:///secret"}, {"target_url": "https://user@weixin.qq.com"}, {"target_url": "https://weixin.qq.com", "scene": 1.5}, {"target_url": "https://weixin.qq.com", "scene": -1}} {
		if _, _, _, err := NormalizeA8KeyPayload(payload); err == nil {
			t.Fatal(payload)
		}
	}
	_, _, scene, err := NormalizeA8KeyPayload(map[string]any{"targetUrl": "https://weixin.qq.com"})
	if err != nil || scene != 5 {
		t.Fatal(scene, err)
	}
}
