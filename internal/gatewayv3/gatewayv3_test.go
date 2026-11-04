package gatewayv3

import (
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestAESCBCRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("Hello WeChat Gateway V3! " + "padding test " + "more data here!!")

	iv, ct, err := aesEncrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(iv) != AESBlockSize {
		t.Errorf("iv len = %d, want %d", len(iv), AESBlockSize)
	}

	if len(ct)%AESBlockSize != 0 {
		t.Errorf("ct not block-aligned: %d", len(ct))
	}

	pt, err := aesDecrypt(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(plaintext) {
		t.Fatal("AES-CBC round-trip mismatch")
	}
	t.Logf("AES-CBC: %dB → %dB → %dB OK", len(plaintext), len(ct), len(pt))

	wire := append(iv, ct...)
	pt2, err := aesDecryptFromWire(key, wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != string(plaintext) {
		t.Fatal("wire decrypt mismatch")
	}
	t.Log("wire decrypt: OK")
}

func TestPBV3Header(t *testing.T) {
	h := &V3Header{
		EncryptionTimestamp: 1757922934215,
		Compression:         "snappy",
		LibBuildTs:          1784279218415,
		AppProtocol:         "1/JSON",
	}
	pb := pbEncodeV3Header(h)
	h2, err := pbDecodeV3Header(pb)
	if err != nil {
		t.Fatal(err)
	}
	if h2.AppProtocol != "1/JSON" {
		t.Errorf("appProtocol = %s", h2.AppProtocol)
	}
	if h2.Compression != "snappy" {
		t.Errorf("compression = %s", h2.Compression)
	}
	if h2.EncryptionTimestamp != 1757922934215 {
		t.Errorf("encryptionTimestamp = %d", h2.EncryptionTimestamp)
	}
	t.Logf("V3Header PB: %dB OK", len(pb))
}

func TestPBV3Request(t *testing.T) {
	req := &V3RequestPB{
		Method: "POST",
		Header: []PBHeader{{Key: "k1", Value: "v1"}},
		Body:   []byte("BINARY"),
		CallID: "abc-123",
	}
	pb := pbEncodeV3Request(req)
	t.Logf("V3Request PB: %dB", len(pb))
	if len(pb) < 10 {
		t.Error("encoded too short")
	}
}

func TestFullV3JSONRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	headers := map[string]string{"X-Test": "hello"}
	data := map[string]any{"msg": "world"}

	wire, callID, err := v3EncodeRequest(key, headers, "POST", data, "/api/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("callID=%s wire=%dB", callID, len(wire))

	dec, err := v3DecryptResponse(key, wire)
	if err != nil {
		t.Fatal(err)
	}
	if dec.V3Header.AppProtocol != "1/JSON" {
		t.Errorf("appProtocol = %s", dec.V3Header.AppProtocol)
	}

	var req V3RequestJSON
	if err := json.Unmarshal(dec.Data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" {
		t.Errorf("method = %s", req.Method)
	}
	if req.CallID != callID {
		t.Errorf("callID = %s, want %s", req.CallID, callID)
	}
	t.Logf("V3 full round-trip: OK")
}

func TestTokenNormalize(t *testing.T) {
	nowMs := nowMs()
	raw := map[string]any{
		"key":        "aGVsbG8=",
		"token":      "tok123",
		"rid":        758911827,
		"timestamp":  float64(nowMs),
		"expires_in": float64(7200),
	}
	tok := normalizeToken(raw)
	if tok.RID != "758911827" {
		t.Errorf("rid = %s", tok.RID)
	}
	if tok.Exp <= nowMs {
		t.Error("expiry should be in the future")
	}
	t.Logf("Token: rid=%s exp=%d", tok.RID, tok.Exp)
}

func TestPKCS7Padding(t *testing.T) {
	data := make([]byte, 16)
	padded := pkcs7Pad(data, 16)
	if len(padded) != 32 {
		t.Errorf("padded len = %d, want 32", len(padded))
	}
	unpadded, err := pkcs7Unpad(padded, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpadded) != 16 {
		t.Errorf("unpadded len = %d", len(unpadded))
	}

	data2 := make([]byte, 20)
	padded2 := pkcs7Pad(data2, 16)
	if len(padded2) != 32 {
		t.Errorf("padded2 len = %d, want 32", len(padded2))
	}
	unpadded2, _ := pkcs7Unpad(padded2, 16)
	if len(unpadded2) != 20 {
		t.Errorf("unpadded2 len = %d", len(unpadded2))
	}
	t.Log("PKCS7: OK")
}

func TestRefreshFunc(t *testing.T) {
	tm := newTokenManager("test.example.com", "session123")

	customRefresh := func(host, session string) (*GatewayToken, error) {
		return &GatewayToken{
			Key:       "dGVzdGtleQ==",
			Token:     "custom-token-123",
			RID:       "999",
			Exp:       nowMs() + 7200000,
			Timestamp: nowMs(),
			ExpiresIn: 7200,
		}, nil
	}

	tm.SetRefresher(customRefresh)
	token, err := tm.GetToken()
	if err != nil {
		t.Fatal(err)
	}
	if token.Token != "custom-token-123" {
		t.Errorf("token = %s, want custom-token-123", token.Token)
	}
	if token.RID != "999" {
		t.Errorf("rid = %s, want 999", token.RID)
	}
	t.Logf("RefreshFunc: token=%s rid=%s OK", token.Token, token.RID)
}

func TestBuildAuthPayload(t *testing.T) {
	domain := "a1d5ae6e7-wx621112590b635086.sh.wxcloudrun.com"
	payload := BuildAuthPayload(domain)

	if payload["api_name"] != "qbase_commapi" {
		t.Errorf("api_name = %v", payload["api_name"])
	}
	if payload["operate_directly"] != true {
		t.Errorf("operate_directly = %v", payload["operate_directly"])
	}
	if v, ok := payload["env"]; !ok || toInt(v) != 1 {
		t.Errorf("env = %v", payload["env"])
	}

	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	if data["qbase_api_name"] != "tcbapi_get_service_info" {
		t.Errorf("qbase_api_name = %v", data["qbase_api_name"])
	}

	qbaseReqStr, ok := data["qbase_req"].(string)
	if !ok {
		t.Fatal("qbase_req is not a string")
	}
	var qbaseReq map[string]any
	json.Unmarshal([]byte(qbaseReqStr), &qbaseReq)
	if qbaseReq["system"] != "HarmonyOS" {
		t.Errorf("system = %v", qbaseReq["system"])
	}
	if qbaseReq["domain"] != domain {
		t.Errorf("domain = %v, want %s", qbaseReq["domain"], domain)
	}
	if v, ok := qbaseReq["scene"]; !ok || toInt(v) != 3 {
		t.Errorf("scene = %v", qbaseReq["scene"])
	}

	cliReqID, ok := data["cli_req_id"].(string)
	if !ok {
		t.Fatal("cli_req_id is not a string")
	}
	t.Logf("cli_req_id = %s", cliReqID)

	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	t.Logf("payload:\n%s", string(payloadJSON))
}

func TestBuildCliReqID(t *testing.T) {
	tsMs := int64(1784616571299)
	id := BuildCliReqID(tsMs)
	if len(id) < 20 {
		t.Errorf("cli_req_id too short: %s", id)
	}
	t.Logf("BuildCliReqID(%d) = %s", tsMs, id)
}

func TestNormalizeTokenExported(t *testing.T) {
	nowMs := nowMs()
	raw := map[string]any{
		"key":        "aGVsbG8=",
		"token":      "tok456",
		"rid":        12345,
		"timestamp":  float64(nowMs),
		"expires_in": float64(3600),
	}
	tok := NormalizeToken(raw)
	if tok.Token != "tok456" {
		t.Errorf("token = %s", tok.Token)
	}
	if tok.RID != "12345" {
		t.Errorf("rid = %s", tok.RID)
	}
	t.Logf("NormalizeToken (flat): token=%s rid=%s OK", tok.Token, tok.RID)
}

func TestNormalizeTokenOperateWXData(t *testing.T) {
	raw := map[string]any{"data": map[string]any{"key": "synthetic-key", "token": "synthetic-token", "rid": "synthetic-rid", "timestamp": float64(1700000000000), "expires_in": float64(3600)}}
	tok := NormalizeToken(raw)
	if tok.Key != "synthetic-key" || tok.Token != "synthetic-token" || tok.RID != "synthetic-rid" || tok.ExpiresIn != 3600 {
		t.Fatalf("incorrect token normalization: %+v", tok)
	}
}
func TestNormalizeTokenDataString(t *testing.T) {
	raw := map[string]any{
		"data":   `{"token":"106_test","key":"aGVsbG8=","rid":999,"iat":1784626168,"exp":1784633368}`,
		"err_no": float64(0),
	}
	tok := NormalizeToken(raw)
	if tok.Token != "106_test" {
		t.Errorf("token = %s, want 106_test", tok.Token)
	}
	if tok.RID != "999" {
		t.Errorf("rid = %s, want 999", tok.RID)
	}
	if tok.Key != "aGVsbG8=" {
		t.Errorf("key = %s", tok.Key)
	}
	if tok.Timestamp != 1784626168000 {
		t.Errorf("timestamp = %d, want 1784626168000", tok.Timestamp)
	}
	t.Logf("NormalizeToken (data string): token=%s rid=%s key=%s OK", tok.Token, tok.RID, tok.Key)
}
