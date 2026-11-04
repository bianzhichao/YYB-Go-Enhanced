package gatewayv3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip909 func(*http.Request) (*http.Response, error)

func (f roundTrip909) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func Test909ClientEncryptedHTTP(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	client := NewClient("fixture.sh.wxcloudrun.com", "", time.Second)
	client.SetToken(&GatewayToken{Key: base64.StdEncoding.EncodeToString(key), Token: "fixture+token&=", Exp: nowMs() + 60000})
	count := 0
	client.SetHTTPClient(&http.Client{Transport: roundTrip909(func(r *http.Request) (*http.Response, error) {
		count++
		if r.URL.Query().Get("token") != "fixture+token&=" || r.URL.Path != CallPath {
			t.Fatal("query escaping")
		}
		raw, _ := io.ReadAll(r.Body)
		dec, err := v3DecryptResponse(key, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(dec.Data, []byte("/api/test")) {
			t.Fatal("business path lost")
		}
		body, _ := json.Marshal(V3ResponseJSON{StatusCode: 200, BodyString: `{"ok":true}`})
		wire, _, err := zeV3Pack(key, body, "JSON")
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/octet-stream; charset=binary"}}, Body: io.NopCloser(bytes.NewReader(wire))}, nil
	})})
	result, err := client.CallContext(context.Background(), "/api/test", "POST", map[string]any{"x": 1}, nil)
	if err != nil || result.StatusCode != 200 || string(result.Data) != `{"ok":true}` || count != 1 {
		t.Fatalf("%+v %v calls=%d", result, err, count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.CallContext(ctx, "/api/test", "POST", nil, nil); err == nil || count != 1 {
		t.Fatal("cancellation")
	}
	client.SetHTTPClient(&http.Client{Transport: roundTrip909(func(r *http.Request) (*http.Response, error) { return nil, fmt.Errorf("secret fixture+token&=") })})
	if _, err = client.CallContext(context.Background(), "/api/test", "POST", nil, nil); err == nil || strings.Contains(err.Error(), "fixture+") {
		t.Fatal("secret leaked")
	}
}

func Test909MalformedWireAndExpiry(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	for n := 0; n < 100; n++ {
		_, _ = aesDecrypt(key, make([]byte, 16), make([]byte, n))
		_, _ = v3DecodeResponse(key, make([]byte, n))
	}
	if _, _, err := pbDecodeRawValue([]byte{255, 255, 255, 255, 255, 255, 255, 255, 127}, 0, 2); err == nil {
		t.Fatal("oversized length")
	}
	if _, _, err := pbDecodeVarint(bytes.Repeat([]byte{255}, 11), 0); err == nil {
		t.Fatal("overflow")
	}
	if NormalizeToken(map[string]any{}).Key != "" {
		t.Fatal("missing key converted to text")
	}
	old := nowMs() - 3600000
	if exp := calcExpiry(old, 60); exp > nowMs() {
		t.Fatal("expired token resurrected")
	}
}

func TestGatewayResponseLimitsAndHTTPFailures(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	for _, kind := range []string{"oversized", "status", "content-type", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			c := NewClient("fixture.wxcloudrun.com", "", time.Second)
			c.SetToken(&GatewayToken{Key: base64.StdEncoding.EncodeToString(key), Token: "synthetic", Exp: nowMs() + 60000})
			calls := 0
			c.SetHTTPClient(&http.Client{Transport: roundTrip909(func(r *http.Request) (*http.Response, error) {
				calls++
				status := 200
				contentType := "application/octet-stream"
				data := []byte{0, 1, 2}
				switch kind {
				case "oversized":
					data = make([]byte, MaxResponseBytes+1)
				case "status":
					status = 302
				case "content-type":
					contentType = "text/html"
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})})
			if _, err := c.Call("/api", "POST", nil, nil); err == nil || calls != 1 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
	wire, _, err := zeV3Pack(key, make([]byte, MaxResponseBytes+1), "JSON")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v3DecodeResponse(key, wire); err == nil {
		t.Fatal("accepted decompression overflow")
	}
}

func TestGatewayRejectsMalformedPBAndJSON(t *testing.T) {
	// A valid status followed by an unterminated tag must not become a success.
	pb := pbEncodeInt64(nil, 1, 200)
	pb = append(pb, 0x80)
	if _, err := pbDecodeV3Response(pb); err == nil {
		t.Fatal("accepted malformed PB tail")
	}
	if _, _, err := v3EncodeRequest(make([]byte, 32), nil, "POST", make(chan int), "/api"); err == nil {
		t.Fatal("ignored JSON encoding failure")
	}
}
