package gatewayv3

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/golang/snappy"
)

// ═══════════════════════════════════════════════════════════════
// V3 protocol: encrypt + pack (gatewayV3.js:2241-2257 ze)
// ═══════════════════════════════════════════════════════════════
//
// Wire format:
//
//	[2B big-endian header_len] [16B header_IV] [header_ct] [16B body_IV] [body_ct]

func zeV3Pack(key []byte, bodyPlaintext []byte, appProtocol string) ([]byte, *V3Header, error) {
	nowMs := time.Now().UnixMilli()

	v3h := &V3Header{
		AppProtocol:         "1/" + appProtocol,
		Compression:         "snappy",
		EncryptionTimestamp: nowMs,
		LibBuildTs:          LibBuildTS,
	}
	headerPB := pbEncodeV3Header(v3h)

	headerIV, headerCT, err := aesEncrypt(key, headerPB)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt header: %w", err)
	}
	headerSection := append(headerIV, headerCT...)
	headerLen := len(headerSection)

	compressed := snappy.Encode(nil, bodyPlaintext)

	bodyIV, bodyCT, err := aesEncrypt(key, compressed)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt body: %w", err)
	}
	bodySection := append(bodyIV, bodyCT...)

	buf := make([]byte, 2+headerLen+len(bodySection))
	binary.BigEndian.PutUint16(buf[:2], uint16(headerLen))
	copy(buf[2:], headerSection)
	copy(buf[2+headerLen:], bodySection)

	return buf, v3h, nil
}

// ═══════════════════════════════════════════════════════════════
// V3 encodeRequest (gatewayV3.js:2260-2282 Ke)
// ═══════════════════════════════════════════════════════════════

func v3EncodeRequest(key []byte, headers map[string]string, method string, data any, path string) (wire []byte, callID string, err error) {
	callID = fmt.Sprintf("%d-%s", time.Now().UnixMilli(), randomNonce(8))

	headerList := []PBHeader{}
	for k, v := range headers {
		if k != "" {
			headerList = append(headerList, PBHeader{Key: toLower(k), Value: v})
		}
	}
	headerList = append(headerList, PBHeader{Key: "x-wx-target-service", Value: "HTTP"})

	var bodyPlaintext []byte
	var appProtocol string

	if data == nil {
		reqJSON := V3RequestJSON{Body: nil, CallID: callID, Header: headerList, Method: method}
		bodyPlaintext, err = json.Marshal(reqJSON)
		appProtocol = "JSON"
	} else if b, ok := data.([]byte); ok {
		reqPB := &V3RequestPB{Method: method, Header: headerList, Body: b, CallID: callID}
		bodyPlaintext = pbEncodeV3Request(reqPB)
		appProtocol = "PB"
	} else {
		reqJSON := V3RequestJSON{Body: data, CallID: callID, Header: headerList, Method: method}
		bodyPlaintext, err = json.Marshal(reqJSON)
		appProtocol = "JSON"
	}

	if err != nil {
		return nil, callID, fmt.Errorf("encode request JSON: %w", err)
	}
	wire, _, err = zeV3Pack(key, bodyPlaintext, appProtocol)
	return wire, callID, err
}

// ═══════════════════════════════════════════════════════════════
// V3 decrypt response (gatewayV3.js:2316-2326 rt + L2342-2355 it)
// ═══════════════════════════════════════════════════════════════

type v3Decrypted struct {
	Data     []byte
	V3Header *V3Header
}

func v3DecryptResponse(key, rawData []byte) (*v3Decrypted, error) {
	if len(rawData) < 2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(rawData))
	}

	headerLen := int(binary.BigEndian.Uint16(rawData[:2]))
	if 2+headerLen > len(rawData) {
		return nil, fmt.Errorf("header section exceeds data: %d > %d", 2+headerLen, len(rawData))
	}

	headerSection := rawData[2 : 2+headerLen]
	bodySection := rawData[2+headerLen:]

	headerPlain, err := aesDecryptFromWire(key, headerSection)
	if err != nil {
		return nil, fmt.Errorf("decrypt header: %w", err)
	}

	v3h, err := pbDecodeV3Header(headerPlain)
	if err != nil {
		return nil, fmt.Errorf("decode v3header: %w", err)
	}

	bodyPlain, err := aesDecryptFromWire(key, bodySection)
	if err != nil {
		return nil, fmt.Errorf("decrypt body: %w", err)
	}

	size, err := snappy.DecodedLen(bodyPlain)
	if err != nil || size > MaxResponseBytes {
		return nil, fmt.Errorf("invalid or oversized snappy response")
	}
	decompressed, err := snappy.Decode(nil, bodyPlain)
	if err != nil {
		return nil, fmt.Errorf("snappy decompress: %w", err)
	}

	return &v3Decrypted{Data: decompressed, V3Header: v3h}, nil
}

// v3DecodedResponse holds the fully decoded V3 response.
type v3DecodedResponse struct {
	StatusCode int
	Body       []byte
	BodyString string
	Header     map[string]string
}

func v3DecodeResponse(key, rawData []byte) (*v3DecodedResponse, error) {
	dec, err := v3DecryptResponse(key, rawData)
	if err != nil {
		return nil, err
	}

	isPB := false
	if ap := dec.V3Header.AppProtocol; len(ap) > 2 && ap[len(ap)-2:] == "PB" {
		isPB = true
	}

	result := &v3DecodedResponse{Header: map[string]string{}}

	if isPB {
		pbResp, err := pbDecodeV3Response(dec.Data)
		if err != nil {
			return nil, fmt.Errorf("decode v3response pb: %w", err)
		}
		result.StatusCode = int(pbResp.StatusCode)
		if len(pbResp.BodyBuffer) > 0 {
			result.Body = pbResp.BodyBuffer
		} else {
			result.BodyString = pbResp.BodyString
		}
		for _, h := range pbResp.Header {
			if h.Key != "" && h.Value != "" {
				if existing, ok := result.Header[h.Key]; ok {
					result.Header[h.Key] = existing + "," + h.Value
				} else {
					result.Header[h.Key] = h.Value
				}
			}
		}
	} else {
		var jsonResp V3ResponseJSON
		if err := json.Unmarshal(dec.Data, &jsonResp); err != nil {
			return nil, fmt.Errorf("decode v3response json: %w", err)
		}
		result.StatusCode = jsonResp.StatusCode
		if len(jsonResp.BodyBuffer) > 0 {
			result.Body = jsonResp.BodyBuffer
		} else {
			result.BodyString = jsonResp.BodyString
		}
		for _, h := range jsonResp.Header {
			if h.Key != "" && h.Value != "" {
				if existing, ok := result.Header[h.Key]; ok {
					result.Header[h.Key] = existing + "," + h.Value
				} else {
					result.Header[h.Key] = h.Value
				}
			}
		}
	}

	return result, nil
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

const nonceAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"

func randomNonce(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = nonceAlphabet[rand.Intn(len(nonceAlphabet))]
	}
	return string(b)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}
