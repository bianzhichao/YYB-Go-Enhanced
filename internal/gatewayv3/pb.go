package gatewayv3

import (
	"encoding/json"
	"fmt"
)

// ═══════════════════════════════════════════════════════════════
// Protobuf manual encode/decode
// ═══════════════════════════════════════════════════════════════
//
// Wire types: 0=varint, 2=length-delimited
// Tag: (field_number << 3) | wire_type

// -- Varint ---------------------------------------------------

func pbEncodeVarint(buf []byte, value uint64) []byte {
	for value > 0x7F {
		buf = append(buf, byte(value&0x7F|0x80))
		value >>= 7
	}
	buf = append(buf, byte(value&0x7F))
	return buf
}

func pbDecodeVarint(data []byte, offset int) (uint64, int, error) {
	var value uint64
	var shift uint
	for offset < len(data) {
		b := data[offset]
		offset++
		if shift > 63 || (shift == 63 && b > 1) {
			return 0, offset, fmt.Errorf("varint overflow")
		}
		value |= uint64(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			return value, offset, nil
		}
	}
	return 0, offset, fmt.Errorf("varint unterminated")
}

// -- Field helpers --------------------------------------------

func pbTag(fieldNum int, wireType int) uint64 {
	return uint64(fieldNum<<3 | wireType)
}

func pbEncodeFieldTag(buf []byte, fieldNum int, wireType int) []byte {
	return pbEncodeVarint(buf, pbTag(fieldNum, wireType))
}

// -- Encode primitives ----------------------------------------

func pbEncodeString(buf []byte, fieldNum int, value string) []byte {
	if value == "" {
		return buf
	}
	data := []byte(value)
	buf = pbEncodeFieldTag(buf, fieldNum, 2)
	buf = pbEncodeVarint(buf, uint64(len(data)))
	buf = append(buf, data...)
	return buf
}

func pbEncodeBytes(buf []byte, fieldNum int, value []byte) []byte {
	if len(value) == 0 {
		return buf
	}
	buf = pbEncodeFieldTag(buf, fieldNum, 2)
	buf = pbEncodeVarint(buf, uint64(len(value)))
	buf = append(buf, value...)
	return buf
}

func pbEncodeInt64(buf []byte, fieldNum int, value int64) []byte {
	if value == 0 {
		return buf
	}
	buf = pbEncodeFieldTag(buf, fieldNum, 0)
	buf = pbEncodeVarint(buf, uint64(value))
	return buf
}

func pbEncodeMessage(buf []byte, fieldNum int, msg []byte) []byte {
	if len(msg) == 0 {
		return buf
	}
	buf = pbEncodeFieldTag(buf, fieldNum, 2)
	buf = pbEncodeVarint(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	return buf
}

// -- Decode helpers -------------------------------------------

func pbDecodeTag(data []byte, offset int) (fieldNum int, wireType int, newOffset int, err error) {
	val, off, err := pbDecodeVarint(data, offset)
	if err != nil {
		return 0, 0, off, err
	}
	return int(val >> 3), int(val & 0x7), off, nil
}

func pbDecodeRawValue(data []byte, offset int, wireType int) (any, int, error) {
	switch wireType {
	case 0: // varint
		val, off, err := pbDecodeVarint(data, offset)
		return int64(val), off, err
	case 2: // length-delimited
		length, off, err := pbDecodeVarint(data, offset)
		if err != nil {
			return nil, off, err
		}
		if length > uint64(len(data)-off) {
			return nil, off, fmt.Errorf("length-delimited field exceeds data")
		}
		end := off + int(length)
		val := make([]byte, int(length))
		copy(val, data[off:end])
		return val, end, nil
	default:
		return nil, offset, fmt.Errorf("unsupported wire type: %d", wireType)
	}
}

// ═══════════════════════════════════════════════════════════════
// V3Header PB (JS De L2031)
//   field 1: encryptionTimestamp (int64)
//   field 2: compression         (string)
//   field 3: userTimeout         (int64)
//   field 4: libBuildTs          (int64)
//   field 5: appProtocol         (string)
// ═══════════════════════════════════════════════════════════════

type V3Header struct {
	EncryptionTimestamp int64
	Compression         string
	UserTimeout         int64
	LibBuildTs          int64
	AppProtocol         string
}

func pbEncodeV3Header(h *V3Header) []byte {
	var buf []byte
	buf = pbEncodeInt64(buf, 1, h.EncryptionTimestamp)
	buf = pbEncodeString(buf, 2, h.Compression)
	buf = pbEncodeInt64(buf, 3, h.UserTimeout)
	buf = pbEncodeInt64(buf, 4, h.LibBuildTs)
	buf = pbEncodeString(buf, 5, h.AppProtocol)
	return buf
}

func pbDecodeV3Header(data []byte) (*V3Header, error) {
	h := &V3Header{}
	offset := 0
	for offset < len(data) {
		fn, wt, off, err := pbDecodeTag(data, offset)
		if err != nil {
			return h, err
		}
		val, off, err := pbDecodeRawValue(data, off, wt)
		if err != nil {
			return h, err
		}
		offset = off
		switch fn {
		case 1:
			if v, ok := val.(int64); ok {
				h.EncryptionTimestamp = v
			}
		case 2:
			if v, ok := val.([]byte); ok {
				h.Compression = string(v)
			}
		case 3:
			if v, ok := val.(int64); ok {
				h.UserTimeout = v
			}
		case 4:
			if v, ok := val.(int64); ok {
				h.LibBuildTs = v
			}
		case 5:
			if v, ok := val.([]byte); ok {
				h.AppProtocol = string(v)
			}
		}
	}
	return h, nil
}

// ═══════════════════════════════════════════════════════════════
// Header PB (key-value pair)
//   field 1: key   (string)
//   field 2: value (string)
// ═══════════════════════════════════════════════════════════════

type PBHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func pbEncodeHeaderItem(k, v string) []byte {
	var buf []byte
	buf = pbEncodeString(buf, 1, k)
	buf = pbEncodeString(buf, 2, v)
	return buf
}

func pbDecodeHeaderItem(data []byte) *PBHeader {
	h := &PBHeader{}
	offset := 0
	for offset < len(data) {
		fn, wt, off, err := pbDecodeTag(data, offset)
		if err != nil {
			break
		}
		val, off, err := pbDecodeRawValue(data, off, wt)
		if err != nil {
			break
		}
		offset = off
		var s string
		if v, ok := val.([]byte); ok {
			s = string(v)
		}
		switch fn {
		case 1:
			h.Key = s
		case 2:
			h.Value = s
		}
	}
	return h
}

// ═══════════════════════════════════════════════════════════════
// V3Request PB (JS Ne / Ce.HTTPRequest L1669-1671)
//   field 1: method  (string)
//   field 2: header  (repeated)
//   field 3: body    (bytes)
//   field 4: callId  (string)
// ═══════════════════════════════════════════════════════════════

type V3RequestPB struct {
	Method string
	Header []PBHeader
	Body   []byte
	CallID string
}

func pbEncodeV3Request(req *V3RequestPB) []byte {
	var buf []byte
	buf = pbEncodeString(buf, 1, req.Method)
	for _, h := range req.Header {
		buf = pbEncodeMessage(buf, 2, pbEncodeHeaderItem(h.Key, h.Value))
	}
	buf = pbEncodeBytes(buf, 3, req.Body)
	buf = pbEncodeString(buf, 4, req.CallID)
	return buf
}

// ═══════════════════════════════════════════════════════════════
// V3Response PB (JS Re L1743-1745)
//   field 1: statusCode  (uint32)
//   field 2: header      (repeated)
//   field 3: bodyBuffer  (bytes)
//   field 4: bodyString  (string)
// ═══════════════════════════════════════════════════════════════

type V3ResponsePB struct {
	StatusCode uint32
	Header     []PBHeader
	BodyBuffer []byte
	BodyString string
}

func pbDecodeV3Response(data []byte) (*V3ResponsePB, error) {
	resp := &V3ResponsePB{}
	offset := 0
	for offset < len(data) {
		fn, wt, off, err := pbDecodeTag(data, offset)
		if err != nil {
			return resp, err
		}
		val, off, err := pbDecodeRawValue(data, off, wt)
		if err != nil {
			return resp, err
		}
		offset = off
		switch fn {
		case 1:
			if v, ok := val.(int64); ok {
				resp.StatusCode = uint32(v)
			}
		case 2:
			if v, ok := val.([]byte); ok {
				resp.Header = append(resp.Header, *pbDecodeHeaderItem(v))
			}
		case 3:
			if v, ok := val.([]byte); ok {
				resp.BodyBuffer = v
			}
		case 4:
			if v, ok := val.([]byte); ok {
				resp.BodyString = string(v)
			}
		}
	}
	return resp, nil
}

// -- Helpers --------------------------------------------------

func marshalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// V3RequestJSON is the JSON-mode request body.
type V3RequestJSON struct {
	Body   any        `json:"body"`
	CallID string     `json:"call_id"`
	Header []PBHeader `json:"header"`
	Method string     `json:"method"`
}

// V3ResponseJSON is the JSON-mode response body.
type V3ResponseJSON struct {
	StatusCode int        `json:"statusCode"`
	BodyString string     `json:"bodyString,omitempty"`
	BodyBuffer []byte     `json:"bodyBuffer,omitempty"`
	Header     []PBHeader `json:"header"`
}
