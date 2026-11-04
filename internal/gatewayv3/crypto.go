package gatewayv3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// ═══════════════════════════════════════════════════════════════
// AES-256-CBC + PKCS7 (gatewayV3.js:1354: this.mode = "CBC")
// ═══════════════════════════════════════════════════════════════

// aesEncrypt performs AES-256-CBC encryption with PKCS7 padding.
// Returns (iv, ciphertext).
func aesEncrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, AESBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	padded := pkcs7Pad(plaintext, AESBlockSize)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return iv, ciphertext, nil
}

// aesDecrypt performs AES-256-CBC decryption with PKCS7 unpadding.
func aesDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != AESBlockSize || len(ciphertext) == 0 || len(ciphertext)%AESBlockSize != 0 {
		return nil, newGatewayError("invalid CBC block length", -1)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(padded, ciphertext)

	return pkcs7Unpad(padded, AESBlockSize)
}

// aesDecryptFromWire decrypts data in wire format: [16B IV][ciphertext].
func aesDecryptFromWire(key, wireData []byte) ([]byte, error) {
	if len(wireData) < AESBlockSize {
		return nil, newGatewayError("wire data too short for IV", -1)
	}
	iv := wireData[:AESBlockSize]
	ct := wireData[AESBlockSize:]
	return aesDecrypt(key, iv, ct)
}

// pkcs7Pad adds PKCS7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

// pkcs7Unpad removes and validates PKCS7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, newGatewayError("invalid padded length", -1)
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, newGatewayError("invalid pkcs7 padding", -1)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, newGatewayError("invalid pkcs7 padding bytes", -1)
		}
	}
	return data[:len(data)-padLen], nil
}
