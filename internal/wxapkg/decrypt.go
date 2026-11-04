package wxapkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"regexp"
)

var appIDPattern = regexp.MustCompile(`^wx[0-9a-fA-F]{16}$`)

// DecryptWxapkg decodes a V1MMWX wrapper. It does not download packages.
// A structural validation failure (including a wrong AppID) returns no plaintext.
func DecryptWxapkg(wxid string, data []byte) ([]byte, error) {
	const headLen = 6
	const blockLen = 1024
	if !appIDPattern.MatchString(wxid) {
		return nil, fmt.Errorf("invalid AppID")
	}
	if len(data) < headLen+blockLen || len(data) > MaxPackageBytes+7 {
		return nil, fmt.Errorf("invalid encrypted package length")
	}
	if !IsEncrypted(data) {
		return nil, fmt.Errorf("missing V1MMWX encryption header")
	}
	key := pbkdf2.Key([]byte(wxid), []byte("saltiest"), 1000, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, blockLen)
	cipher.NewCBCDecrypter(block, []byte("the iv: 16 bytes")).CryptBlocks(plain, data[headLen:headLen+blockLen])
	plain = plain[:blockLen-1]
	for _, b := range data[headLen+blockLen:] {
		plain = append(plain, b^wxid[len(wxid)-2])
	}
	if _, err := Unpack(plain); err != nil {
		return nil, fmt.Errorf("decrypted package invalid: %w", err)
	}
	return plain, nil
}
func IsEncrypted(data []byte) bool { return bytes.HasPrefix(data, []byte("V1MMWX")) }
