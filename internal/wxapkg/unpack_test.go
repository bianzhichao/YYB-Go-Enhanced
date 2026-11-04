package wxapkg

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(names []string, contents [][]byte) []byte {
	index := new(bytes.Buffer)
	_ = binary.Write(index, binary.BigEndian, uint32(len(names)))
	indexLen := 4
	for _, n := range names {
		indexLen += 12 + len(n)
	}
	off := uint32(14 + indexLen)
	var body []byte
	for i, n := range names {
		_ = binary.Write(index, binary.BigEndian, uint32(len(n)))
		index.WriteString(n)
		_ = binary.Write(index, binary.BigEndian, off)
		_ = binary.Write(index, binary.BigEndian, uint32(len(contents[i])))
		off += uint32(len(contents[i]))
		body = append(body, contents[i]...)
	}
	data := make([]byte, 14)
	data[0] = 0xBE
	data[13] = 0xED
	binary.BigEndian.PutUint32(data[5:9], uint32(index.Len()))
	binary.BigEndian.PutUint32(data[9:13], uint32(len(body)))
	return append(append(data, index.Bytes()...), body...)
}
func TestUnpackAndZipRoundTrip(t *testing.T) {
	raw := fixture([]string{"/app.json", "pages/a.js", "empty"}, [][]byte{[]byte(`{"a":1}`), []byte(`var x=1;`), nil})
	pkg, err := Unpack(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] = 'x' // Package owns its body; caller mutation must not change it.
	data, err := pkg.ExtractFile("pages/a.js")
	if err != nil || string(data) != "var x=1;" {
		t.Fatalf("extract: %q %v", data, err)
	}
	listing := pkg.FileList()
	listing[0].Name = "../bad"
	if pkg.Files[0].Name != "app.json" {
		t.Fatal("aliased file list")
	}
	for _, formatted := range []bool{false, true} {
		var archive []byte
		if formatted {
			archive, err = pkg.ZipBeautified()
		} else {
			archive, err = pkg.Zip()
		}
		if err != nil {
			t.Fatal(err)
		}
		reader, e := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if e != nil {
			t.Fatal(e)
		}
		if len(reader.File) != 3 {
			t.Fatal("wrong file count")
		}
		for _, file := range reader.File {
			r, e := file.Open()
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(r)
			_ = r.Close()
			if e != nil {
				t.Fatal(e)
			}
			if !formatted {
				expected, _ := pkg.ExtractFile(file.Name)
				if !bytes.Equal(expected, b) {
					t.Fatal("ZIP changed bytes")
				}
			}
		}
	}
	dir := filepath.Join(t.TempDir(), "out")
	if err = pkg.ExtractAll(dir); err != nil {
		t.Fatal(err)
	}
	if err = pkg.ExtractAll(dir); err == nil {
		t.Fatal("overwrote existing files")
	}
	b, err := os.ReadFile(filepath.Join(dir, "app.json"))
	if err != nil || string(b) != `{"a":1}` {
		t.Fatal("bad extracted bytes", err)
	}
}
func TestUnpackRejectsMalformed(t *testing.T) {
	valid := fixture([]string{"a"}, [][]byte{[]byte("ok")})
	tests := map[string]func([]byte) []byte{
		"short":              func(b []byte) []byte { return b[:13] },
		"magic":              func(b []byte) []byte { b[0] = 0; return b },
		"index overflow":     func(b []byte) []byte { binary.BigEndian.PutUint32(b[5:9], math.MaxUint32); return b },
		"body mismatch":      func(b []byte) []byte { binary.BigEndian.PutUint32(b[9:13], 1); return b },
		"count overflow":     func(b []byte) []byte { binary.BigEndian.PutUint32(b[14:18], math.MaxUint32); return b },
		"truncated entries":  func(b []byte) []byte { binary.BigEndian.PutUint32(b[14:18], 2); return b },
		"name overflow":      func(b []byte) []byte { binary.BigEndian.PutUint32(b[18:22], math.MaxUint32); return b },
		"offset before body": func(b []byte) []byte { binary.BigEndian.PutUint32(b[23:27], 1); return b },
		"size overflow":      func(b []byte) []byte { binary.BigEndian.PutUint32(b[27:31], math.MaxUint32); return b },
		"offset overflow":    func(b []byte) []byte { binary.BigEndian.PutUint32(b[23:27], math.MaxUint32); return b },
		"extra bytes":        func(b []byte) []byte { return append(b, 0) },
		"trailing index":     func(b []byte) []byte { binary.BigEndian.PutUint32(b[14:18], 0); return b },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Unpack(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted corrupt package")
			}
		})
	}
}
func TestUnpackRejectsPathsAndCollisions(t *testing.T) {
	for _, names := range [][]string{{"../escape"}, {"/../escape"}, {"a/../../b"}, {"//host/file"}, {`C:\file`}, {`a\..\file`}, {"a:b"}, {"a\x00b"}, {"a/./b"}, {"a//b"}, {"a/"}, {"CON"}, {"aux.txt"}, {"a. "}, {"a?"}, {"a", "A"}, {"/a", "a"}, {"a", "a/b"}, {"a/b", "a"}} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			values := make([][]byte, len(names))
			for i := range values {
				values[i] = []byte("x")
			}
			if _, err := Unpack(fixture(names, values)); err == nil {
				t.Fatal("accepted unsafe paths")
			}
		})
	}
}
func TestRevalidationAndShortWrite(t *testing.T) {
	pkg, err := Unpack(fixture([]string{"a"}, [][]byte{[]byte("ok")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pkg.WriteTo(shortWriter{}); err != io.ErrShortWrite {
		t.Fatalf("short write: %v", err)
	}
	pkg.Files[0].Name = "../escape"
	if _, err = pkg.Zip(); err == nil {
		t.Fatal("zip accepted mutated entry")
	}
	if err = pkg.ExtractAll(t.TempDir()); err == nil {
		t.Fatal("extract accepted mutated entry")
	}
	pkg.Files[0].Name = "a"
	pkg.Files[0].Size = math.MaxUint32
	if _, err = pkg.BodyOffset(pkg.Files[0]); err == nil {
		t.Fatal("overflow accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func encryptedFixture(t *testing.T, appid string, plain []byte) []byte {
	t.Helper()
	if len(plain) < 1023 {
		t.Fatal("short fixture")
	}
	key := pbkdf2.Key([]byte(appid), []byte("saltiest"), 1000, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	head := append(bytes.Clone(plain[:1023]), 0)
	encrypted := make([]byte, 1024)
	cipher.NewCBCEncrypter(block, []byte("the iv: 16 bytes")).CryptBlocks(encrypted, head)
	out := append([]byte("V1MMWX"), encrypted...)
	for _, b := range plain[1023:] {
		out = append(out, b^appid[len(appid)-2])
	}
	return out
}
func TestDecryptRoundTripAndInvalidInput(t *testing.T) {
	appid := "wx1234567890abcdef"
	plain := fixture([]string{"data.bin"}, [][]byte{bytes.Repeat([]byte{0x12, 0x34, 0x56}, 512)})
	encoded := encryptedFixture(t, appid, plain)
	decoded, err := DecryptWxapkg(appid, encoded)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("decrypt round trip", err)
	}
	if !IsEncrypted(encoded) || IsEncrypted(plain) || IsEncrypted([]byte("garbage")) {
		t.Fatal("encryption detection")
	}
	for _, n := range []int{0, 5, 6, 14, 1029} {
		if _, err = DecryptWxapkg(appid, encoded[:n]); err == nil {
			t.Fatal("accepted short ciphertext", n)
		}
	}
	if _, err = DecryptWxapkg("wx0000000000000000", encoded); err == nil {
		t.Fatal("accepted wrong key")
	}
	if _, err = DecryptWxapkg("", encoded); err == nil {
		t.Fatal("accepted empty AppID")
	}
	bad := bytes.Clone(encoded)
	bad[0] = 'X'
	if _, err = DecryptWxapkg(appid, bad); err == nil {
		t.Fatal("accepted bad header")
	}
	// Exactly 1023 plaintext bytes (no XOR tail) is also a valid boundary.
	boundary := fixture([]string{"a"}, [][]byte{bytes.Repeat([]byte("x"), 992)})
	decoded, err = DecryptWxapkg(appid, encryptedFixture(t, appid, boundary))
	if err != nil || !bytes.Equal(decoded, boundary) {
		t.Fatal("boundary decryption", err)
	}
}
func TestBeautifyErrorsAndPreservation(t *testing.T) {
	for _, ext := range []string{"json", "js", "html", "wxml", "bin"} {
		input := []byte("<p>hi</p>")
		if ext == "json" {
			input = []byte(`{"a":1}`)
		}
		if ext == "js" {
			input = []byte(`var x=1;`)
		}
		out, err := BeautifyFile("a."+ext, input)
		if err != nil || len(out) == 0 {
			t.Fatal(ext, err)
		}
	}
	if _, err := BeautifyFile("bad.json", []byte("{")); err == nil {
		t.Fatal("invalid JSON hidden")
	}
	pkg, err := Unpack(fixture([]string{"bad.json"}, [][]byte{[]byte("{")}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pkg.ZipBeautified(); err == nil {
		t.Fatal("ZIP hid formatting failure")
	}
	large := bytes.Repeat([]byte("x"), maxBeautifyJsSize+1)
	out, err := BeautifyFile("a.js", large)
	if err != nil || !bytes.Equal(out, large) {
		t.Fatal("oversized JS modified")
	}
}
func FuzzUnpack(f *testing.F) {
	f.Add(fixture([]string{"a"}, [][]byte{[]byte("ok")}))
	f.Add([]byte("V1MMWX"))
	f.Fuzz(func(t *testing.T, b []byte) {
		pkg, err := Unpack(b)
		if err != nil {
			return
		}
		for _, entry := range pkg.FileList() {
			off, err := pkg.BodyOffset(entry)
			if err != nil || uint64(off)+uint64(entry.Size) > uint64(len(pkg.Data)) {
				t.Fatal("invalid accepted package")
			}
		}
	})
}

func TestPackageResourceLimits(t *testing.T) {
	names := make([]string, MaxFiles+1)
	contents := make([][]byte, len(names))
	for i := range names {
		names[i] = fmt.Sprintf("f%d", i)
	}
	if _, err := Unpack(fixture(names, contents)); err == nil {
		t.Fatal("excess file count accepted")
	}
	if _, err := Unpack(fixture([]string{strings.Repeat("a", MaxPathBytes+1)}, [][]byte{nil})); err == nil {
		t.Fatal("excess name length accepted")
	}
	pkg := &WxApkg{BodyStart: 14, Data: make([]byte, MaxPackageBytes/2+1), Files: []FileEntry{
		{Name: "a", Offset: 14, Size: MaxPackageBytes/2 + 1},
		{Name: "b", Offset: 14, Size: MaxPackageBytes/2 + 1},
	}}
	if _, err := pkg.Zip(); err == nil {
		t.Fatal("overlapping entries amplify past limit")
	}
}
