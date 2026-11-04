package wxapkg

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	MaxPackageBytes = 64 << 20
	MaxFiles        = 10000
	MaxPathBytes    = 4096
	wxapkgMagic1    = 0xBE
	wxapkgMagic2    = 0xED
)

type FileEntry struct {
	Name         string
	Offset, Size uint32
}
type WxApkg struct {
	Files     []FileEntry
	Data      []byte
	BodyStart uint32
}

// archiveName accepts the format's single leading slash, but never interprets
// an OS absolute path. Reject ambiguous Windows names on every platform.
func archiveName(name string) (string, error) {
	name = strings.TrimPrefix(name, "/")
	if name == "" || len(name) > MaxPathBytes || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:\x00") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part {
			return "", fmt.Errorf("unsafe archive path %q", name)
		}
		for _, c := range part {
			if c < 32 || strings.ContainsRune(`<>"|?*`, c) {
				return "", fmt.Errorf("unsafe archive path %q", name)
			}
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" || ((strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && len([]rune(stem)) == 4 && strings.ContainsRune("123456789¹²³", []rune(stem)[3])) {
			return "", fmt.Errorf("reserved archive path %q", name)
		}
	}
	return name, nil
}

// ValidateArchivePath applies the package's cross-platform path rules without
// accepting the wxapkg wire format's optional leading slash.
func ValidateArchivePath(name string) error {
	canonical, err := archiveName(name)
	if err != nil {
		return err
	}
	if canonical != name {
		return fmt.Errorf("noncanonical archive path %q", name)
	}
	return nil
}
func validateNames(files []FileEntry) error {
	if len(files) > MaxFiles {
		return fmt.Errorf("too many files: %d", len(files))
	}
	names := make(map[string]bool, len(files))
	for _, f := range files {
		name, err := archiveName(f.Name)
		if err != nil {
			return err
		}
		if name != f.Name {
			return fmt.Errorf("noncanonical file path %q", f.Name)
		}
		key := strings.ToLower(name)
		if names[key] {
			return fmt.Errorf("duplicate file path %q", name)
		}
		names[key] = true
	}
	for name := range names {
		for pos := strings.IndexByte(name, '/'); pos >= 0; {
			if names[name[:pos]] {
				return fmt.Errorf("file/directory conflict: %q", name)
			}
			next := strings.IndexByte(name[pos+1:], '/')
			if next < 0 {
				break
			}
			pos += next + 1
		}
	}
	return nil
}

func UnpackFile(path string) (*WxApkg, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPackageBytes+1))
	if err != nil {
		return nil, err
	}
	return Unpack(data)
}
func Unpack(data []byte) (*WxApkg, error) {
	if len(data) < 18 || len(data) > MaxPackageBytes {
		return nil, fmt.Errorf("invalid package length %d", len(data))
	}
	if data[0] != wxapkgMagic1 || data[13] != wxapkgMagic2 {
		return nil, fmt.Errorf("invalid wxapkg magic")
	}
	indexLen := uint64(binary.BigEndian.Uint32(data[5:9]))
	bodyLen := uint64(binary.BigEndian.Uint32(data[9:13]))
	end := uint64(14) + indexLen
	if indexLen < 4 || end+bodyLen != uint64(len(data)) {
		return nil, fmt.Errorf("index/body lengths do not match package")
	}
	files, err := parseIndex(data[14:end])
	if err != nil {
		return nil, err
	}
	w := &WxApkg{Files: files, Data: bytes.Clone(data[end:]), BodyStart: uint32(end)}
	if err := w.validate(); err != nil {
		return nil, err
	}
	return w, nil
}
func parseIndex(data []byte) ([]FileEntry, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("index too small")
	}
	count := uint64(binary.BigEndian.Uint32(data[:4]))
	if count > MaxFiles || count > uint64(len(data)-4)/13 {
		return nil, fmt.Errorf("invalid file count %d", count)
	}
	files := make([]FileEntry, 0, int(count))
	pos := uint64(4)
	for i := uint64(0); i < count; i++ {
		if pos+4 > uint64(len(data)) {
			return nil, fmt.Errorf("truncated file index")
		}
		n := uint64(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if n == 0 || n > MaxPathBytes || pos+n+8 > uint64(len(data)) {
			return nil, fmt.Errorf("invalid file name length")
		}
		name, err := archiveName(string(data[pos : pos+n]))
		if err != nil {
			return nil, err
		}
		pos += n
		files = append(files, FileEntry{name, binary.BigEndian.Uint32(data[pos : pos+4]), binary.BigEndian.Uint32(data[pos+4 : pos+8])})
		pos += 8
	}
	if pos != uint64(len(data)) {
		return nil, fmt.Errorf("trailing index bytes")
	}
	if err := validateNames(files); err != nil {
		return nil, err
	}
	return files, nil
}
func (w *WxApkg) validate() error {
	if w == nil {
		return fmt.Errorf("nil package")
	}
	if len(w.Data) > MaxPackageBytes {
		return fmt.Errorf("body too large")
	}
	if err := validateNames(w.Files); err != nil {
		return err
	}
	total := uint64(0)
	for _, f := range w.Files {
		if _, err := w.bodyOffset(f); err != nil {
			return err
		}
		total += uint64(f.Size)
		if total > MaxPackageBytes {
			return fmt.Errorf("expanded package too large")
		}
	}
	return nil
}
func (w *WxApkg) bodyOffset(f FileEntry) (uint32, error) {
	if w == nil || f.Offset < w.BodyStart {
		return 0, fmt.Errorf("file offset before body")
	}
	off := f.Offset - w.BodyStart
	if uint64(off)+uint64(f.Size) > uint64(len(w.Data)) {
		return 0, fmt.Errorf("file %q exceeds body bounds", f.Name)
	}
	return off, nil
}
func (w *WxApkg) BodyOffset(f FileEntry) (uint32, error) { return w.bodyOffset(f) }
func (w *WxApkg) FileList() []FileEntry                  { return append([]FileEntry(nil), w.Files...) }
func (w *WxApkg) FileNames() []string {
	names := make([]string, len(w.Files))
	for i, f := range w.Files {
		names[i] = f.Name
	}
	return names
}
func (w *WxApkg) ExtractFile(name string) ([]byte, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	for _, f := range w.Files {
		if f.Name == name {
			off, _ := w.bodyOffset(f)
			return bytes.Clone(w.Data[off : off+f.Size]), nil
		}
	}
	return nil, fmt.Errorf("file not found: %s", name)
}

// ExtractAll never overwrites existing files or follows existing symlinks.
// The destination must be private to the caller: Go 1.23 cannot make the
// Lstat/OpenFile sequence atomic against a concurrent directory replacement.
func (w *WxApkg) ExtractAll(dir string) error {
	if err := w.validate(); err != nil {
		return err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err = mkdirNoLinks(root); err != nil {
		return err
	}
	for _, f := range w.Files {
		out := filepath.Join(root, filepath.FromSlash(f.Name))
		if err = mkdirNoLinks(filepath.Dir(out)); err != nil {
			return err
		}
		file, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		off, _ := w.bodyOffset(f)
		_, writeErr := file.Write(w.Data[off : off+f.Size])
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
func mkdirNoLinks(dir string) error {
	info, err := os.Lstat(dir)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("not a real directory: %s", dir)
		}
		parent := filepath.Dir(dir)
		if parent != dir {
			return mkdirNoLinks(parent)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return err
	}
	if err = mkdirNoLinks(parent); err != nil {
		return err
	}
	return os.Mkdir(dir, 0700)
}
func (w *WxApkg) HeaderInfo() map[string]any {
	info := map[string]any{"fileCount": len(w.Files), "bodyLen": len(w.Data)}
	if len(w.Files) > 0 {
		for key, f := range map[string]FileEntry{"firstFile": w.Files[0], "lastFile": w.Files[len(w.Files)-1]} {
			info[key] = map[string]any{"name": f.Name, "offset": f.Offset, "size": f.Size}
		}
	}
	return info
}
func (w *WxApkg) ToMap() map[string]any {
	files := make([]map[string]any, 0, len(w.Files))
	total := uint64(0)
	for _, f := range w.Files {
		off := f.Offset
		if off >= w.BodyStart {
			off -= w.BodyStart
		}
		files = append(files, map[string]any{"name": f.Name, "offset": off, "size": f.Size})
		total += uint64(f.Size)
	}
	return map[string]any{"fileCount": len(files), "totalSize": total, "bodyStart": w.BodyStart, "files": files}
}

// WriteTo implements io.WriterTo and reports both a partial count and any error.
func (w *WxApkg) WriteTo(writer io.Writer) (int64, error) {
	if err := w.validate(); err != nil {
		return 0, err
	}
	var total int64
	for _, f := range w.Files {
		off, _ := w.bodyOffset(f)
		n, err := writer.Write(w.Data[off : off+f.Size])
		total += int64(n)
		if err != nil {
			return total, err
		}
		if n != int(f.Size) {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (w *WxApkg) Zip() ([]byte, error)           { return w.zip(false) }
func (w *WxApkg) ZipBeautified() ([]byte, error) { return w.zip(true) }
func (w *WxApkg) zip(beautify bool) ([]byte, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	total := 0
	for _, f := range w.Files {
		off, _ := w.bodyOffset(f)
		data := w.Data[off : off+f.Size]
		if beautify {
			var err error
			data, err = BeautifyFile(f.Name, data)
			if err != nil {
				return nil, fmt.Errorf("beautify %s: %w", f.Name, err)
			}
		}
		total += len(data)
		if total > MaxPackageBytes {
			return nil, fmt.Errorf("formatted package too large")
		}
		entry, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err = entry.Write(data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
