package wxapkg

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestZipDirAndCleanup(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "x"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "output.zip")
	if err := ZipDir(source, target); err != nil {
		t.Fatal(err)
	}
	r, err := zip.OpenReader(target)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	found := false
	emptyFound := false
	for _, entry := range r.File {
		if entry.Name == "empty/" {
			emptyFound = true
		}
		if entry.Name == "nested/x" {
			f, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(f)
			_ = f.Close()
			if err != nil || !bytes.Equal(b, []byte("hello")) {
				t.Fatal("bad zip content", err)
			}
			found = true
		}
	}
	if !found || !emptyFound {
		t.Fatal("missing file")
	}
	if err = ZipDir(source, target); err == nil {
		t.Fatal("overwrote output")
	}
	if err = ZipDir(source, filepath.Join(source, "self.zip")); err == nil {
		t.Fatal("included own output")
	}
	owned, err := TempUnpackDir()
	if err != nil {
		t.Fatal(err)
	}
	if err = CleanTempDir(owned); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("owned temp survives")
	}
	alien := filepath.Join(base, "wxapkg_unpack_not_owned")
	if err = os.Mkdir(alien, 0700); err != nil {
		t.Fatal(err)
	}
	if err = CleanTempDir(alien); err == nil {
		t.Fatal("accepted unowned temp")
	}
	if _, err = os.Stat(alien); err != nil {
		t.Fatal("deleted unowned temp")
	}
}
func TestSymlinkBoundaries(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	out := filepath.Join(base, "out")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(out, "linked")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	pkg, err := Unpack(fixture([]string{"linked/escape"}, [][]byte{[]byte("bad")}))
	if err != nil {
		t.Fatal(err)
	}
	if err = pkg.ExtractAll(out); err == nil {
		t.Fatal("followed symlink on extraction")
	}
	if err = ZipDir(out, filepath.Join(base, "symlink.zip")); err == nil {
		t.Fatal("archived symlink")
	}
	if _, err = os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatal("escaped destination")
	}
}
