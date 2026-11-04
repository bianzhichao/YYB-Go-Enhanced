package wxapkg

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ZipDir excludes links/special files, refuses existing outputs and never puts
// the output inside the input tree. Source and destination must be caller-owned
// and not mutated concurrently. A failed operation removes its partial output.
func ZipDir(sourceDir, targetZip string) (err error) {
	source, err := filepath.Abs(sourceDir)
	if err != nil {
		return err
	}
	if err = checkRealDirectory(source); err != nil {
		return err
	}
	target, err := filepath.Abs(targetZip)
	if err != nil {
		return err
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return err
	}
	resolvedTarget := filepath.Join(resolvedParent, filepath.Base(target))
	rel, err := filepath.Rel(resolvedSource, resolvedTarget)
	if err != nil {
		return err
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("ZIP output must be outside source directory")
	}
	var paths []string
	var directories []string
	seenPaths := map[string]bool{}
	var names []FileEntry
	total := int64(0)
	err = filepath.WalkDir(source, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in source: %s", p)
		}
		if p == source {
			return nil
		}
		rawName, relErr := filepath.Rel(source, p)
		if relErr != nil {
			return relErr
		}
		cleanName, nameErr := archiveName(filepath.ToSlash(rawName))
		if nameErr != nil {
			return nameErr
		}
		folded := strings.ToLower(cleanName)
		if seenPaths[folded] {
			return fmt.Errorf("colliding directory entry: %s", cleanName)
		}
		seenPaths[folded] = true
		if len(seenPaths) > MaxFiles {
			return fmt.Errorf("too many directory entries")
		}
		if d.IsDir() {
			directories = append(directories, cleanName+"/")
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("nonregular file: %s", p)
		}
		total += info.Size()
		if total > MaxPackageBytes || len(names) >= MaxFiles {
			return fmt.Errorf("directory exceeds archive limits")
		}
		paths = append(paths, p)
		names = append(names, FileEntry{Name: cleanName})
		return nil
	})
	if err != nil {
		return err
	}
	if err = validateNames(names); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := output.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(target)
		}
	}()
	zw := zip.NewWriter(output)
	for _, dir := range directories {
		if _, createErr := zw.Create(dir); createErr != nil {
			return createErr
		}
	}
	remaining := int64(MaxPackageBytes)
	for i, p := range paths {
		info, statErr := os.Lstat(p)
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source changed: %s", p)
		}
		f, openErr := os.Open(p)
		if openErr != nil {
			return openErr
		}
		entry, createErr := zw.CreateHeader(&zip.FileHeader{Name: names[i].Name, Method: zip.Deflate})
		if createErr != nil {
			_ = f.Close()
			return createErr
		}
		n, copyErr := io.Copy(entry, io.LimitReader(f, remaining+1))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		remaining -= n
		if remaining < 0 {
			return fmt.Errorf("directory grew beyond byte limit")
		}
	}
	return zw.Close()
}
func checkRealDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("not a real directory: %s", dir)
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		return checkRealDirectory(parent)
	}
	return nil
}
func ZipSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
func FormatSize(size int64) string {
	switch {
	case size < 0:
		return "?"
	case size >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(size)/(1<<30))
	case size >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

var ownedTempDirs sync.Map

func TempUnpackDir() (string, error) {
	dir, err := os.MkdirTemp("", "wxapkg_unpack_")
	if err == nil {
		ownedTempDirs.Store(dir, true)
	}
	return dir, err
}

// CleanTempDir only removes a directory created by TempUnpackDir in this process.
func CleanTempDir(dir string) error {
	if dir == "" {
		return nil
	}
	if _, ok := ownedTempDirs.Load(dir); !ok {
		return fmt.Errorf("directory is not owned by wxapkg")
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	ownedTempDirs.Delete(dir)
	return nil
}
