package wxapkg

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	MaxDependencies         = 128
	MaxDependencyBytes      = 2 << 20
	MaxDependencyTotalBytes = 16 << 20
)

var reRequire = regexp.MustCompile(`require\s*\(\s*["']([^"']+)["']\s*\)`)
var specChars = regexp.MustCompile(`^[A-Za-z0-9_@.+/-]+$`)

func dependencyPath(spec string) (string, error) {
	if !specChars.MatchString(spec) || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, ".") {
		return "", fmt.Errorf("unsafe dependency spec %q", spec)
	}
	if _, err := archiveName(spec); err != nil {
		return "", err
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") && (len(parts) < 2 || len(parts[0]) == 1) {
		return "", fmt.Errorf("invalid scoped dependency %q", spec)
	}
	return archiveName(spec + "/index.js")
}
func ScanRequires(data []byte) []string {
	matches := reRequire.FindAllSubmatch(data, -1)
	seen := map[string]bool{}
	var deps []string
	for _, m := range matches {
		spec := string(m[1])
		if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || seen[spec] {
			continue
		}
		seen[spec] = true
		deps = append(deps, spec)
	}
	return deps
}
func ScanAllRequires(pkg *WxApkg) ([]string, error) {
	if err := pkg.validate(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var deps []string
	for _, f := range pkg.Files {
		if !strings.HasSuffix(f.Name, ".js") {
			continue
		}
		off, _ := pkg.bodyOffset(f)
		for _, spec := range ScanRequires(pkg.Data[off : off+f.Size]) {
			if seen[spec] {
				continue
			}
			if _, err := dependencyPath(spec); err != nil {
				return nil, err
			}
			seen[spec] = true
			deps = append(deps, spec)
			if len(deps) > MaxDependencies {
				return nil, fmt.Errorf("too many dependencies")
			}
		}
	}
	return deps, nil
}

type DepFile struct {
	Path string
	Data []byte
}

// ResolveDeps is opt-in network access; Unpack and Zip never fetch anything.
// Downloads are all-or-error, in input order, limited to HTTPS unpkg.com.
func ResolveDeps(deps []string) ([]DepFile, error) {
	return ResolveDepsContext(context.Background(), deps)
}
func ResolveDepsContext(ctx context.Context, deps []string) ([]DepFile, error) {
	return resolveDeps(ctx, deps, http.DefaultTransport)
}
func dependencyURLAllowed(u *url.URL) bool {
	return u.Scheme == "https" && u.Host == "unpkg.com" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func resolveDeps(ctx context.Context, deps []string, transport http.RoundTripper) ([]DepFile, error) {
	if len(deps) > MaxDependencies {
		return nil, fmt.Errorf("too many dependencies")
	}
	// Validate the entire list before the first request.
	names := make([]FileEntry, 0, len(deps))
	unique := make([]string, 0, len(deps))
	seen := map[string]bool{}
	for _, spec := range deps {
		p, err := dependencyPath(spec)
		if err != nil {
			return nil, err
		}
		if seen[spec] {
			continue
		}
		seen[spec] = true
		unique = append(unique, spec)
		names = append(names, FileEntry{Name: p})
	}
	if err := validateNames(names); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !dependencyURLAllowed(req.URL) {
			return fmt.Errorf("blocked dependency redirect")
		}
		return nil
	}}
	var files []DepFile
	total := 0
	for i, spec := range unique {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://unpkg.com/"+spec, nil)
		if err != nil {
			return nil, err
		}
		if !dependencyURLAllowed(req.URL) {
			return nil, fmt.Errorf("blocked dependency URL")
		}
		req.Header.Set("User-Agent", "wxapkg/2.0")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", spec, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxDependencyBytes+1))
		closeErr := resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: HTTP %d", spec, resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", spec, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", spec, closeErr)
		}
		if len(data) == 0 || len(data) > MaxDependencyBytes {
			return nil, fmt.Errorf("invalid dependency size: %s", spec)
		}
		total += len(data)
		if total > MaxDependencyTotalBytes {
			return nil, fmt.Errorf("dependencies exceed total byte limit")
		}
		files = append(files, DepFile{names[i].Name, data})
	}
	return files, nil
}
