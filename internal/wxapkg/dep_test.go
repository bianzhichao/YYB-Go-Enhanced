package wxapkg

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(req *http.Request, status int, body io.Reader) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(body), Header: make(http.Header), Request: req}
}
func TestDependenciesOffline(t *testing.T) {
	pkg, err := Unpack(fixture([]string{"a.js"}, [][]byte{[]byte(`require("./local");require("pkg");require('@scope/pkg/file');require("pkg")`)}))
	if err != nil {
		t.Fatal(err)
	}
	deps, err := ScanAllRequires(pkg)
	if err != nil || len(deps) != 2 {
		t.Fatalf("scan: %v %v", deps, err)
	}
	calls := 0
	fake := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "unpkg.com" {
			t.Fatal("unexpected URL", r.URL)
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("no deadline")
		}
		return response(r, 200, strings.NewReader("module.exports=1;")), nil
	})
	files, err := resolveDeps(context.Background(), deps, fake)
	if err != nil || len(files) != 2 || calls != 2 {
		t.Fatal("resolve", err)
	}
	if files[0].Path != "pkg/index.js" || files[1].Path != "@scope/pkg/file/index.js" {
		t.Fatal("paths", files)
	}
	for _, spec := range []string{"../x", "pkg/../../x", "//localhost/x", "https://localhost/x", "pkg%2f..", "pkg?x=1", "pkg#x", `pkg\x`, "@scope", "pkg/CON"} {
		calls = 0
		if _, err = resolveDeps(context.Background(), []string{"ok", spec}, fake); err == nil || calls != 0 {
			t.Fatalf("unsafe spec %s: calls=%d err=%v", spec, calls, err)
		}
	}
	if _, err = resolveDeps(context.Background(), make([]string, MaxDependencies+1), fake); err == nil {
		t.Fatal("accepted excessive list")
	}
	if _, err = resolveDeps(context.Background(), []string{"pkg", "PKG"}, fake); err == nil {
		t.Fatal("accepted colliding archive paths")
	}
	pkg.Files[0].Offset = 0
	if _, err = ScanAllRequires(pkg); err == nil {
		t.Fatal("scan silently skipped invalid file")
	}
}
func TestDependencyFailures(t *testing.T) {
	tests := map[string]roundTripFunc{
		"HTTP":  func(r *http.Request) (*http.Response, error) { return response(r, 404, strings.NewReader("no")), nil },
		"empty": func(r *http.Request) (*http.Response, error) { return response(r, 200, strings.NewReader("")), nil },
		"oversize": func(r *http.Request) (*http.Response, error) {
			return response(r, 200, io.LimitReader(repeatReader{}, MaxDependencyBytes+1)), nil
		},
		"transport": func(r *http.Request) (*http.Response, error) { return nil, errors.New("offline") },
		"read":      func(r *http.Request) (*http.Response, error) { return response(r, 200, errorReader{}), nil },
		"close": func(r *http.Request) (*http.Response, error) {
			v := response(r, 200, strings.NewReader("x"))
			v.Body = closeErrorBody{Reader: strings.NewReader("x")}
			return v, nil
		},
	}
	for name, fake := range tests {
		t.Run(name, func(t *testing.T) {
			files, err := resolveDeps(context.Background(), []string{"pkg"}, fake)
			if err == nil || files != nil {
				t.Fatal("failure presented as success", err)
			}
		})
	}
	calls := 0
	fake := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("second failed")
		}
		return response(r, 200, strings.NewReader("x")), nil
	})
	files, err := resolveDeps(context.Background(), []string{"a", "b"}, fake)
	if err == nil || files != nil {
		t.Fatal("partial success returned")
	}
	fake = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(r, 200, io.LimitReader(repeatReader{}, MaxDependencyBytes)), nil
	})
	if _, err = resolveDeps(context.Background(), []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, fake); err == nil {
		t.Fatal("total limit ignored")
	}
}
func TestDependencyRedirects(t *testing.T) {
	for _, location := range []string{"http://unpkg.com/pkg", "https://127.0.0.1/pkg", "https://evil.example/pkg", "https://unpkg.com:443/pkg", "https://user@unpkg.com/pkg", "https://unpkg.com/pkg?x=1"} {
		calls := 0
		fake := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			v := response(r, 302, strings.NewReader(""))
			v.Header.Set("Location", location)
			return v, nil
		})
		if _, err := resolveDeps(context.Background(), []string{"pkg"}, fake); err == nil || calls != 1 {
			t.Fatalf("redirect escaped: %s calls=%d err=%v", location, calls, err)
		}
	}
	calls := 0
	fake := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			v := response(r, 302, strings.NewReader(""))
			v.Header.Set("Location", "https://unpkg.com/pkg@1.0.0/index.js")
			return v, nil
		}
		return response(r, 200, strings.NewReader("ok")), nil
	})
	if _, err := resolveDeps(context.Background(), []string{"pkg"}, fake); err != nil || calls != 2 {
		t.Fatal("valid redirect failed", err)
	}
	fake = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		v := response(r, 302, strings.NewReader(""))
		v.Header.Set("Location", "https://unpkg.com/pkg")
		return v, nil
	})
	if _, err := resolveDeps(context.Background(), []string{"pkg"}, fake); err == nil {
		t.Fatal("redirect loop accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake = roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })
	if _, err := resolveDeps(ctx, []string{"pkg"}, fake); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

type repeatReader struct{}

func (repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type closeErrorBody struct{ io.Reader }

func (closeErrorBody) Close() error { return errors.New("close failed") }

func TestDependencyDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	fake := roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	if _, err := resolveDeps(ctx, []string{"pkg"}, fake); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}
