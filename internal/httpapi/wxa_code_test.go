package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yyb_go/internal/wxapkg"
)

func wxaCodeFixture(names []string, contents [][]byte) []byte {
	index := new(bytes.Buffer)
	_ = binary.Write(index, binary.BigEndian, uint32(len(names)))
	size := 4
	for _, name := range names {
		size += 12 + len(name)
	}
	offset := uint32(14 + size)
	var body []byte
	for i, name := range names {
		_ = binary.Write(index, binary.BigEndian, uint32(len(name)))
		index.WriteString(name)
		_ = binary.Write(index, binary.BigEndian, offset)
		_ = binary.Write(index, binary.BigEndian, uint32(len(contents[i])))
		offset += uint32(len(contents[i]))
		body = append(body, contents[i]...)
	}
	data := make([]byte, 14)
	data[0] = 0xbe
	data[13] = 0xed
	binary.BigEndian.PutUint32(data[5:9], uint32(index.Len()))
	binary.BigEndian.PutUint32(data[9:13], uint32(len(body)))
	return append(append(data, index.Bytes()...), body...)
}
func wxaTestPackage(t *testing.T, names []string, contents [][]byte) *wxapkg.WxApkg {
	t.Helper()
	pkg, err := wxapkg.Unpack(wxaCodeFixture(names, contents))
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}
func TestWxaCodeDownloadBoundaries(t *testing.T) {
	for _, raw := range []string{"http://dldir1.qq.com/pkg", "https://127.0.0.1/pkg", "https://dldir1.qq.com.evil.invalid/pkg", "https://evilqpic.cn/pkg", "https://user@dldir1.qq.com/pkg", "https://dldir1.qq.com:443/pkg"} {
		if wxaCodeURLAllowed(raw) {
			t.Fatalf("accepted %s", raw)
		}
	}
	data := wxaCodeFixture([]string{"app.json"}, [][]byte{[]byte(`{"a":1}`)})
	calls := 0
	client := &http.Client{Transport: runtimeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
	})}
	pkg, size, err := downloadWxaCode(context.Background(), client, "https://dldir1.qq.com/pkg", "wx3723729dc4ac916c")
	if err != nil || pkg == nil || size != len(data) || calls != 1 {
		t.Fatalf("download %v %d %v", pkg, size, err)
	}
	_, _, err = downloadWxaCode(context.Background(), client, "https://localhost/pkg", "wx3723729dc4ac916c")
	if err == nil || calls != 1 {
		t.Fatal("disallowed host reached transport")
	}
	for _, status := range []int{302, 404} {
		client.Transport = runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://localhost/secret"}}}, nil
		})
		before := calls
		if _, _, err := downloadWxaCode(context.Background(), client, "https://dldir1.qq.com/pkg", "wx3723729dc4ac916c"); err == nil || calls != before+1 {
			t.Fatal("redirect or failed download accepted")
		}
	}
	client.Transport = runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("secret signed URL") })
	if _, _, err := downloadWxaCode(context.Background(), client, "https://dldir1.qq.com/pkg?token=secret", "wx3723729dc4ac916c"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("download error exposed request")
	}
}
func TestWxaCodeMergeAndDependencyErrors(t *testing.T) {
	main := wxaTestPackage(t, []string{"app.js"}, [][]byte{[]byte(`const a = require("test-lib");`)})
	sub := wxaTestPackage(t, []string{"data.txt"}, [][]byte{[]byte("child")})
	resolves := 0
	resolver := func(_ context.Context, deps []string) ([]wxapkg.DepFile, error) {
		resolves++
		if len(deps) != 1 || deps[0] != "test-lib" {
			t.Fatal(deps)
		}
		return []wxapkg.DepFile{{Path: "test-lib/index.js", Data: []byte("module.exports = {};")}}, nil
	}
	raw, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"main", main}, {"sub", sub}}, resolver)
	if err != nil || resolves != 1 {
		t.Fatalf("merge %v", err)
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, file := range archive.File {
		names[file.Name] = true
	}
	for _, name := range []string{"app.js", "sub/data.txt", "test-lib/index.js"} {
		if !names[name] {
			t.Fatal(names)
		}
	}
	collision := wxaTestPackage(t, []string{"sub/data.txt"}, [][]byte{[]byte("main file")})
	if _, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"", collision}, {"sub", sub}}, nil); err == nil {
		t.Fatal("duplicate merged path accepted")
	}
	for _, name := range []string{"../escape", "/root", "a\\b", "C:bad"} {
		if _, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"", main}, {name, sub}}, nil); err == nil {
			t.Fatal("unsafe module name accepted")
		}
	}
	if _, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"", main}}, func(context.Context, []string) ([]wxapkg.DepFile, error) {
		return nil, fmt.Errorf("dependency unavailable")
	}); err == nil {
		t.Fatal("dependency failure hidden")
	}
}
func TestWxaCodeVersionAndHandlerValidation(t *testing.T) {
	result := map[string]any{"keyValues": []map[string]any{{"key": "WxaAppVersionInfo", "value": `{"AppVersion":"12","VersionMD5":"hash","EntranceModule":"main","module_list":[{"name":"main"},{"name":"sub"},{"name":"sub"}]}`}}}
	names, payload, err := wxaCodeVersionModules(result)
	if err != nil || len(names) != 2 || names[1] != "sub" || payload["version"] != float64(12) {
		t.Fatalf("version %v %v %v", names, payload, err)
	}
	result["keyValues"] = []map[string]any{{"key": "WxaAppVersionInfo", "value": `{"AppVersion":1.5}`}}
	if _, _, err := wxaCodeVersionModules(result); err == nil {
		t.Fatal("fractional version accepted")
	}
	app, err := NewApp(Config{ResourceRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/wxapp/getWxaCode", strings.NewReader(`{"ref":"missing","appid":"wx3723729dc4ac916c","downloadUrl":"https://127.0.0.1/pkg"}`))
	app.handleGetWxaCode(w, r)
	if w.Code != 400 {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
}

func TestWxaCodeRejectsReservedModuleAndDependencyPaths(t *testing.T) {
	main := wxaTestPackage(t, []string{"app.js"}, [][]byte{[]byte(`require("test-lib");`)})
	sub := wxaTestPackage(t, []string{"data.txt"}, [][]byte{[]byte("child")})
	for _, name := range []string{"CON", "AUX", "COM1", "con.txt", "aux.json", "com1.js", "parent/LPT9", "COM¹"} {
		t.Run(name, func(t *testing.T) {
			if _, err := wxaExportPath(name + "/data.txt"); err == nil {
				t.Fatal("reserved final path accepted")
			}
			if _, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"", main}, {name, sub}}, nil); err == nil {
				t.Fatal("reserved module prefix accepted")
			}
			if _, err := mergeWxaCode(context.Background(), []wxaCodePackage{{"", main}}, func(context.Context, []string) ([]wxapkg.DepFile, error) {
				return []wxapkg.DepFile{{Path: name + "/index.js", Data: []byte("dependency")}}, nil
			}); err == nil {
				t.Fatal("reserved merged dependency path accepted")
			}
		})
	}
	if _, err := wxaExportPath("consumer/com10/data.txt"); err != nil {
		t.Fatalf("ordinary path rejected: %v", err)
	}
}
