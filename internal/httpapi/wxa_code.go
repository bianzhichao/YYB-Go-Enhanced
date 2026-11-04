package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/wxapkg"
)

const maxWxaExportBytes = 128 << 20
const maxWxaModules = 32

type wxaCodeModule struct{ name, url string }
type wxaCodePackage struct {
	name string
	pkg  *wxapkg.WxApkg
}

func wxaCodeURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Host != u.Hostname() {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range []string{"weixin.qq.com", "servicewechat.com", "qpic.cn"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	switch host {
	case "dldir1.qq.com", "dldir1v6.qq.com", "wxapp.tc.qq.com", "wxappds.tc.qq.com":
		return true
	}
	return false
}
func wxaExportPath(name string) (string, error) {
	if err := wxapkg.ValidateArchivePath(name); err != nil {
		return "", fmt.Errorf("invalid export path: %w", err)
	}
	return name, nil
}
func wxaCodeVersionModules(result map[string]any) ([]string, map[string]any, error) {
	var kvs []map[string]any
	switch raw := result["keyValues"].(type) {
	case []map[string]any:
		kvs = raw
	case []any:
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				kvs = append(kvs, m)
			}
		}
	}
	var version map[string]any
	for _, kv := range kvs {
		if kv["key"] == "WxaAppVersionInfo" {
			text, _ := kv["value"].(string)
			if json.Unmarshal([]byte(text), &version) != nil {
				return nil, nil, fmt.Errorf("invalid WxaAppVersionInfo JSON")
			}
			break
		}
	}
	if version == nil {
		return nil, nil, fmt.Errorf("WxaAppVersionInfo missing")
	}
	var number int64
	switch n := version["AppVersion"].(type) {
	case float64:
		if math.Trunc(n) != n || n < 0 || n > math.MaxInt32 {
			return nil, nil, fmt.Errorf("invalid AppVersion")
		}
		number = int64(n)
	case string:
		var err error
		number, err = strconv.ParseInt(n, 10, 32)
		if err != nil || number < 0 {
			return nil, nil, fmt.Errorf("invalid AppVersion")
		}
	default:
		return nil, nil, fmt.Errorf("AppVersion missing")
	}
	first := func(keys ...string) string {
		for _, key := range keys {
			if s, ok := version[key].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	md5 := first("VersionMD5", "version_md5", "versionMd5")
	main := first("EntranceModule", "module_name", "moduleName")
	list, _ := version["module_list"].([]any)
	if main == "" && len(list) > 0 {
		if item, ok := list[0].(map[string]any); ok {
			main, _ = item["name"].(string)
		}
	}
	names := []string{main}
	seen := map[string]bool{main: true}
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			if name, ok := m["name"].(string); ok && name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	if len(names) > maxWxaModules {
		return nil, nil, fmt.Errorf("too many modules")
	}
	for _, name := range names {
		if name != "" {
			if _, err := wxaExportPath(name); err != nil {
				return nil, nil, err
			}
		}
	}
	return names, map[string]any{"version": float64(number), "versionMd5": md5}, nil
}
func downloadWxaCode(ctx context.Context, client *http.Client, rawURL, appID string) (*wxapkg.WxApkg, int, error) {
	if !wxaCodeURLAllowed(rawURL) {
		return nil, 0, fmt.Errorf("CDN URL is not allowed")
	}
	// Clone the client so every caller, including tests, has redirects disabled.
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid CDN request")
	}
	response, err := bounded.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("CDN request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, 0, fmt.Errorf("CDN HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, wxapkg.MaxPackageBytes+8))
	if err != nil || len(data) > wxapkg.MaxPackageBytes+7 {
		return nil, 0, fmt.Errorf("CDN package unreadable or oversized")
	}
	size := len(data)
	if wxapkg.IsEncrypted(data) {
		data, err = wxapkg.DecryptWxapkg(appID, data)
		if err != nil {
			return nil, 0, fmt.Errorf("package decryption failed")
		}
	}
	pkg, err := wxapkg.Unpack(data)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid wxapkg: %w", err)
	}
	return pkg, size, nil
}

func mergeWxaCode(ctx context.Context, packages []wxaCodePackage, resolve func(context.Context, []string) ([]wxapkg.DepFile, error)) ([]byte, error) {
	if len(packages) == 0 || len(packages) > maxWxaModules {
		return nil, fmt.Errorf("invalid module count")
	}
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	names := map[string]bool{}
	total, count := 0, 0
	add := func(name string, data []byte) error {
		if _, err := wxaExportPath(name); err != nil {
			return err
		}
		key := strings.ToLower(name)
		if names[key] {
			return fmt.Errorf("duplicate module export path")
		}
		for old := range names {
			if strings.HasPrefix(old, key+"/") || strings.HasPrefix(key, old+"/") {
				return fmt.Errorf("module file/directory collision")
			}
		}
		total += len(data)
		count++
		if total > maxWxaExportBytes || count > wxapkg.MaxFiles {
			return fmt.Errorf("export resource limit exceeded")
		}
		names[key] = true
		file, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			return err
		}
		_, err = file.Write(data)
		return err
	}
	deps := map[string]bool{}
	for i, module := range packages {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if module.pkg == nil {
			return nil, fmt.Errorf("missing module package")
		}
		prefix := ""
		if i > 0 {
			if _, err := wxaExportPath(module.name); err != nil {
				return nil, err
			}
			prefix = module.name + "/"
		}
		for _, file := range module.pkg.FileList() {
			raw, err := module.pkg.ExtractFile(file.Name)
			if err != nil {
				return nil, err
			}
			data, err := wxapkg.BeautifyFile(file.Name, raw)
			if err != nil {
				return nil, err
			}
			if err := add(prefix+strings.TrimPrefix(file.Name, "/"), data); err != nil {
				return nil, err
			}
		}
		if resolve != nil {
			specs, err := wxapkg.ScanAllRequires(module.pkg)
			if err != nil {
				return nil, err
			}
			for _, spec := range specs {
				deps[spec] = true
			}
		}
	}
	if resolve != nil && len(deps) > 0 {
		list := make([]string, 0, len(deps))
		for dep := range deps {
			list = append(list, dep)
		}
		sort.Strings(list)
		files, err := resolve(ctx, list)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if err := add(file.Path, file.Data); err != nil {
				return nil, err
			}
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("empty module export")
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *App) handleGetWxaCode(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getWxaCode") || !a.authorizeProtocol(w, r) {
		return
	}
	var body struct {
		Ref         string         `json:"ref"`
		OpenID      string         `json:"openid"`
		AppID       string         `json:"appid"`
		AppIDAlt    string         `json:"app_id"`
		DownloadURL string         `json:"downloadUrl"`
		Payload     map[string]any `json:"payload"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	body.Ref = runtimeFirstNonEmpty(body.Ref, body.OpenID)
	body.AppID = runtimeFirstNonEmpty(body.AppIDAlt, body.AppID)
	if !runtimeAppIDValid(body.AppID) {
		writeError(w, 400, "a valid app_id is required")
		return
	}
	if body.DownloadURL != "" && !wxaCodeURLAllowed(body.DownloadURL) {
		writeError(w, 400, "CDN URL is not allowed")
		return
	}
	if err := protocol.ValidateWxaAttrSync(body.AppID, body.Payload); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	entries := []wxaCodeModule{{url: body.DownloadURL}}
	auto := body.DownloadURL == ""
	if auto {
		attrs, err := a.invokeWXApp(ctx, acc, body.AppID, body.Payload, a.invokeWxaAttrSync)
		if err != nil {
			writeProtocolCallError(w, err)
			return
		}
		modules, payload, err := wxaCodeVersionModules(attrs)
		if err != nil {
			writeError(w, 502, err.Error())
			return
		}
		entries = nil
		for _, name := range modules {
			payload["moduleName"] = name
			result, err := a.invokeWXApp(ctx, acc, body.AppID, payload, a.invokeGetWxaCDNDownloadUrl)
			if err != nil {
				writeProtocolCallError(w, err)
				return
			}
			downloadURL, _ := result["downloadUrl"].(string)
			if !wxaCodeURLAllowed(downloadURL) {
				writeError(w, 502, "upstream returned an unsupported CDN URL")
				return
			}
			entries = append(entries, wxaCodeModule{name, downloadURL})
		}
	}
	proxyValue, _, err := a.resolveWXAppProxy(ctx, acc.ID)
	if err != nil {
		writeError(w, 502, "CDN proxy lookup failed")
		return
	}
	transport, err := protocol.NewHTTPTransport(proxyValue, false)
	if err != nil {
		writeError(w, 502, "CDN proxy setup failed")
		return
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	packages := make([]wxaCodePackage, 0, len(entries))
	total := 0
	for _, entry := range entries {
		pkg, size, err := downloadWxaCode(ctx, client, entry.url, body.AppID)
		if err != nil {
			writeError(w, 502, err.Error())
			return
		}
		total += size
		if total > maxWxaExportBytes {
			writeError(w, 502, "module download limit exceeded")
			return
		}
		packages = append(packages, wxaCodePackage{entry.name, pkg})
	}
	var resolve func(context.Context, []string) ([]wxapkg.DepFile, error)
	if auto {
		resolve = wxapkg.ResolveDepsContext
	}
	archive, err := mergeWxaCode(ctx, packages, resolve)
	if err != nil {
		writeError(w, 502, "module export failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="wxapkg.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	_, _ = w.Write(archive)
}
