package wxapkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/tidwall/pretty"
	"github.com/yosssi/gohtml"
	"path"
	"regexp"
	"strings"
)

const (
	maxBeautifyJsSize   = 512 * 1024
	maxBeautifyHtmlSize = 1024 * 1024
	maxBeautifyJsonSize = 2 * 1024 * 1024
)

var regScriptInHtml = regexp.MustCompile(`(?s) *<script\b[^>]*>(.*?)</script>`)

// BeautifyFile preserves binary and oversized files. Syntax/formatter failures
// are errors, not a successful prettified result. Callers must handle the error.
func BeautifyFile(name string, data []byte) (result []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			result = nil
			err = fmt.Errorf("formatter panic: %v", p)
		}
	}()
	result = data
	switch strings.ToLower(path.Ext(name)) {
	case ".json":
		if len(data) <= maxBeautifyJsonSize {
			if !json.Valid(data) {
				return nil, fmt.Errorf("invalid JSON")
			}
			result = pretty.Pretty(data)
		}
	case ".js":
		if len(data) <= maxBeautifyJsSize {
			result, err = prettyJavaScript(data)
		}
	case ".html", ".wxml":
		if len(data) <= maxBeautifyHtmlSize {
			result = gohtml.FormatBytes(bytes.TrimSpace(data))
			result = regScriptInHtml.ReplaceAllFunc(result, func(script []byte) []byte {
				if err != nil {
					return script
				}
				code := regScriptInHtml.FindSubmatch(script)[1]
				var formatted []byte
				formatted, err = prettyJavaScript(code)
				if err != nil {
					return script
				}
				return bytes.Replace(script, code, append(append([]byte("\n"), formatted...), '\n'), 1)
			})
		}
	}
	if err != nil {
		return nil, err
	}
	if len(result) > MaxPackageBytes {
		return nil, fmt.Errorf("formatted file too large")
	}
	return result, nil
}
func prettyJavaScript(data []byte) ([]byte, error) {
	code := string(bytes.TrimSpace(data))
	formatted, err := jsbeautifier.Beautify(&code, jsbeautifier.DefaultOptions())
	if err != nil {
		return nil, err
	}
	return []byte(formatted), nil
}
