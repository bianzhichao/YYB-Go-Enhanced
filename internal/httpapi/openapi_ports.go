package httpapi

func addPortedOpenAPI(spec map[string]any) {
	paths := spec["paths"].(map[string]any)
	for path, summary := range map[string]string{
		"/wxapp/getAllPhone":          "查询可授权手机号列表（不执行指定号码授权）",
		"/wx/getallphonenumber":       "查询可授权手机号列表兼容路径",
		"/wxapp/checkShortUrl":        "检查并解析小程序短链，payload.shortUrl 必填",
		"/wxapp/wxaAttrSync":          "查询小程序属性与版本，payload 可含 syncKey、keyList",
		"/wxapp/wxaAppSync":           "小程序属性查询兼容路径",
		"/wxapp/getWxaCDNDownloadUrl": "查询下载地址，payload 含 version、versionMd5、moduleName",
		"/wxapp/getA8Key":             "专用 A8Key CGI，payload.target_url 必填，biz_username、scene 可选",
		"/wxapp/userRollList":         "A8Key 后查询 HTTPS 微信或财付通 JSON，payload.target_url 必填",
	} {
		paths[path] = wxAliasOperation(summary, "WxappRequest", "WxappResponse")
	}
	flat := objectSchema([]string{"ref", "app_id"}, map[string]any{
		"ref": stringSchema(), "app_id": stringSchema(), "appid": stringSchema(), "openid": stringSchema(),
	})
	for _, path := range []string{"/wxapp/getRuntimeSession", "/wxapp/getPayQRCode", "/wxapp/gatewayv3", "/wx/gatewayv3", "/wxapp/getWxaCode"} {
		request := map[string]any{}
		for k, v := range flat {
			request[k] = v
		}
		properties := map[string]any{}
		for k, v := range flat["properties"].(map[string]any) {
			properties[k] = v
		}
		request["properties"] = properties
		summary := "获取运行时会话（实验性，真实上游兼容待验证）"
		response := defaulted(map[string]any{"200": jsonResponse("实际协议结果。", freeFormObjectSchema("experimental=true 表示尚未验证线上兼容。"))})
		switch path {
		case "/wxapp/getPayQRCode":
			summary = "获取支付二维码 UUID（实验性，不确认支付结算）"
			request["required"] = []string{"ref", "app_id", "package", "paySign", "nonceStr", "timeStamp"}
			for _, name := range []string{"package", "paySign", "nonceStr", "timeStamp", "runtimeTicket"} {
				properties[name] = stringSchema()
			}
			properties["signType"] = map[string]any{"type": "string", "enum": []string{"MD5", "RSA", "HMAC-SHA256"}, "default": "MD5"}
		case "/wxapp/gatewayv3", "/wx/gatewayv3":
			summary = "Gateway V3 云托管调用，业务请求仅发送一次"
			request["required"] = []string{"ref", "app_id", "host", "path"}
			properties["host"] = map[string]any{"type": "string", "description": "*.wxcloudrun.com 主机名，不含协议或端口。"}
			properties["path"] = stringSchema()
			properties["method"] = map[string]any{"type": "string", "default": "POST"}
			properties["headers"] = freeFormObjectSchema("字符串值请求头；禁止 Host 和 X-WX-* 保留头。")
			properties["payload"] = map[string]any{"description": "任意 JSON 业务载荷。"}
		case "/wxapp/getWxaCode":
			summary = "下载主包及分包、解密解包并导出 ZIP"
			properties["downloadUrl"] = map[string]any{"type": "string", "description": "可选，受限微信 CDN HTTPS URL；省略则先查询属性和各模块下载地址。"}
			properties["payload"] = freeFormObjectSchema("属性查询参数。")
			response = defaulted(map[string]any{"200": map[string]any{"description": "完整 ZIP；任何模块失败均不返回部分成功。", "content": map[string]any{"application/zip": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}}})
		}
		paths[path] = map[string]any{"post": openAPIOperation([]string{"wxapp"}, summary, nil, jsonRequestBody(request), response)}
	}
	paths["/auth/keys"] = map[string]any{}
	for _, method := range []string{"get", "post", "put", "delete"} {
		paths["/auth/keys"].(map[string]any)[method] = openAPIOperation([]string{"accounts"}, "管理账号/代理范围 API Key（仅管理员浏览器会话；创建或轮换只展示一次明文）", []map[string]any{{"name": "id", "in": "query", "schema": int64Schema()}}, nil, defaulted(map[string]any{"200": jsonResponse("Key 元数据，不包含持久化明文。", freeFormObjectSchema("POST/PUT 使用 name、account_ids、proxy_ids、exclusive、enabled、rotate。"))}))
	}
	paths["/api/merchant/bills"] = map[string]any{"get": openAPIOperation([]string{"accounts"}, "查询本地账单（浏览器会话，普通用户仅自己的账号）", nil, nil, defaulted(map[string]any{"200": jsonResponse("本地账单，不证明支付结算。", map[string]any{"type": "array", "items": freeFormObjectSchema("账单。")})}))}
}

func stringSchema() map[string]any { return map[string]any{"type": "string"} }
