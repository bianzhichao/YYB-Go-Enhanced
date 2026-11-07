# 本地测试实现移植清单

日期：2026-11-04。参考源码：`D:\jiaoben\应用宝协议\应用宝测试`（Go module `yyb_go_2`）。

对照基线：本 fork 的 `maint/main`，`115455a7dc7b59e3cc752d399b92f22fc8299030`，v0.2.65。下表中的“缺失”指这个固定基线，不能据此声称现在的维护分支仍缺失。

原清单的 13 个确认缺失项已补入目标架构；另补独立 A8Key，作为 userRollList 的必要依赖。实现、离线验证与线上兼容分开记录。没有使用真实账号或真实支付请求验收。

后续继续移植了原来标为差异或待补的接口：请求级 `proxyUrl`、专用 OAuth/第三方授权/AppMsgExt、API Key 扫码归属、静态代理 profile 创建和管理员代理 profile 迁移。

## 功能与证据

源文件位置均相对于上述参考目录；目标位置均相对于本仓库。

| 任务卡 | 源实现与作用 | 固定基线缺失依据 | 本次落地 |
| --- | --- | --- | --- |
| CORE-GATEWAYV3 | `internal/gatewayv3/{client,crypto,gatewayv3,pb,protocol,token}.go`；`internal/httpapi/features_909.go`：云托管网关 token、AES、压缩、protobuf、响应解密 | 无 gatewayv3 包、GatewayToken、CallContext、网关路由 | `internal/gatewayv3/`；`internal/httpapi/gatewayv3.go`，`/wxapp/gatewayv3`、`/wx/gatewayv3`。业务调用位于 token 恢复流程之外，只发送一次 |
| CORE-HOSTSIGN | `internal/protocol/hostsign.go`、`internal/httpapi/hostsign.go`：verifyplugin 插件签名 | 无 HostSign/GetHostSign 或三个路由 | 目标同路径；支持标准 payload 与源 provider/plugins/data、openid/appid 参数及三个路径。使用当前账号设备与授权快照 |
| CORE-RUNTIME | `internal/protocol/runtime_session.go`、`internal/httpapi/runtime_pay.go`：CGI 3540 运行时会话 | 无该 CGI builder/parser、方法或接口 | 目标同路径，`/wxapp/getRuntimeSession`；保留 `experimental=true` |
| CORE-PAY | `internal/httpapi/runtime_pay.go`：使用会话访问 wxaruntime/getuuid | 无该接口或调用 | `/wxapp/getPayQRCode`；保留商户支付参数，仅生成二维码 UUID/URL，不声称支付成功，不自动重放 |
| CORE-ALLPHONE | `internal/protocol/pool.go` 的 GetAllPhone；`ilink.go` 的 buildGetAllPhoneRequest/解析；`httpapi/app.go`：可授权号码列表 | 无列表方法、2536 请求构造和列表路由 | `internal/protocol/allphone.go`、`internal/httpapi/allphone.go`；`/wxapp/getAllPhone`、`/wx/getallphonenumber`。兼容 wx_phone 对象/数组、嵌套 code、空数组 |
| CORE-SHORTURL | `pool.go` 的 CheckShortUrl、`ilink.go` 的 buildCheckShortLinkRequest/解析：小程序短链检查 | 无对应 Pool 方法、builder/parser、路由 | `internal/protocol/wxa_metadata.go`、`internal/httpapi/wxa_metadata.go`；`/wxapp/checkShortUrl` |
| CORE-WXA-ATTR | 同上目录的 WxaAttrSync：属性和版本同步 | 无对应方法和路由 | 同一 metadata 模块；`/wxapp/wxaAttrSync`、`/wxapp/wxaAppSync` |
| CORE-WXA-CDN | 同上目录的 GetWxaCDNDownloadUrl：获取分包下载地址 | 无对应方法和路由 | 同一 metadata 模块；`/wxapp/getWxaCDNDownloadUrl` |
| CORE-WXAPKG | `internal/wxapkg/{unpack,decrypt,beautify,dep,ziputil}.go`、`httpapi/app.go` 的 handleGetWxaCode：下载、解密、解包、美化、依赖归并和 ZIP | 无 wxapkg 包、DecryptWxapkg、UnpackFile、ZipBeautified、下载导出路由 | `internal/wxapkg/`、`internal/httpapi/wxa_code.go`；`/wxapp/getWxaCode`，主包/分包统一校验，失败不返回部分成功 |
| CORE-USERROLL | `internal/httpapi/features_909.go`：A8Key 后查询微信/财付通 JSON | 无 userRollList handler/路由 | `internal/httpapi/user_roll.go`；`/wxapp/userRollList`，限定 HTTPS 域、禁止跳转、限制响应大小 |
| STORE-MERCHANT | `internal/store/merchant.go`、`internal/httpapi/merchant.go`、`resource/templates/merchant.html`：本地账单 CRUD、状态、用户列表、清理与页面 | 无 bills schema、Bill 方法、商户页面/路由 | 目标同路径，复用现有 DB；`/merchant`、`/wx/bills*`、`/api/merchant/*`。写入仅管理员，普通用户读取受账号 ownership 限制 |
| STORE-ONLINE | 源 `internal/store/store.go` 的 OnlineSince/OnlineEndedAt/OnlineBasis 和首页展示：最近观测区间 | 目标无这些字段；Web last_login_at 不等价 | 目标 `store.go`、`account_rebind.go`、`account_merge.go` 与首页模板。可空迁移；显示观测开始/结束/依据，不推算未知历史 |
| AUTH-APIKEY | 源 `store.go` 的 AuthKey 系列方法、`httpapi/exclusive_keys.go`、`account_list_acl.go`：多 Key、账号/代理范围、撤销、独占归属 | 目标只有全局 ProtocolToken 和 Web 用户归属，无 scoped key 数据及入口 | `internal/store/auth_keys.go`、`internal/httpapi/scoped_keys.go`；`/auth/keys`，账号、业务代理、凭据代理均检查；保持原 Web ownership |
| CORE-A8KEY（依赖项） | 源 `pool.go` 的 GetA8Key 与 `ilink.go` 的 buildMPa8keyRequest/解析：专用 CGI | 目标只有 generic operateWxData alias；实验测试不构成正式专用接口 | `internal/protocol/a8key.go`、`internal/httpapi/user_roll.go`；`/wxapp/getA8Key`。旧 `/wx/mpgeta8key` 保留原行为 |
| AUTH-ENROLLMENT | 源 `store.go` 扫码事务接受 owner_key_ids，`app.go` 固定 owner_key_id 到 QR 流程；普通 Key 创建代理节点并绑定 | 基线无 scoped Key 自助二维码归属与节点绑定 | `internal/store/auth_key_enrollment.go`、`internal/httpapi/scoped_enrollment.go`；普通 scoped key 的二维码创建时固定归属，确认扫描时账号与 Key 授权同事务写入。已存在账号只允许该 Key 已授权的账号重扫；排他冲突拒绝 |
| CORE-OAUTH | 源 `protocol/pool.go` OauthAuthorize、`ilink.go` CGI1254 builder/parser、`httpapi/app.go` OAuth handler | 目标 `/wx/oauth` 只生成授权链接，不请求专用 CGI | `internal/protocol/oauth_authorize.go`、`internal/httpapi/oauth_protocol.go`；`/wxapp/oauthAuthorize`。返回授权信息，不绕过用户同意 |
| CORE-THIRDAPP | 源 `httpapi/app.go` 的 ThirdAppAuthorize：qrconnect、A8Key 确认 URL、一次确认及一次取 code | 基线没有第三方扫码确认链 | `internal/httpapi/oauth_protocol.go`；`/wxapp/thirdAppAuthorize`。保留 pending 错误，不能声称扫码授权完成 |
| CORE-APPMSGEXT | 源 `httpapi/app.go` 的 GetAppMsgExt：A8Key 加微信公众号文章扩展查询 | 基线 `/wx/appmsgext` 是 generic operateWxData | `internal/httpapi/appmsg_ext.go`；专用 `/wxapp/getAppMsgExt`；旧 generic 路由保持 |
| PROXY-REQUEST | 源 `internal/httpapi/request_proxy.go`：每次请求独立选登录出口与业务出口 | 基线无 `proxyUrl`；账号代理绑定不等价于一次性覆写 | `internal/protocol/request_proxy.go`、`internal/httpapi/request_proxy.go` 与协议池：null 继承、空串业务直连、URL 仅覆盖本次业务代理；登录和刷新仍走账号设置，缓存按双路由隔离，失败不直连重试 |
| PROXY-MIGRATE | 源 `internal/httpapi/app.go` 的 handleProxyAccountMigrate：按省市将账号从旧动态节点批量迁到另一节点 | 基线无对应批量 profile 迁移接口 | `internal/store/proxy_migration.go`、`internal/httpapi/proxy_migration.go`；管理员 `POST /api/proxy-accounts/migrate`。事务批量更新、失效会话/lease；跨供应商地区必须唯一完整匹配 |

## 调用方式

普通协议路由使用目标现有 JSON 合同：

```json
{"ref":"账号ID、UIN或OpenID","app_id":"wx1234567890abcdef","payload":{}}
```

配置全局令牌时携带 `Authorization: Bearer ...`；也可使用管理员创建的 scoped key。HostSign、Runtime/Payment、源码导出另兼容源 flat 字段。Gateway 使用 `ref/app_id/host/path/method/headers/payload` 顶层字段；`host` 必须是 `*.wxcloudrun.com`。具体请求字段见 `/openapi.json`。

管理 API Key 需要已启用的 Web 身份系统与管理员浏览器会话；协议 Key 不能创建或扩权自己的 Key。`POST /auth/keys` 创建，`PUT /auth/keys?id=...` 更新/轮换，`DELETE` 撤销删除，`GET` 只列元数据。明文只在创建或轮换时返回一次。`account_ids`/`proxy_ids` 空数组不授权资源；direct 流量不消耗代理绑定。

独占账号优先于全局业务 token，包括 integration 业务入口；控制台管理员仍能管理账号。禁用独占 Key 不把其账号重新放给全局调用者。为避免授权跟随错误身份，账号编号整理同步重映射两种 Key 关联；存在 Key 绑定的账号禁止直接合并。换绑保留账号槽位及其配置，Key 也仍绑定这个槽位，这是沿用目标产品的换号合同。

## 实现差异，不能继续计为缺失

1. 目标沿用手写 protobuf、Pool.run、稳定设备身份、授权快照、pacing/circuit 与代理体系，没有复制源整个 generated protobuf 或 go.mod。新增业务/解析终止错误标记 `NoRetryError`，在协议代理回退和 HTTP 凭据恢复两层阻止重放。
2. 源 HostSign 请求可接受 legacy 参数；返回沿用目标 `code/msg/data` 以及账号/result 包装。源 `Status/Message/Data` envelope 没有整体替换目标合同。
3. 源“确认收款”只是 sleep 后把本地状态写成 done。目标明确显示“手工标记本地账单状态，未执行支付结算”，不复制“收款成功”的无依据结论；复用主 DB 而非第二套连接。
4. 源代理节点与目标 proxy provider profile 模型不同。新 Key 的 `proxy_ids` 指目标 profile ID，不能直接导入旧节点 ID。请求级 `proxyUrl` 只作用当前调用；scoped key 的非空代理必须与该账号已绑定 profile 当前解析出的代理一致。扫码自助代理只创建静态目标 profile；动态供应商仍由管理员先配置。批量迁移跨供应商需完整唯一的省市目录匹配，否则跳过；不能撤回已发出的在途请求。Gateway、支付、下载业务 HTTP 禁止失败后回落直连，避免不确定重放。
5. 源 getAllPhone 请求 JSON 少一个右括号；目标用 json.Marshal 构造完整对象。源 wxaAppSync alias 被原 handler 的路径判断拒绝；目标修正别名路径。
6. wxapkg 对错误、路径、符号链接、Windows 保留名、包/文件/分包数量、总量和重定向采用明确边界。`BeautifyFile`、`ScanAllRequires`、`ResolveDeps` 返回 error，`WriteTo` 返回 `(int64,error)`。依赖网络只允许 HTTPS unpkg.com。未知 CDN 不自动扩大白名单。
7. QR 登录、getCode、单号码授权、operateWxData、MMTLS/ILink、保活和诊断在目标已有；保留目标实现。OAuth `/wx/oauth` 继续生成链接；generic AppMsgExt、CreateWxaShortLink 不因源多了 wrapper 而记为整个能力缺失。
8. 目标资源继续使用 embed 与现有部署结构。API Key 管理在 Web AuthDriver=none 时不会开放给协议 token；需启用现有 Web 身份系统。

## 待确认及未完成差异

| 项目 | 当前证据与边界 |
| --- | --- |
| 真实账号与上游接受情况 | 本轮只执行离线测试、合成报文和本地 HTTP 模拟；HostSign、全部新 CGI、A8Key/userRoll 的真实返回布局及 Cookie 语义尚未在线确认 |
| RuntimeSession / Payment | 源本身声明实验性；返回 experimental。没有验证支付请求被微信接受、扫码付款、结算、回调或退款 |
| 指定手机号授权 | 列表查询已实现；源没有已确认的“指定列表号码完成授权”实现，不能声称已补齐 |
| 请求级代理动态节点固定 | 每次协议调用和同一下载/支付子请求复用已解析的业务代理，登录/刷新仍走账号代理；动态 API 的刷新提前量、迁移时已在途的网络请求仍按调用时序生效 |
| OAuth / ThirdAppAuthorize / AppMsgExt 实际上游结果 | 专用接口和单次确认流程已实现并有离线 mock；真实微信用户同意、sessionId/cookie/code 线上交换尚未验证，不把 API 响应等同完成授权 |
| 解密生产调用链 | 源有解密库，但源下载 handler 仅确认调用 Unpack。目标现在按 V1MMWX 头选择解密；合成往返通过，真实密文和实际 CDN 域范围待确认 |
| scoped Key 动态代理自助 | 新 Key 可创建绑定静态 profile；旧动态节点 ID 不导入，动态 profile 仍由管理员配置和绑定 |
| 商户实际资金结算 | 源只有本地状态，未找到微信支付查询、回调验签或结算实现；没有补造这类功能 |
| `_dp_adapter.py` | 缺少其导入的 `_dp_runtime/_dp_records/_dp_transport/_dp_logmode/_dp_cash_recovery/_dp_core`。不完整的其他业务适配器，未导入服务 |
| Utils.go、生成 pb、旧错误辅助文件 | 文件数量不是功能数；已用到的字段按行为迁移，未承诺旧内部符号级兼容 |

## 验证与调度证据

离线覆盖：协议构造/解析、截断及上游错误、手机号列表、Gateway 加密回环与单次业务发送、Runtime 支付参数及单次 UUID 请求、受保护路由、Key 管理/隔离/撤销/代理/编号重映射、本地账单 ownership、在线状态迁移、wxapkg 合成解密解包、路径边界和跨模块 ZIP。

最终集成验证：`go test ./...` 全部 14 个包通过；`go build ./...`、`go vet ./...`、`git diff --check` 均退出 0。环境为 Windows/amd64、Go 1.26.0。未执行容器构建、跨平台运行或真实账号/实际支付调用。

继续移植后的复验：原差异域定向回归通过；`go test ./...`、`go build ./...`、`go vet ./...` 和 `git diff --check` 再次全部退出 0。覆盖请求代理路由隔离、OAuth/第三方授权离线模拟、scoped 扫码绑定/静态代理绑定、管理员批量迁移事务。全程没有真实账号、扫码同意、动态代理付费或支付请求。

六个已有员工聊天均先读取核实；先派员工1并确认真实 commandExecution 输出，再展开其余独立任务。员工1、2、5、6在实际读取后因模型服务 `403 insufficient balance` 中断，没有把这些尝试计为交付。员工3交付在线区间、员工4交付 wxapkg 和质量审查；有效类型 default 的临时员工补齐受阻域，PM负责公共接线与集成。审查发现的编号错绑、错误重放、Windows ZIP 前缀均有离线回归修复。

## 2026-11-05 上游同步

同步前维护提交：`75d2fca545708c160afd0afec8eae5f63eab5818`；合并上游固定提交：`60921f77efb9949bc7cc2ef3ab94c7fcc71f6757`（包含 v0.2.75 后 fleet 修复），共同基线 `115455a7dc7b59e3cc752d399b92f22fc8299030`。

保留维护接口和权限合同，并引入上游 H5/OAuth、GameAssist、动态 AppID denylist 和 fleet。`/wx/oauth` 默认自动交换 code；调用者可用 `return_url_only=true` 保留只生成授权链接行为，自动交换透传请求级 `proxyUrl`。旧维护 app.go 的 119 条显式唯一路径全部保留，合并后为 123 条（按 URL 大小写敏感统计，StringComparer.Ordinal）。

交叉适配：fleet 候选逐账号执行 scoped Key、独占账号和浏览器 ownership 过滤；各成员仍独立执行代理授权与解析、会话 expected-account 检查。NoRetryError 在 fleet 层终止，不跨成员重放。named 兼容入口执行账号可见性与请求级代理检查。store 同时保留 fleet_primary_id 与 online 区间字段、迁移和扫描；过期清理保留 GameAssist 渠道标记。

新增离线回归覆盖 scoped/独占成员隔离、浏览器 ownership、NoRetry 跨成员终止、proxyUrl 切换成员保留和 OAuth 自动交换代理透传。复验发现 fleet 的进程级 LRU 会串用不同 App 中相同账号 ID，已改为 App 实例独立记录，并增加跨实例隔离回归。

H5 授权发送后的错误标记为 NoRetry；业务报文仅发送到一个 ShortLink 目标，禁止直连回退和跨目标重发。发送前的凭据获取策略保留。新增本地模拟覆盖响应丢失与畸形响应：各发送一次，不失效已有代理 session。此前未完成的进程级发送注入已移除，测试注入仅作用单个 Pool。

最终修复后 `go test ./...`、`go build ./...`、`go vet ./...`、`git diff --check` 全部退出 0；`python -B -m unittest discover -s tests -p test_website_appid_scripts.py` 的 3 项离线测试通过。未进行真实账号、扫码、支付或部署验证。

## 2026-11-05 上游 v0.2.79 同步

同步前维护提交 `6881b09fb6f1fcd1a2699311b791d777ca2872c2`；固定上游 `151bf1eda77abbeb4135b8a94f2e0e6efd9ea9e4`。合入本轮 5 个提交，包括运行参数面板、多渠道扫码、账号组合及面板代表同步。保留维护的专用微信接口、scoped Key/独占账号、扫码归属、代理、在线区间、账单、H5 单次发送和实例级 fleet 调度状态。

文本冲突位于 app.go 的扫码确认：保留维护方 saveScannedAccount 与 scoped enrollment 检查，同时采用上游 skipAutoSync/defer_panel_sync 行为。源码回读确认账号合并的 ErrMergeAPIKeyBindings 防护、编号整理的 Key/独占关系重映射均保留。按大小写敏感的显式唯一路径统计，维护 123 条、上游 89 条、合并 127 条，两边路径均无丢失；兼容别名与管理路径包含在计数内。

交叉审查后修复：fleet 状态查询逐成员检查账号可见性，对含隐藏成员的历史组返回 403，避免披露其他归属的成员资料；runtime settings 在 Reset、文件写入及内存修改前校验全部现有限制字段，非法请求不产生部分修改。新增 sync_v079_test.go 覆盖 scoped Key/浏览器成员隔离和非法请求保留配置及黑名单状态。

验证：多渠道页面使用独立本机服务、SQLite seed 数据与 mock QR，node tests/multi-channel-ui.cjs 输出 multi-channel scan UI ok，退出 0；两项补修有定向回归。最终 `go test ./...`、`go build ./...`、`go vet ./...` 与 `git diff --check` 均退出 0。未调用真实账号、真实扫码、支付或部署。临时 UI 服务和数据已清理。
## 2026-11-07 上游 v0.2.87 同步

同步前维护提交 `525a66aaf724e4496d2bc62f2851d6b5ca3720a6`；固定上游 `51bfe8ff2c3dc0da16b53246d69cf0723ceb9a21`。保留上游 QQ 浏览器登录、雷电模拟器实验渠道、多渠道授权链接、AppID 名单管理及现有维护业务接口。

唯一文本冲突是账号编号整理的关联表列表，合并保留 API Key、独占归属、多渠道主账号和扫码进度的全部引用。QQ 浏览器令牌导入接入维护方 scoped enrollment、事务内 Key/独占校验和 Web 账号归属；公开多渠道链接在写事务内拒绝已独占的来源/主账号/目标账号，包括独占之前发出的旧链接。多渠道新增/刷新账号沿用在线观测区间规则。

大小写敏感路由比较：旧维护 127 条、上游 90 条、合并 128 条，双方显式路径均无丢失。新增离线回归验证 QQ 浏览器 Key 绑定、独占拒绝、Web 归属、多渠道链接事务回滚和在线区间；原编号整理回归同时通过。没有调用真实微信账号或支付接口。

验证通过：`go test ./...`、`go build ./...`、`go vet ./...`、`git diff --check`；3 项 website AppID 脚本测试；隔离服务的 `multi-channel-ui.cjs` 和 `account-link-multi-ui.cjs`（合成 QR，320–1280px）。UI 回归改为读取服务端渠道数量，切换单渠道时等待新 QR 响应，避免仍以三个渠道和旧图片作为完成条件。
