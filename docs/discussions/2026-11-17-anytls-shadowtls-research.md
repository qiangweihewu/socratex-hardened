# anytls-go 与 shadow-tls 借鉴调研（2026-11-17）

**状态：调研完成。** 两个 P0 和两个 P1 已于 2026-11-17 实施（`--stealth` 还待用 Shadowrocket 实测）；P2 未拍板。同日补充了 naiveproxy 和 forwardproxy 的调研（见文末）。

## 起因

想知道 [anytls/anytls-go](https://github.com/anytls/anytls-go) 和 [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) 有哪些东西值得 socratex 学习、借鉴或直接移植。

## 快照与许可证

| 仓库 | 快照 | 许可证 | 结论 |
|---|---|---|---|
| anytls-go | `fd6167a`（2026-08-03） | 根目录**没有 LICENSE 文件**（`find -maxdepth 1 -iname 'licen*'` 无结果） | 红线：不能复制代码，只能按协议文档里的思路重新实现 |
| shadow-tls | `02dd0bc`（2025-04-25） | MIT（`LICENSE:1-3`） | 绿：可以摄入，需保留署名 |

本节是工程分析，不构成法律意见。

## 核心判断

两个项目都是**需要专用客户端的翻墙协议**：anytls 要求客户端实现会话复用和 padding；shadow-tls 要求客户端在 ClientHello 的 SessionID 里嵌入 HMAC。socratex 的定位是**标准 HTTPS 正向代理**，用 Shadowrocket、curl、浏览器这类现成客户端就能连。

所以整套协议**不移植**，否则产品性质会从“标准代理”变成“私有协议”。值得搬的是三类东西：
1. 抗主动探测的思路；
2. 多路复用的思路（但要换成标准协议 HTTP/2 CONNECT 来实现）；
3. 长连接保活的细节。

## 逐项发现

### anytls-go
- **会话层多路复用**：多条代理流共用一条 TLS 连接，省掉每条隧道各自的 TLS 握手。依据是 `docs/protocol.md` 的“复用”一节，以及 `proxy/session/client.go:140-149`（取最新的空闲会话）和 `:201`（idleCleanup）。复用策略可以概括为“优先复用最新的会话，优先清理最老的会话”。
- **Padding 方案由服务端下发、可以热更新**：`proxy/session/session.go:418-473`（writeConn 按包序号拆包、补 `cmdWaste`），`:279-283`（padding 的 md5 不一致时下发新方案）。目的是缓解 TLS-in-TLS 的包长特征。
- **v2 版 SYNACK 和心跳**：`session.go:335-339`。用来发现卡死的隧道，不必等系统级 TCP 超时。
- **反 hype**：
  - 文档说认证失败会 fallback 到正常的 HTTP 服务，但参考实现里写着“暂未实现”（`cmd/server/inbound_tcp.go:86-89`）。
  - 认证比较用的是 `bytes.Equal`，不是常量时间比较（`inbound_tcp.go:41`）。
  - 读认证包时没有设 deadline（`inbound_tcp.go:33`）。
  - 出站拨号不限制目标地址，内网可以直达（`cmd/server/outbound_tcp.go:17`）。
  - 证书是启动时自签的，客户端必须跳过证书校验（`cmd/server/main.go:63-68`）。
  - FAQ 自己也承认：“由于这不是 HTTP 服务器，仍然可能存在主动探测问题”（`docs/faq.md` 的“已知弱点”一节）。

### shadow-tls
- **认证失败就原样转发到真实网站**：`src/server.rs:282-283`，ClientHello 校验不通过时，直接和握手服务器做 TCP 双向中继。探测者看到的是一个真网站，这是这两个项目里抗探测最彻底的做法。
- **按 SNI 分流，加通配 SNI**：`src/server.rs:54-62`（`WildcardSNI::Authed/All`）。
- **ClientHello 的 SNI 解析**：`src/server.rs:584` 起（`extract_sni_v2`），`:658` 判断 SNI 扩展类型。MIT 许可，可以参照着改写成 JS。
- **TCP keepalive 90s/90s/2 次，加 nodelay**：`src/util.rs:123-131`。**TCP Fast Open**：`util.rs:225-227`。
- **反 hype**：`server.rs` 和 `main.rs` 里搜不到任何 timeout，握手阶段没有超时保护。

### 对照中发现的 socratex 自身问题
- **主动探测能直接认出是 socratex**：
  - `GET /` 固定返回 `42`（`lib/web.mjs:71-72`）。
  - 407 响应里带 `Proxy-Authenticate: Basic realm="Socratex"`（`lib/socratex.mjs:149`、`:183`）。
  - 任何未认证的 CONNECT 都会收到 407，等于告诉对方“这里是代理”。
- **凭据比较不是常量时间**：`main.mjs:113-115`（`===`），PAC token 的比较也一样（`lib/web.mjs:66`）。
- **`idleTimeout` 60 秒同时作用于已建立的隧道**：静默超过 60 秒的长连接（WebSocket、IM、推送）会被切断。这一条是推断，需要实测确认。

### socratex 已有且更强（不要倒退）
- 私网和保留地址的出站拦截，并且只拨号已经检查过的地址（anytls 没有）。
- 请求头和握手有截止时间（anytls 和 shadow-tls 都没有）。
- 客户端会校验代理的证书（anytls 是自签证书）。
- TLS 会话复用、DNS 缓存、Happy Eyeballs（2026-11-17 已实现）。

## 裁决表

| 优先 | 事项 | 来源（路径:行号） | 落哪层 | 需先做什么验证 | 成本 |
|---|---|---|---|---|---|
| P0 ✅ 已完成 | 凭据、PAC token 和 console token 都改用 `crypto.timingSafeEqual`（先对两边做 SHA-256，再比较；空 secret 一律不匹配） | 我方 `main.mjs:113-115`、`lib/web.mjs:66`；对照 anytls `inbound_tcp.go:41` 的反例 | main.mjs、web.mjs | 无，补单元测试即可 | 小（约 10 行） |
| P0 ✅ 已完成 | 去掉指纹：realm 默认改为 `proxy`，可用 `--realm` 配置（会校验，防止头部注入）；`/`、`/favicon.ico`，以及没带有效 token 的 `/console`、PAC 路由，都和未知路径返回同样的 404 | 我方 `lib/web.mjs:71-72`、`lib/socratex.mjs:149,183` | socratex.mjs、web.mjs | 确认没有客户端依赖 realm 字符串 | 小 |
| P1 ✅ 已实现，待 Shadowrocket 实测 | 抗探测模式 `--stealth`（默认关闭；按 forwardproxy 的设计加了 `--secret-domain`）：没带凭据或凭据错误的请求，按普通 Web 服务器处理（404，或反代到 `--fallback` 指定的站点），**不返回 407** | shadow-tls `server.rs:282-283`；anytls `docs/protocol.md`“服务器/认证”一节（只有思路，实现缺失） | socratex.mjs | **先实测 Shadowrocket、curl 是否会主动带上 Basic 凭据**；会依赖 407 质询的客户端（如浏览器）在 stealth 模式下无法使用，需写进文档 | 中 |
| P1 ✅ 已完成（已复现：静默的隧道在第 60.0 秒被断开） | 已建立的隧道开 TCP keepalive（`setKeepAlive(true, 30s)`），并把隧道空闲超时和握手前空闲超时拆开（新增 `tunnelIdleTimeout`，默认例如 10 分钟） | shadow-tls `util.rs:123-131`；anytls 心跳 `session.go:335-339` | socratex.mjs | 先复现“静默 60 秒以上的长连接被断开” | 小 |
| P2 | HTTP/2 CONNECT（ALPN 同时声明 h2 和 http/1.1）：多条隧道共用一条 TLS 连接，这是 anytls 多路复用在标准协议里的对应做法；之后可以加 h2 帧 padding | anytls `docs/protocol.md`“复用”一节、`client.go:140-149`；padding `session.go:418-473` | socratex.mjs（新增 http2 分支） | **先确认目标客户端支持 h2 代理**（Chrome 推测支持，Shadowrocket 未知）；不支持的客户端会自动回落到 http/1.1，不受影响 | 大 |
| P2 | SNI 分流：ClientHello 的 SNI 不是本域名（或没有 SNI，比如直接按 IP 扫描）时，原样 TCP 转发到诱饵站点 | shadow-tls `server.rs:584-662`（MIT，参照改写需署名） | socratex.mjs 的连接入口 | 确认 Shadowrocket 等客户端会发送正确的 SNI | 中 |

### 结案不做
- **移植 anytls 或 shadow-tls 协议本身**：需要专用客户端，改变了产品定位；anytls 没有 LICENSE。如果确实需要，用 sing-box 等现成服务端单独部署，和 socratex 并行运行，不要合并进来。
- **TCP Fast Open**：Node 没有提供 TFO 的 API，需要原生扩展，收益和维护成本不成比例。
- **anytls 的 padding 方案（HTTP/1.1 下）**：CONNECT 隧道是不透明的字节流，服务端插入的 padding 标准客户端无法剥离。只有做了 h2 之后，才可以用 h2 自带的帧 padding。

### 未采纳登记（不赋优先级）
- anytls 的 UDP-over-TCP（sing-box uot v2）：标准 HTTP 代理客户端不会用到。
- shadow-tls v3 的 ApplicationData HMAC 封装和防劫持：依赖专用客户端。
- anytls 的 `client-name` 上报：对 socratex 没有对应场景。

## 预注册判据
- P1 stealth：Shadowrocket 和 curl 在 stealth 模式下都能正常代理，才把它写进推荐配置；任何一个必须依赖 407 质询，就只作为高级选项保留。
- P1 隧道保活：先证实 60 秒空闲会断开，再改；无法复现就结案。
- P2 h2：至少一个目标客户端能实际在 h2 上复用隧道，才立项。

## 已知盲区
- 没有读 anytls 的 `proxy/padding/padding.go` 细节、`proxy/pipe/`，以及 shadow-tls 的 `client.rs`、`helper_v2.rs`。
- “Chrome 支持 h2 代理”“Shadowrocket 会主动带 Basic 凭据”都是推断，没有实测。
- anytls FAQ 里提到的 naiveproxy（Caddy forwardproxy，带 probe_resistance、h2 和 padding）是和 socratex 形态最接近的参照，已在同日补充调研，见下一节。

## 补充：naiveproxy 和 forwardproxy（2026-11-17）

| 仓库 | 快照 | 许可证 |
|---|---|---|
| klzgrad/forwardproxy（Caddy 插件，naiveproxy 的服务端） | `e747854`（2026-10-23） | Apache-2.0（绿；摄入代码需加 NOTICE） |
| klzgrad/naiveproxy（只稀疏读了文档和 `src/net/tools/naive`） | `6acbded`（2026-11-01） | Chromium BSD（绿） |

- **探测抵抗**（`forwardproxy.go:258-276`，README `:122-132`）：
  - 未认证的请求交给后面的普通网站处理，不返回 407；
  - 只有请求秘密域名时才返回 407（`serveHiddenPage`，`:612-637`）；
  - README `:130` 明写：会主动发送凭据的客户端不需要秘密链接。
  - socratex 的 `--stealth` 和 `--secret-domain` 就是按这个设计实现的。
- **凭据比较**用 `subtle.ConstantTimeCompare`（`:465`），和我们的 P0 一致。
- **padding 是按需协商的**（naiveproxy README `:92-130`）：
  - 双方靠 CONNECT 请求和响应里有没有 `padding` 头来判断对方是否支持，不支持的一方照常走标准 h2 CONNECT（`:126-128`）。
  - 只对隧道建立后的前 8 次读写加 padding，每次是 3 字节头部加 0–255 字节随机填充（`:98-108`；forwardproxy `:662-760`）。
  - CONNECT 的 HEADERS 帧也会加一个 `padding` 头（`:122`；forwardproxy `:308-320`）。
- **P2 的修正判断**：
  - 做 h2 CONNECT 时，顺带实现上面这套按需协商的 padding，socratex 就能兼容 **NaïveProxy 客户端**，普通的 h2 客户端也不受影响。这让 h2 这一项的价值明显上升。
  - 前提不变：先确认目标客户端支持 h2 代理。哪些客户端支持 naive 协议，还没有调研。
- **forwardproxy 自身的反例**：秘密页面里还写着 `Caddy Secure Web Proxy` 的 realm 和 `Hidden Proxy Page` 字样（`:612-630`），转发 HTTP 时默认会加 `Via: ... caddy` 头（`:387`、`:773`）。socratex 不照搬这些。

## naiveproxy 深读（2026-11-17，快照 `6acbded`）

只读了 `src/net/tools/naive/`（约 4500 行），没有读 Chromium 网络栈本身。

### 关键发现
- **padding 协商不要求 h2，HTTP/1.1 CONNECT 也可以**：
  - 客户端：`naive_proxy_delegate.cc:42-67`、`:141-176`，只在直连和 SOCKS 时跳过协商，http/https/quic 代理都会协商。
  - 服务端：naive 自己的服务端就是 HTTP/1.1 的 CONNECT 代理（`http_proxy_server_socket.cc:274-305` 解析 `padding` 和 `padding-type-request`；`:449-458` 回复 `HTTP/1.1 200 OK` 加上 30–62 字节的 `Padding:` 头）。
  - **推翻上一节的判断**：padding 和 h2 是可以拆开做的。socratex 只要在 HTTP/1.1 上实现 Variant1，NaïveProxy 客户端就能连。
- **Variant1 帧格式**（`naive_protocol.h:29-44`，`naive_padding_framer.cc` 约 70 行状态机）：
  - 每帧是 `[长度高字节, 长度低字节, padding 长度, 数据, 零填充]`，每个方向只有前 8 帧加 padding（`naive_padding_socket.cc:20`），之后直接透传。
  - **README 没写的细节**：服务端发出的数据小于 100 字节时，padding 取 `[255−长度, 255]`，把小包抬到接近 255 字节；其他情况在 `[0, 255]` 里均匀随机（`naive_padding_socket.cc` 的 `WritePaddingV1`）。移植以代码为准。
  - 回复里没有 `padding-type-reply` 时，客户端按向后兼容规则把 `Padding` 头视为 Variant1（`http_proxy_server_socket.cc:280-286`，客户端解析逻辑相同）。
- **preamble（开场请求）**：客户端在发 CONNECT 之前，先用 Chrome 的请求头 `GET https://<代理域名>/`（`preamble_getter.cc:91-93`、`:244-246`），让连接一开始看起来像在正常浏览网站。这意味着服务端的 `/` 最好是一个像样的网站；socratex 现在 `/` 返回 404，功能上不受影响，但伪装效果打折扣。
- **超时参照**（USAGE）：
  - `--idle-timeout` 默认 600 秒，和 socratex 的 `tunnelIdleTimeout` 一致。
  - `--tunnel-timeout` 1800 秒后让连接“退役”，用来对付 CGNAT 网络里长连接卡死。这是 h2 连接层面的机制，做了 h2 之后才用得上。
- **支持 naive 协议的客户端**（README `:22`、`:84-86`）：官方 naive 客户端、Exclave、husi、NekoBox（Android）、v2rayN。**名单里没有 Shadowrocket**；Shadowrocket 是否支持 naive 协议，需要另外核实。

### 反例
- 凭据比较用 `!=`，不是常量时间；校验失败时会把客户端发来的 `Proxy-Authorization` 原文写进日志（`http_proxy_server_socket.cc:362-369`）。日志默认关闭（USAGE `--log`）。
- 服务端没有任何出站地址过滤，内网可以直达（`naive_connection.cc` 里搜不到相关检查）。
- 认证失败直接断开连接（`:368`），因为它设计上就藏在 Caddy 或 HAProxy 后面。

### 修正后的裁决（追加，未拍板）

| 优先 | 事项 | 来源 | 落哪层 | 需先做什么验证 | 成本 |
|---|---|---|---|---|---|
| P1 ✅ 已完成，判据达标（见下方“实测记录”） | 在 HTTP/1.1 CONNECT 上兼容 naive padding Variant1：CONNECT 请求带 `padding` 头（或 `padding-type-request` 里包含 `1`）时，回复 `200` 加 `Padding:` 头，两个方向的前 8 帧做 padding 编解码；不带这个头的客户端行为完全不变 | `naive_proxy_delegate.cc:42-67,141-176`；`http_proxy_server_socket.cc:274-305,449-458`；`naive_padding_framer.cc`；`naive_padding_socket.cc` 的 `WritePaddingV1` | socratex.mjs 的 CONNECT 分支，新增约 120 行的帧编解码 | 用官方 naive 客户端实连本地 socratex，日志里出现 `negotiated padding type`，并且经它的 SOCKS 端口取页面 20 次全部正确 | 中 |
| P2 | 诱饵站点 `--site-root`：`/` 返回一个静态网站，配合 stealth 和 naive 的 preamble | `preamble_getter.cc:91-93` | web 路由 | 防路径穿越；和 stealth 下的 404 行为保持一致 | 中小 |
| P2 | h2 CONNECT：恢复多路复用（naive 抗流量分类的核心，README `:7`）；之后可以加连接“退役”机制 | README `:7`；USAGE `--tunnel-timeout` | 新增 http2 分支 | 确认目标客户端支持 h2 代理 | 大 |

**结案不做**：Chromium 客户端的 TLS 指纹复用、QUIC/HTTP3、redir 模式和伪 DNS、SOCKS 监听。这些都是客户端功能，或者对 socratex 来说过重。

**预注册判据（naive padding）**：naive 客户端通过 HTTP/1.1 能协商出 Variant1，并且 20 次取页全部正确，才合并；如果 naive 客户端在 HTTP/1.1 下无法建立隧道，就把这一项推迟到 h2 之后。

### 实测记录（2026-11-17，判据达标）
- **环境**：官方 naive v154.0.8037.49-5（macOS arm64，SHA-256 与 GitHub Release 公布的摘要一致，验证完已删除）。链路是 `curl → naive(SOCKS) → 记录字节的中继 → socratex(明文 HTTP 模式) → 本地源站或 1.1.1.1`。
- **padding 开启**：naive 日志打出 `negotiated padding type: Variant1`；1MB 随机文件 20/20 次 SHA-256 一致；经 1.1.1.1 的 HTTPS 5/5 正常；中继记录的 25 条隧道全部是 `HTTP/1.1 200 OK` 加 `Padding:` 头。
- **对照组**（`naivePadding: false`）：naive 协商出 `None`，数据 20/20 正确，线上没有任何 padding 字节。
- **搭配 `--stealth`**：Variant1 协商正常，20/20 正确。naive 在第一个 CONNECT 里就主动带 `Proxy-Authorization`。
- **未覆盖**：naive 走 HTTPS 连 socratex 的端到端测试（需要让客户端信任自签证书，就得改系统钥匙串）。padding 协商逻辑对 http 和 https 代理是同一套（`naive_proxy_delegate.cc:42-67` 不区分这两种）。
- **preamble 失败不影响建立隧道**：`naive_proxy.cc` 的 `DoPreambleComplete` 写明 “Preamble error doesn't prevent Connect()”。~~preamble 只在 `IsSessionCapable()` 时才发，HTTP/1.1 代理不会触发~~：**这条推断是错的**，2026-11-17 用真实服务器实测后推翻，见下一节。
- **测试过程中踩的坑**：第一版验证脚本用同步的 `execFileSync` 调 curl，卡住了同一进程里的中继和 socratex，导致 0 条隧道。改成异步调用后正常。

### 真实服务器实测（2026-11-17，hy.geshandi.vip:8443，Debian 12 x64，用 deploy.sh 部署）
- **naive 走 HTTPS 时会发 preamble**：表现为 `CONNECT preamble:0`（NetLog 抓包确认，凭据已被 NetLog 自动去掉）。socratex 因为端口为 0 回了 400。
- **问题**：这个 400 响应里没有 `Padding` 头，而 naive 对每台服务器只保存一份 padding 状态，于是状态在 `None` 和 `Variant1` 之间来回切换（各 16 次），20 次下载里有 2 次 SHA-256 不一致。
- **修复**（commit `a50e520`）：客户端通过认证并声明支持 padding 之后，错误响应也带上 `Padding` 头；未认证的请求和普通客户端不受影响。
- **修复后的结果**：
  - naive 走 HTTPS 共 140 次：padding 只协商一次 `Variant1`；139 次正确，1 次是 curl exit 35（和目标站点的 TLS 握手失败，属于网络层错误，不是数据损坏）；100 次那一轮全部成功，每条连接都正常关闭。
  - 对照组 curl 走 HTTPS 代理、不加 padding：40/40。
- **结论**：padding 搭配 HTTP/1.1 和 HTTPS 在真实链路上可用。preamble 在 HTTP/1.1 下一定会失败，这和官方 forwardproxy 的行为一致（forwardproxy 里也没有任何针对 preamble 的处理），不影响使用。

### h2 CONNECT 是否要做（2026-11-17 讨论，未拍板）
- **起因**：配置 Shadowrocket 时，它的 TLS 设置页有「HTTP2」开关（说明文字是“如果 ALPN 协商结果为 h2，则启用 HTTP/2”），ALPN 的默认占位值是 `h2,http/1.1`。Zach 问 http/1.1 和 h2 有什么区别、有没有必要支持 h2。
- **新证据**：Shadowrocket 的 HTTPS 类型支持走 h2 代理。这部分满足了上文 P2 的前提“先确认目标客户端支持 h2 代理”。它是否真的在一条连接上复用多条隧道，还没有实测。naive 客户端默认就优先用 h2。
- **现状**：socratex 不声明 ALPN（`lib/` 和 `main.mjs` 里没有 `ALPNProtocols`）。在线上用 `openssl s_client -alpn h2,http/1.1` 实测，结果是 `No ALPN negotiated`，客户端随后走 HTTP/1.1。
  - Shadowrocket 的 ALPN 说明写的是：这个字段是为了降低 TLS 指纹的独特性，并提醒“如果服务器支持 HTTP/2，设置为任何包含 h2 的组合可能导致连接失败”。
  - 所以对现在的 socratex 来说，客户端 ALPN 保持默认的 `h2,http/1.1` 就可以，这样 ClientHello 更像浏览器。HTTP2 开关保持关闭。
  - **这是对 h2 立项的硬约束**：服务端一旦在 ALPN 里声明 h2，那些保持默认 ALPN、又没打开 HTTP2 开关的 Shadowrocket 客户端就会连不上。上线 h2 时必须二选一：要么默认关闭 h2、通过参数显式开启，要么在部署脚本输出的配置里同步要求客户端打开 HTTP2。
- **h2 的收益**：
  - 新隧道不用重新握手，打开新网站的首包延迟更低。跨境线路 RTT 大、TLS 握手慢时，收益最明显。
  - 一个客户端只对服务器保持一条长连接，和浏览器访问 h2 网站的形态一致。HTTP/1.1 下一个客户端会对同一台服务器开几十条 TLS 连接，这是可以被识别的特征。
  - ALPN 声明 h2 也和普通网站（nginx、Caddy）的默认表现一致。
- **h2 的代价**：
  - TCP 层的队头阻塞：丢一个包，所有隧道一起卡住。在丢包多的跨境线路上，大文件下载可能比多条 HTTP/1.1 连接还慢。
  - 所有隧道共用一个拥塞窗口。Node `http2` 的默认流控窗口是 64KB，必须调大，否则高带宽时延积的线路上会限速。
  - 实现量大：要新增 http2 分支，并在这条路径上重新实现认证、stealth 的 404、`Padding` 响应头、超时和 keepalive，测试也要整套补齐。纯转发时 CPU 开销也比现在的 `pipe` 高。
- **建议（未拍板）**：暂不做。先用现有的 HTTP/1.1 版本在 Shadowrocket 和 NekoBox 上实际使用一段时间，再决定。
- **预注册判据**：
  - 实际使用中明显感到“打开新网站慢”，而且从客户端侧测得到 socratex 的 TLS 握手中位数 ≥300ms，才立项。
  - 立项后，在同一台服务器上用 Caddy forwardproxy（h2）和 socratex（h1）做 A/B：分别对 20 个新域名测首字节时间，并测 1 个大文件的吞吐。h2 首字节时间中位数改善 ≥30%，并且吞吐下降不超过 10%，才合并。

### 一键部署 anytls / shadow-tls / naiveproxy（2026-11-17，已实施）
- **起因**：Zach 要求在本仓库增加这三个协议的一键部署脚本，参考 s-ui 的安装脚本。s-ui 是 GPL-3.0，只参考了它的流程（选架构、校验下载、首次安装生成随机凭据），没有复制代码。
- **选型（已拍板，Zach 选定）**：
  - anytls 和 shadow-tls 用 sing-box v1.14.4，一个服务里跑两个入站。
  - naive 用官方的 Caddy + klzgrad/forwardproxy v2.11.7-naive2。
  - 没选 sing-box 的 naive 入站，是因为它不防主动探测：非 CONNECT 请求和不带 `Padding` 头的请求一律返回 400 并重置连接（`protocol/naive/inbound.go:148-156`）。Caddy 版有 `probe_resistance`，对外是一个普通网站。
- **代价**：forwardproxy 只发布了 x86-64 版本，arm64 上只能部署 anytls 和 shadowtls，naive 改用 socratex。
- **实现**：`scripts/deploy-protocols.sh`。
  - 二进制从 GitHub Release 下载，并按 API 返回的 `digest`（sha256）校验。
  - 生成的配置先用 `sing-box check` 和 `caddy validate` 校验，通过后才替换旧配置。
  - 两个服务都禁止连到私有地址、CGNAT 地址和 169.254/16。forwardproxy 默认只拦 RFC 1918 和回环地址（`forwardproxy.go:156-169`），云元数据地址 169.254.169.254 是我们补上的。
  - shadow-tls 后端是 Shadowsocks 2022，只支持 TCP，开了 strict_mode。
- **实测**（104 服务器，端口 8444/8445/8446）：
  - 从公网访问，三条链路的 `generate_204` 都是 20/20 成功；31.7MB 文件下载 3 次，sha256 全部一致。
  - 探测结果：naive 看到的是 Caddy 网站，未授权的 CONNECT 返回 308；shadowtls 不管带什么 SNI，看到的都是微软的真实证书和网站；anytls 握手后直接断开。
  - 升级（重复运行）、增减协议、续期 hook、卸载后重装都验证过。
- **已知弱点**：anytls 认证失败时没有 fallback（anytls FAQ 自己承认这一点）。
- **未测试**：certbot 新签证书、arm64、不提供域名只用 `--address` 的情况、各客户端导入 `anytls://` 链接、Shadowrocket 的 ShadowTLS 配置。
- **Shadowrocket 导入链接**（2026-11-17，由 Zach 在 macOS 版 Shadowrocket 上导出确认）：
  - Shadowrocket 不认 `naive+https://`。
  - HTTPS 节点的格式是 `https://user:pass@host:port?peer=<SNI>&method=auto&fingerprint=Safari26_3#name`。
  - Shadowsocks + ShadowTLS 节点的格式是 `ss://` + base64url(`method:password@host:port`) + `?shadow-tls=` + base64url(`{"version":"3","host":…,"password":…}`)，不带 padding。
  - 两个部署脚本的 `--show` 都改成输出这两种格式。在 macOS bash 3.2 和服务器 bash 5.2 上生成的结果，都和 Shadowrocket 自己导出的链接逐字节一致。
  - HTTP2 开关和「填充」开关对应链接里的哪个参数还不知道：naive（Caddy）节点导入后，需要手动打开这两个开关。
- **踩坑**：bash 3.2 有个 bug，`"$(f "{…,…}")"` 这种写法里的花括号会被展开，导致生成的 JSON 被拆成几段。改成先把 JSON 赋值给变量，再传进去。

### 证书来源可选（2026-11-18，已实施）
- **起因**：Zach 要求两个部署脚本都能选择证书来源，三个选项：
  - 已有证书，默认路径 `/etc/letsencrypt/live/<域名>/fullchain.pem`；
  - 重新申请；
  - 内置证书功能。
- **「内置证书」的解释**：理解为程序自带的 ACME 自动申请，不是 utilitas 打包的那张证书。原因是：
  - utilitas 的 `keys/` 目录里打包了一张签给 `127.0.0.1` 的自签证书，私钥随 npm 包一起公开，绝不能用于公网部署。
  - 实际采用的三个实现：
    - socratex 用 utilitas 的 ACME（`ssl.mjs:82-125`），HTTP-01 验证，主进程常驻占用 80 端口，每周检查一次，到期前 30 天续期，联系邮箱固定写成 `i@域名`；
    - naive 用 Caddy 的自动 HTTPS；
    - anytls 用 sing-box 1.14 的 `certificate_provider: acme`。官方发布包带了 `with_acme` 构建标签（`release/DEFAULT_BUILD_TAGS`）；旧写法 `tls.acme` 已废弃，1.16 移除。
  - sing-box 的 `data_directory` 指向 Caddy 的 certmagic 存储目录，两个程序共用一张证书和一套锁文件，避免重复申请和争抢 80 端口（这是推断，还没有用真实签发验证过）。
- **实现**：`--cert existing|certbot|builtin`。
  - 首次安装时，如果在终端里运行，会弹出菜单；不在终端里时，有 Let's Encrypt 证书就用 existing，否则用 certbot。
  - 选择会保存下来，重跑时沿用；旧安装里的 `certbot`/`custom` 会自动迁移。
  - 证书和私钥必须匹配（比对公钥），并且证书要覆盖这个域名。校验通过后才写设置文件，失败的运行不会留下错误的配置。
  - 续期处理：`/etc/letsencrypt/live/*` 下的证书用 certbot deploy hook；其他路径的证书用 systemd path 单元。两者都调用同一个同步脚本，同步脚本会再校验一次证书和私钥是否匹配。
- **实测**（104 服务器）：
  - 已通过：旧模式迁移（凭据不变）、existing 默认路径、existing 自定义路径（文件变化后自动同步并重启服务；私钥不匹配时拒绝更新、不重启服务）、交互菜单、80 被 nginx 占用时 builtin 拒绝执行（状态不变）、builtin 和 existing 两种模式生成的配置都通过了 `sing-box check` 和 `caddy validate`。
  - **未测试**：certbot 和 builtin 的真实签发。104 的 80/443 端口属于 nginx，需要一台这两个端口空闲的服务器。
- **补充（2026-11-18）**：
  - 首次安装时，没给域名就在交互里询问，所以直接运行 `sudo bash deploy.sh` 就行，README 的主命令也改成了这个。
  - 邮箱只在两种情况下询问：certbot 即将申请证书，或者 sing-box/Caddy 走内置申请（builtin）。可以直接回车跳过。socratex 的内置申请不问邮箱，因为 utilitas 把邮箱写死了。
  - 提示语里去掉了“到期提醒”：Let's Encrypt 从 2025 年起不再发送证书到期提醒邮件。
  - 不在终端里运行（比如 `curl | bash`）时不会提问，这时必须传 `--domain`。
  - 已在 104 上测过：不给参数也不在终端里运行时会报错；交互模式下按 certbot、builtin、existing 三种选择，分别问了该问的问题；带着已有设置重跑时没有出现任何提问。
- **借鉴 certbot 文章（2026-11-18，Zach 提供的 kanda.me 文章）**：
  - **采纳 `--webroot DIR`**：80 端口已经有网站时用。调用 certbot 前，先按 Let's Encrypt 的方式（跟随跳转）自检一次，确认这个目录能从外部访问到。
  - **采纳 `--stop-service NAME`**：在申请和每次续期时短暂停掉占用 80 端口的服务，通过 certbot 的 pre/post hook 实现，certbot 会把 hook 写进续期配置。
  - **采纳 `renew --dry-run`**：新申请证书后，立即演练一次续期。
  - **采纳 `certificates -d`**：按域名查找证书，支持证书名和域名不同的多域名证书。
  - **不采纳手动 cron**：Debian/Ubuntu 的 certbot 包自带 `certbot.timer`，每天跑两次续期检查，再加 cron 是重复的。脚本改为检查这个定时器有没有在运行，没在运行就提示。
  - **104 上的现状（没有改动）**：root 的 crontab 里有一条文章那种每月续期的 cron，和 certbot.timer 重复，但不会出问题。证书的续期配置是 standalone 模式加停/启 nginx 的 hook。
  - **实测**：
    - 按域名查找：部署 `cloud.geshandi.vip` 时，自动找到了 `hy.geshandi.vip` 这张证书。
    - 参数错误时能拦下：在非 certbot 模式下用 webroot、webroot 目录不存在、服务名不存在、webroot 和 stop-service 同时使用。
    - webroot 自检：目录没有被 80 端口的网站提供时，在调用 certbot 之前就拒绝执行，测试文件也已清理。
    - 80 端口被占用时，报错信息给出了三种解决办法。
    - 带着已有设置正常重跑，结果不变。
  - **未测试**：webroot 和 stop-service 的真实签发、新申请证书后的 dry-run（同样需要一台 80 端口空闲或可控的服务器）。
- **80 端口被占用时的交互处理（2026-11-18，Zach 拍板按方案实施）**：
  - **识别占用者**：用 `ss -ltnp` 取进程名和 PID，再从 `/proc/PID/cgroup` 取它所属的 systemd 服务，例如 `nginx.service`。
  - **certbot 模式的菜单**：
    1. 只在 certbot 需要时停掉这个服务，等同 `--stop-service`；
    2. 用网站目录完成验证，等同 `--webroot`，会先自检；
    3. 退出，自己处理，这是默认项。
  - **builtin 模式的菜单**：改用 certbot（接着进入上面的菜单），或退出。
  - **不提供"杀掉进程"**：systemd 管理的进程会被重新拉起，下次续期时端口又会被占，而且占用者通常是正在服务网站的 nginx。
  - **以下情况不提供"停服务"选项**：
    - `docker.service`、`containerd.service`：停掉会连带所有容器；
    - 不归 systemd 管理的进程：每次续期时没法重新启动它。
  - 没有终端时（自动化部署），保持原来的做法：报错退出，并列出可用参数。
  - **修过的问题**：`deploy.sh` 里第一版菜单放在 `CERT_SRC` 赋值之前，在 `set -u` 下报 unbound variable，已挪到证书路径确定之后、邮箱询问之前。
  - **104 实测**（只选"退出"，没有停任何服务）：
    - 两个脚本的菜单都正确识别出 nginx.service；
    - 默认选项、非法输入、目录不存在、builtin 转 certbot 的连环菜单、无终端时的报错都符合预期；
    - 通过菜单选了一个 nginx 没有提供的目录，自检拒绝执行，测试文件已清理；
    - 用真实进程验证：docker-proxy 识别为容器，不提供停服务选项；普通 bash 进程识别为非 systemd 进程；
    - 正常重跑不会弹出菜单，设置文件 md5 不变，4 个服务都在运行。
