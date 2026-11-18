# 和 nginx 共用 443 端口（2026-11-18，未拍板）

## 起因

Zach 在另一台服务器上部署时，报错 `port 443 is already in use`，占用者是 nginx。这台服务器的 nginx 在 443 上提供网站，同时承载一个 v2ray WebSocket 入口（`/us`）。8443、2083、2096 端口也被 nginx 占着。问题是：能不能通过修改或新增 nginx 配置，让代理和网站共用 443。

## 核心判断

- **可以，用 nginx 的 `stream` 模块配合 `ssl_preread`，按 SNI 在 TCP 层分流。** nginx 不解开 TLS，只读 ClientHello 里的域名，再把整条连接原样转给后端：
  - 网站的域名转给 nginx 自己的 https，监听地址改到 `127.0.0.1:10443`；
  - 代理的域名转给 socratex / naive / anytls；
  - ShadowTLS 借用的 SNI（例如 `www.microsoft.com`）转给 shadowtls。
- **不能在 nginx 的 http 层做反向代理。** NaïveProxy 和 socratex 都是 HTTPS 正向代理，要靠 CONNECT 方法；nginx 的 http 模块不支持 CONNECT，而且会自己终结 TLS，改变 TLS 指纹。
- **每个代理需要一个单独的子域名。** 同一个 SNI 没法分给两个后端。用 ALPN 区分也不可行：Shadowrocket 默认的 ALPN 和浏览器一样，都是 `h2,http/1.1`。
- **stream 配置必须放在 `nginx.conf` 的最外层。** `conf.d/*.conf` 是被 include 在 `http {}` 里面的，放不了 stream。

## 代价

- 代理后端看到的客户端 IP 都是 127.0.0.1。socratex 只在日志里用到客户端地址（`lib/socratex.mjs:246`），所以只影响日志。
- 网站要拿到真实 IP，得在 443 上开 `proxy_protocol`，http 的 listen 也加上 `proxy_protocol`，再配 `real_ip`。socratex 不认 PROXY 协议，所以它的流量要经过一个中间 stream server 把这个头剥掉。
- 新子域名申请证书时，原来 80 端口的 server 在 server 层直接 `return 301`，webroot 方式过不了。需要给新子域名单独加一个 80 端口的 server，里面放 `/.well-known/acme-challenge/`。
- 多了一跳 nginx 转发，开销可以忽略。
- 一个附带的好处：用其他 SNI 或直接用 IP 来探测 443，看到的是真实网站。

## 候选做法

1. 只写文档：README 给出配置样例和步骤，由用户自己改 nginx。
2. 脚本只生成配置片段，并做前置检查：nginx 是否带 `stream_ssl_preread`、内部端口是否空闲。真正修改 nginx 配置由用户自己来。
3. 脚本全自动：备份配置，把 `listen 443` 改成内部端口，写入 stream 配置，然后 `nginx -t`，失败就回滚。风险是各家 nginx 的配置布局差别很大，比如宝塔面板、nginx.org 官方包、Debian 包都不一样。

## 状态

**已拍板（2026-11-18）**：采用第 3 种做法，脚本全自动修改 nginx。Zach 补充要求：nginx 有多个配置文件时，只改必须改的那个；其他文件能不动就不动，必须动时先征得同意。

## 实现（2026-11-18）

- **`scripts/nginx_sni.py`**：独立工具，只用 Python 标准库，安装为 `/usr/local/sbin/sx-nginx-sni`，有 status / plan / add / remove 四个子命令。
  - 自己解析 nginx 实际加载的配置树（跟随 include），找出 http 层所有监听该端口的 `listen`。
  - 只修改两类文件：含这些 `listen` 的文件，以及主 `nginx.conf`（末尾追加一行 include）。其余文件一律不碰。
  - **按 Zach 的要求，每个要改的文件都单独展示 diff、单独确认**。任何一个回答 n，就什么都不改。所以第一次必须在终端里运行；没有终端时直接拒绝，不会擅自修改。
  - 网站移到 `127.0.0.1:10443`。stream 层开启 PROXY 协议，被移动的 server 加上 `set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`，网站仍能拿到访客的真实 IP。代理流量经过一个中转的 stream server，在那里去掉 PROXY 头。
  - **应用改动的步骤**：备份 → `nginx -t` → reload → 等新 worker 接手（`nginx -t` 查不出端口绑定失败，这一步能发现）→ 改动前后各请求一次每个网站并对比 → 任何一步失败就自动回滚。
  - 改过的行都带 `#sx-sni-orig#` 标记并保留原文，追加的行带 `#sx-sni-added#` 标记。卸载时只还原这些行，用户之后在这些文件里做的其他修改不受影响。
  - **遇到以下情况拒绝自动修改，提示手动处理**：`listen` 和其他指令写在同一行、代理域名本身就是 nginx 的网站、nginx 已有自己的 `stream {}` 块、配置里有其他来源的 `real_ip_header`、缺少相关模块、配置里有 Lua 块。
- **`deploy.sh` 接入**：
  - nginx 占着端口时弹出菜单：共享端口 / 换一个端口 / 退出，默认退出；也可以直接传 `--nginx-sni`。
  - 共享时 Socratex 只监听 `127.0.0.1:20443` 起的空闲端口，客户端链接里仍是 443。
  - 重跑时沿用共享设置；`--uninstall` 先把端口还给 nginx。
- **104 实测**：
  - 线上 nginx 只读 `plan`：识别出 5 个配置文件中的 4 个需要改动，线上没有任何变化。
  - 另起一个独立的 nginx 实例，测了以下各项，全部通过：
    - 逐文件拒绝；
    - 全部同意后按 SNI 分流，从外网访问能拿到访客真实 IP；
    - 幂等重跑；
    - 无终端加第二条路由；
    - 各种拒绝情况；
    - 部分移除和全部移除（文件逐字节还原）；
    - reload 时绑定失败自动回滚。
  - deploy.sh 菜单的三条退出路径。
  - 线上 nginx 全程没有改动，也没有 reload。
- **踩过的坑**：
  - reload 是异步的，紧接着探测可能连到旧 worker，所以加了"等新 worker"这一步。
  - 测试端口占用时，不设 `SO_REUSEADDR` 的 bind 会被 TIME_WAIT 连接挡住，`port_free()` 已经改成设置这个选项。
- **未测**：在 nginx 占着 443 的服务器上完整跑一遍 `deploy.sh --nginx-sni`。

## 独立复核与修复（2026-11-18）

派了一个独立 agent 只读复核 `nginx_sni.py` 和 deploy.sh 的改动。它找出的问题都已修复，并在 104 的独立测试 nginx 上复测通过：

1. **软链接被换成普通文件**：Debian 的 `sites-enabled` 下默认是软链接，原来的原子写入会把链接替换掉。改为写到链接指向的真实文件，临时文件名以点开头，`include dir/*` 不会加载它。实测：改完和还原后都仍是软链接。
2. **共用的 listen 片段被替换两次**：多个 server include 同一个 listen 片段时，同一行会被改两次，导致 `remove` 还原失败。改为拒绝自动修改。
3. **跳转地址带上 `:10443`**：nginx 自己生成的跳转（补斜杠、相对路径的 return/rewrite）会带上内部端口。改为在搬走的 server 里加 `port_in_redirect off;`；server 里已经写了这个指令或还监听其他端口时，不加，只给出提示。另外在 plan 里提示：`$server_port` 会变成内部端口。
4. **原本已经在收 PROXY 协议的 443**（前面有负载均衡）：改为拒绝，否则所有网站都会挂。
5. **回滚有缺口**：
   - 动文件之前先写状态文件；
   - 改动期间忽略 SIGINT、SIGHUP、SIGTERM；
   - 任何异常（不限于 Fail）都会回滚；
   - 终端断开时输出不再报错。
   实测：等待期间发 SIGINT 和 SIGHUP，回滚照常完成。
6. **按 IP 区分的虚拟主机**（`listen 1.2.3.4:443`）：改为拒绝，避免多个站点被合并到同一个内部端口。
7. **stream 的 listen 去重**：改为按地址去重，`ipv6only=` 选项合并进去。
8. **`remove` 不够健壮**：`stream.conf` 不存在时不再出错；文件已还原但 reload 失败时，会清掉状态并提示手动 reload。
9. **同一 owner 换了域名，旧路由还留着**：改为每个 owner 只保留一条路由，新的替换旧的。实测通过。

**运维隐患（已在文档和工具里提醒）**：端口共享期间，如果新加的 HTTPS 站点自己写了 `listen 443`（包括 `certbot --nginx` 自动加的），`nginx -t` 能通过，但 reload 时绑不上端口，nginx 下次重启就会起不来。对策：
- `status` 会指出冲突的行；
- `nginx.conf` 里追加的 include 那一行注释写明了新站点应该怎么监听；
- 重跑 deploy.sh 会把这类站点也搬过去，同样逐个文件确认。

**deploy.sh 的两处调整**：
- 用户拒绝修改时，工具的退出码改为 3，和参数错误的退出码 2 区分开；
- 不再共享端口，或者上一次运行在加完路由后中断时，按工具的状态文件把 Socratex 的路由删掉。
