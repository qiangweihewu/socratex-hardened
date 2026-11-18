# Socratex

This is a security-focused fork of [Leask/socratex](https://github.com/Leask/socratex). The original project and author retain their MIT license attribution.

Socratex is a Node.js HTTPS forward proxy for standard HTTP proxy clients. It terminates TLS **to the proxy**, then tunnels CONNECT traffic unchanged; it does not decrypt destination HTTPS traffic or require a MITM certificate.

This local hardening revision changes authentication and removes unsafe legacy transport features. Read the migration notes before replacing an existing installation.

## Run

Requires Node.js 22 or newer. Install the checked-in dependency versions:

```sh
npm ci
node main.mjs --domain=proxy.example.com --port=8443 \
  --user=myuser --password='a-long-unique-password' \
  --cert=/absolute/path/fullchain.pem --key=/absolute/path/privkey.pem
```

Use a certificate valid for the proxy hostname. Keep TLS certificate verification enabled on clients. Certificate files are read at startup; restart after externally managed renewal. Password arguments may be visible to other local processes; use a trusted host and protect the stored configuration (`~/.socratex.json`, containing credentials and potentially private keys). Startup logs no longer print credentials or token URLs.

If certificate files are omitted, the utilitas ACME integration is used (`scripts/deploy.sh --cert builtin` sets this up). Its issuance/renewal has **not** been validated in this revision; HTTP-01 requires public port 80. Its localhost fallback is a bundled development certificate and must not be used for a trusted public deployment. Prefer externally managed certificates and the explicit `--cert`/`--key` options.

For isolated local testing only:

```sh
node main.mjs --http --address=127.0.0.1 --port=8080 --user=test --password=test-only
npm test
```

HTTP-only mode sends proxy credentials without TLS. Never use it across an untrusted network.

## One-step server deployment (Debian/Ubuntu)

`scripts/deploy.sh` installs Socratex as a hardened systemd service on a Debian/Ubuntu server (x64 or arm64) and prints ready-to-paste client configuration. Point the domain's DNS record at the server and open inbound TCP 443 (and 80 if a certificate is to be requested) first. Download the script, read it, then run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/qiangweihewu/socratex-hardened/main/scripts/deploy.sh
sudo bash deploy.sh
```

Run in a terminal, it asks for the domain, the certificate source (existing files, a new certbot certificate, or the built-in ACME client; see *Certificates*) and, only when certbot is about to request a certificate, an optional e-mail. All other settings have defaults. For unattended installs pass everything as options instead; without a terminal nothing is asked and `--domain` is required:

```sh
sudo bash deploy.sh --domain proxy.example.com --cert certbot --email you@example.com
```

What it does: installs official Node.js 22 (SHA-256 verified) unless Node 22+ is present, deploys the repository at `--ref` (default `main`) to `/opt/socratex`, sets up the certificate (see *Certificates* below), generates random credentials, and runs the service as the unprivileged `socratex` user with systemd sandboxing. Credentials live in `/etc/socratex/socratex.env` (root-only) and reach the process through the environment, so they never appear in the process list. A health check then confirms an authenticated tunnel works and an unauthenticated one is rejected.

It finally prints a NaïveProxy share link (`naive+https://…`, also as a QR code) for NekoBox/husi/Exclave/v2rayN, a standard `https://user:pass@host:port` proxy URL, a Clash Meta/mihomo `proxies` entry, and a Shadowrocket import link (`https://user:pass@host:port?peer=host&method=auto&fingerprint=Safari26_3#name`). The naive link format follows the NekoBox and v2rayN parsers. Shadowrocket rejects `naive+https://`; its link format was taken from a node Shadowrocket (macOS) itself exported, and the script's output is byte-identical to that export.

Useful options: `--stealth` (probe resistance; also prints the browser secret link), `--port`, `--user`/`--password`, `--cert existing|certbot|builtin` and `--cert-file`/`--key-file` (see below), `--tune-network` (BBR and TCP buffers), `--ref`, `--name`. Re-running updates the code and keeps credentials; `sudo bash deploy.sh --show` prints the links again; `--uninstall [--purge]` removes it. Tested on Ubuntu 24.04 (arm64, systemd container) with a custom certificate (install, re-run with `--stealth`, `--show`, `--uninstall --purge`), and on a live Debian 12 x64 server that already ran nginx on 80/443: deployed on port 8443 reusing the host's existing Let's Encrypt certificate, upgraded by re-running with no arguments (settings kept), and verified from the public internet with curl and the official naive client over HTTPS (140 downloads; one transient TLS error at the destination). Fresh certificate issuance via certbot standalone has not been exercised yet.

`main.mjs` also reads `SOCRATEX_USER`, `SOCRATEX_PASSWORD` and `SOCRATEX_SECRET_DOMAIN` from the environment when the matching options are not given.

### Certificates

Both deploy scripts ask on first install (or take `--cert MODE`) where the certificate comes from, after asking for the domain if `--domain` was not given. The choice is saved and reused on re-runs, and `--cert` switches it later.

| `--cert` | What happens | Renewal | Needs |
|---|---|---|---|
| `existing` | Uses files already on the server: by default `/etc/letsencrypt/live/DOMAIN/fullchain.pem` (or, if that does not exist, the certbot lineage that `certbot certificates -d DOMAIN` reports, e.g. a multi-domain certificate with another name) and `privkey.pem` next to it, or any `--cert-file` / `--key-file` (absolute paths, `[A-Za-z0-9._/@+-]` only) | Under `/etc/letsencrypt/live/`: a certbot deploy hook for that lineage. Elsewhere (acme.sh, a corporate CA, …): a systemd path unit that copies the files again whenever they change | Nothing extra |
| `certbot` | Requests a Let's Encrypt ECDSA certificate (`--cert-name DOMAIN`) if the domain has none yet, then runs `certbot renew --dry-run` to prove renewal works, then behaves like `existing`. Port 80 already taken by a web server? `--webroot DIR` answers the challenge through it (the script first checks that `http://DOMAIN/.well-known/acme-challenge/` is served from DIR, following redirects like Let's Encrypt does); `--stop-service nginx` instead stops that service around issuance and every renewal (certbot stores the hooks) | certbot's systemd timer (`certbot.timer`, installed by the package; the script warns if it is not active, so no cron job is needed) plus the deploy hook | Port 80 free, or `--webroot` / `--stop-service` |
| `builtin` | The proxy obtains and renews the certificate itself: Socratex's ACME client (utilitas, HTTP-01), Caddy's automatic HTTPS for naive, and sing-box's ACME certificate provider for AnyTLS. Caddy and sing-box share one certmagic store (`/var/lib/sx-proto/caddy`), so they get one certificate between them | Automatic | Port 80 free (Socratex keeps it open permanently; Caddy and sing-box only during challenges, or TLS-ALPN when naive/AnyTLS listens on 443) |

Without a choice and without a terminal, `existing` is used when `/etc/letsencrypt/live/DOMAIN/fullchain.pem` exists, otherwise `certbot`. Every file-based certificate must cover the domain, and its private key must match: both are checked before anything is changed, and a failed check leaves the previous settings in place. The sync step re-checks the pair, so a half-written renewal is never installed. When certbot or `builtin` needs port 80 and another program holds it, the script names that program (process, PID and its systemd service). Run in a terminal, it then offers a menu. For certbot the choices are: stop that service only while certbot needs the port (the same as `--stop-service`, offered only for a systemd service and never for `docker.service` / `containerd.service`, since stopping those would stop every container), use the web server's document root (the same as `--webroot`), or exit and free the port yourself. Exit is the default. For `builtin`, which keeps the port permanently, the choices are: switch to certbot, or exit. The script never kills the program: a systemd service would be restarted anyway, and the port would be busy again at the next renewal. Without a terminal, the script stops and names the options as flags. Installs from before this option (`certbot`, or the old `custom`) carry over unchanged.

Tested on the live Debian 12 server: the upgrade from the old modes, `existing` with the default Let's Encrypt path, `existing` with a custom path (the path unit copied a changed certificate and restarted the services; a mismatched key was refused and nothing was restarted), the interactive menu, `builtin` being refused while nginx holds port 80 (nothing changed), and the port-80 menus (nginx was recognised as `nginx.service`; the exit, invalid-input, missing-directory and builtin-to-certbot paths were checked; a webroot that nginx does not serve was refused; a `docker-proxy` listener was recognised as a container and not offered for stopping). The `builtin` configurations pass `sing-box check` and `caddy validate`. **Not yet tested**: actual ACME issuance with `certbot` and `builtin`. That server's ports 80 and 443 belong to nginx, so issuance needs a server where they are free. Socratex's built-in client registers the contact `i@DOMAIN` (hard-coded in utilitas).

### AnyTLS, ShadowTLS and NaïveProxy servers

`scripts/deploy-protocols.sh` deploys three other proxy protocols next to (or instead of) Socratex, using upstream server implementations rather than code from this repository:

| Protocol | Server | Default port | Client config printed |
|---|---|---|---|
| NaïveProxy | Caddy with [klzgrad/forwardproxy](https://github.com/klzgrad/forwardproxy) (the official naive server: HTTP/2, `probe_resistance`, decoy static site) | 443 | `naive+https://` link and QR code, Shadowrocket `https://…?peer=` link, mihomo |
| AnyTLS | [sing-box](https://github.com/SagerNet/sing-box) `anytls` inbound | 8443 | `anytls://` link and QR code ([URI format](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)), mihomo, sing-box outbound |
| ShadowTLS v3 | sing-box `shadowtls` inbound (strict mode) in front of Shadowsocks 2022 (`2022-blake3-aes-128-gcm`, TCP only) | 9443 | Shadowrocket `ss://…?shadow-tls=` link and QR code, mihomo (`ss` + `shadow-tls` plugin), sing-box outbounds; no cross-client standard link exists |

```sh
curl -fsSLO https://raw.githubusercontent.com/qiangweihewu/socratex-hardened/main/scripts/deploy-protocols.sh
sudo bash deploy-protocols.sh                                         # asks for the domain and certificate source
sudo bash deploy-protocols.sh --domain proxy.example.com --cert existing   # unattended
sudo bash deploy-protocols.sh --protocols anytls,shadowtls --domain proxy.example.com   # pick a subset
```

Both binaries come from the projects' latest GitHub releases and are checked against the SHA-256 digest GitHub publishes for each asset. Generated configurations are validated (`sing-box check`, `caddy validate`) before anything is replaced. AnyTLS and NaïveProxy need a certificate for the domain, chosen with the same `--cert` modes as `deploy.sh` (see *Certificates* below). ShadowTLS needs no certificate: it borrows the TLS 1.3 handshake of `--shadowtls-sni` (default `www.microsoft.com`, checked for TLS 1.3 from the server), and clients must use that same SNI. Both services run as the unprivileged `sx-proto` user with the same systemd sandboxing as Socratex. Outbound connections to loopback, private, CGNAT and link-local (cloud metadata) addresses are refused. Settings and passwords live in `/etc/sx-proto/settings.env` (root-only); re-running updates both binaries and keeps them (`--regenerate` makes new passwords). `--show` prints the client configuration again and `--uninstall [--purge]` removes everything.

After installing, the script drives each protocol end to end with a temporary sing-box client on loopback, fetches a page through naive, and checks what an unauthenticated visitor sees.

Limits: the official Caddy build is x86-64 only, so on arm64 deploy `--protocols anytls,shadowtls` (Socratex itself also speaks the naive protocol). Caddy negotiates HTTP/2, so after importing the naive node into Shadowrocket turn its HTTP2 switch on (or set ALPN to `http/1.1`); the import link cannot carry that switch yet. Shadowrocket's ShadowTLS link is `ss://` + base64url(`method:password@host:port`) + `?shadow-tls=` + base64url(`{"version":"3","host":…,"password":…}`), reconstructed from a Shadowrocket export and matched byte for byte. AnyTLS has no fallback: an unauthenticated client completes TLS and is then disconnected, which the AnyTLS FAQ lists as a known weakness.

Tested on a live Debian 12 x64 server alongside nginx and Socratex (ports 8444/8445/8446, reusing an existing certificate). From the public internet: each protocol fetched `generate_204` 20/20 times and downloaded a 31.7 MB file three times with a matching SHA-256; private and metadata addresses were refused. Probes saw a plain Caddy site (unauthenticated `CONNECT` gets 308, never 407) on naive, Microsoft's real certificate and site on ShadowTLS for any SNI, and a closed connection after TLS on AnyTLS. Re-running, dropping and re-adding a protocol, the renewal hook, and uninstall plus reinstall (credentials kept) were also exercised. Not yet tested: fresh certbot issuance, arm64, and `--address` without a domain.

## Client configuration

The required protocol is **HTTPS forward proxy** (TLS to the proxy), with the proxy domain, port, Basic username and password. Preserve normal server certificate validation. No VPN, MITM certificate, or destination TLS interception is required by this server.

For Shadowrocket, `scripts/deploy.sh --show` prints an import link in the format Shadowrocket itself exports (`https://user:pass@host:port?peer=host&method=auto&fingerprint=Safari26_3#name`); keep the node's HTTP2 switch off and ALPN at its default, since this server speaks HTTP/1.1 and negotiates no ALPN. Import was confirmed in Shadowrocket on macOS; end-to-end browsing through it has not been reported yet.

A protocol check with curl (use your own trusted hostname and credentials):

```sh
curl --proxy https://proxy.example.com:8443 --proxy-user 'myuser:password' https://example.com/
```

PAC is optional. `/proxy.pac?token=YOUR_PAC_TOKEN` and `/wpad.dat?token=YOUR_PAC_TOKEN` return a proxy configuration; `--token` supplies the PAC download token, otherwise the existing/generated token is stored in the local configuration. A PAC token **only** authorizes the download. Clients still need Basic proxy authentication. PAC URLs can leak through browser/access logs; treat them as secrets. `/`, unknown local routes, and the PAC/console routes without a valid token all return the same plain 404, so a probe cannot tell them apart or identify the software; `/console` is disabled by default. Proxy credentials and tokens are compared in constant time. The 407 challenge uses `Basic realm="proxy"`; change it with `--realm` (library: `realm`, 1–64 printable ASCII characters, no quotes or backslashes).

## Security defaults and migration

- Each HTTP proxy request and CONNECT requires `Proxy-Authorization: Basic …`. Passwords may contain colons. Origin `Authorization` is preserved; proxy credentials and hop-by-hop headers are removed before forwarding.
- Downloading PAC no longer authorizes an IP address. Previous IP authorization state is ignored. Token-only PAC setups must configure Basic credentials; there is no legacy shared-IP opt-in.
- CONNECT uses Node's HTTP parser and then a byte stream with pipe backpressure. Initial CONNECT payload bytes are preserved. Request headers are capped at 16 KiB, initial headers/TLS handshake at 15 seconds, inactive connections at 60 seconds, and concurrent connections at 256 by default.
- Private, loopback, link-local, metadata, multicast, reserved/documentation IPv4 and non-global IPv6 destinations are denied. All DNS answers are checked and the TCP connection uses an already checked IP. This is an application guard, not a substitute for an outbound firewall or an assurance that every reachable public service is safe. Private network access is only available through the explicit library option `allowPrivateNetworks: true`; the CLI does not expose it.
- Console access cannot use the PAC token or proxy password. The CLI leaves the console disabled. Embedders may separately set `_socratex.consoleToken`; this internal console mechanism is not a stable public API.
- The former `upstream`, `intercept`, `injectData`, and `injectResponse` library options are explicitly rejected. Their old raw-buffer/Session semantics cannot safely be retained by the new parsed HTTP transport; upstream proxy chaining requires a separately implemented and tested protocol adapter. No traffic camouflage or undetectability claim is made.
- `tcpOutgoingAddress` remains available, but now receives `(IncomingMessage, socket)` and may return/resolve a local IP. `basicAuth` similarly receives `(user, password, socket)`. `getConnections()` returns active socket objects keyed by peer address/port; the former `Session` API is removed. `bypass` country-learning no longer modifies PAC routes.

## Library

```js
import Socratex from './index.mjs';
const proxy = new Socratex({
  basicAuth: async (user, password) => user === 'example' && password === 'secret',
  // https: true, tls: { key: keyBuffer, cert: certBuffer },
});
proxy.listen(8080, '127.0.0.1');
```

No `basicAuth` callback means all proxy traffic receives 407. Library mode is plaintext unless `https: true` is explicitly supplied. Optional limits: `headerTimeout`, `connectTimeout`, `idleTimeout` (milliseconds), and `maxConnections` (default 4096 per process). Performance options: `ticketKeys` (48-byte Buffer; share it across processes so TLS sessions resume on any of them), `dnsCacheTtl` (milliseconds, default 60000; `0` disables), `dnsCacheSize` (default 4096) and `connectAttemptDelay` (Happy Eyeballs stagger, default 250 ms). Configuration endpoints use the existing `_socratex` integration; library users without it can still use proxy requests.

## Probe resistance (optional)

`--stealth` makes unauthenticated or wrongly authenticated proxy requests receive the same plain 404 as an unknown path, instead of a 407 challenge, so a port scan sees an ordinary web server (design after Caddy forwardproxy `probe_resistance`). Your client must send Basic credentials **preemptively**; curl does. Add `--secret-domain=<random-name.example>` so browsers can still log in: visit `http://<random-name.example>/` through the proxy once, which is the only request that returns 407, then the browser reuses the credentials. Keep that name secret; it is only matched in the proxy request, never resolved. Library: `probeResistance: true` or `{ domain }`. Not yet verified with Shadowrocket.

## NaïveProxy clients

Socratex speaks the NaïveProxy padding protocol (Variant1) on HTTP/1.1 CONNECT, so NaïveProxy-compatible clients (the official `naive` client, NekoBox, husi, Exclave, v2rayN and similar) can use it as their HTTPS proxy server, for example `naive --listen=socks://127.0.0.1:1080 --proxy=https://user:pass@proxy.example.com`. Only clients that send the `padding`/`padding-type-request` headers get padded tunnels (the first 8 frames in each direction); other clients see the unchanged `200 Connection Established` stream. Library option `naivePadding: false` disables it. NaïveProxy clients send credentials preemptively, so they also work with `--stealth`. HTTP/2 multiplexing is not supported yet, so each tunnel uses its own TLS connection (resumed via session tickets).

Verified with naive v154.0.8037.49-5 (macOS arm64) through a local plain-HTTP Socratex: the client logged `negotiated padding type: Variant1`, and 20/20 1 MiB downloads matched their SHA-256, with and without `--stealth`; with `naivePadding: false` it fell back to `None` and still worked. The HTTPS-to-proxy variant was not run end to end (it needs a client-trusted certificate), but the padding code path is the same.

## Performance

- TLS: one secure context is built per process and reused, so certificates are not re-parsed per connection and clients can resume sessions. `main.mjs` generates session-ticket keys in memory at startup and shares them with all cluster workers; they rotate on each full restart. Prefer an ECDSA P-256 certificate: server handshakes cost far less CPU than RSA.
- DNS: lookups are cached (60 s) and concurrent lookups for one host share a single query. The private-address policy is still checked on every request, and only the checked addresses are dialed. `main.mjs` sets `UV_THREADPOOL_SIZE=16` for workers unless already set.
- Long-lived tunnels: an established CONNECT tunnel uses `tunnelIdleTimeout` (default 10 minutes) instead of `idleTimeout` (60 s), so quiet WebSocket, push or chat connections are not cut at 60 s; TCP keepalive (`keepAliveDelay`, default 30 s) still detects dead peers.
- Connect: all checked addresses are tried Happy Eyeballs style (alternating IPv6/IPv4, a new attempt every 250 ms without aborting slower ones), so an unreachable IPv6 route no longer stalls the full connect timeout. `TCP_NODELAY` is enabled on both legs.
- Host (Linux): raise `ulimit -n` above `maxConnections` × 2 × worker count, and consider `net.ipv4.tcp_congestion_control=bbr` with `net.core.default_qdisc=fq`, larger `net.core.rmem_max`/`wmem_max`, `net.core.somaxconn=4096` and `net.ipv4.tcp_slow_start_after_idle=0`.
- For very high TLS throughput, terminate TLS in front (for example HAProxy `mode tcp`) and run Socratex with `--http --address=127.0.0.1`; never expose the HTTP-only listener publicly.

## Docker

Builds the local source with the lockfile, Node 22 Alpine and a non-root user. The explicit port avoids privileged port requirements; it does not fetch a published socratex binary.

```sh
docker build -t socratex-local .
docker volume create socratex-home
docker run --rm -p 8443:8080 \
  -v socratex-home:/home/node \
  -v /absolute/path/certs:/certs:ro \
  socratex-local --port=8080 --domain=proxy.example.com \
  --user=myuser --password='a-long-unique-password' \
  --cert=/certs/fullchain.pem --key=/certs/privkey.pem
```

The named volume persists `/home/node/.socratex.json`; bind mounts must be writable by the image's `node` user (UID 1000). Certificate files must be readable by that user. Prefer external renewal with explicit certificate files; automatic ACME in this non-root container has not been validated and also requires routing public port 80 correctly. Restart after replacing certificate files. Actual container startup and public certificate issuance must be validated in your deployment environment.

## Verification

`npm test` requires the local `openssl` command and runs isolated loopback HTTP/TCP/TLS tests (a temporary self-signed certificate is explicitly trusted with verification enabled): credential separation, PAC authorization isolation, destination blocking, fragmented CONNECT with binary data and asynchronous authentication, initial header timeouts, HTTP forwarding, and authenticated CONNECT inside verified outer TLS. It uses no external proxy target. `npm run test:external` retains the original manual internet-dependent script; it is not the hardening acceptance suite.

License: MIT.

The dependency lock includes targeted overrides inside utilitas only: mathjs 15.2.0, file-type 21.3.4 and uuid 11.1.1. These cross their previous major ranges to fix the reported advisories without upgrading utilitas or unrelated direct dependencies. Compatibility smoke tests cover utilitas BigNumber arithmetic, UUID creation/validation, PNG identification, unknown-file handling and configuration read/write, alongside the proxy suite. The suite passes on Node 22 and the local Node 25 runtime. An official-registry production dependency audit reports zero known vulnerabilities at verification time; that is not a general security guarantee.
