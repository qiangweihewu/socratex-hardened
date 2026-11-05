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

If certificate files are omitted, the pre-existing utilitas certificate/ACME integration remains in use. Its issuance/renewal has **not** been validated in this revision; HTTP-01 requires public port 80. Its localhost fallback is a bundled development certificate and must not be used for a trusted public deployment. Prefer externally managed certificates and the explicit `--cert`/`--key` options.

For isolated local testing only:

```sh
node main.mjs --http --address=127.0.0.1 --port=8080 --user=test --password=test-only
npm test
```

HTTP-only mode sends proxy credentials without TLS. Never use it across an untrusted network.

## Client configuration

The required protocol is **HTTPS forward proxy** (TLS to the proxy), with the proxy domain, port, Basic username and password. Preserve normal server certificate validation. No VPN, MITM certificate, or destination TLS interception is required by this server.

For Shadowrocket, use those standard parameters; exact UI steps and import URLs are intentionally omitted. This revision has not been tested on a real Shadowrocket device. Desktop/mobile compatibility must be checked on the intended client before deployment.

A protocol check with curl (use your own trusted hostname and credentials):

```sh
curl --proxy https://proxy.example.com:8443 --proxy-user 'myuser:password' https://example.com/
```

PAC is optional. `/proxy.pac?token=YOUR_PAC_TOKEN` and `/wpad.dat?token=YOUR_PAC_TOKEN` return a proxy configuration; `--token` supplies the PAC download token, otherwise the existing/generated token is stored in the local configuration. A PAC token **only** authorizes the download. Clients still need Basic proxy authentication. PAC URLs can leak through browser/access logs; treat them as secrets. `/` returns a small ordinary HTTP response, unknown local routes return 404, and `/console` is disabled by default.

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

No `basicAuth` callback means all proxy traffic receives 407. Library mode is plaintext unless `https: true` is explicitly supplied. Optional limits: `headerTimeout`, `connectTimeout`, `idleTimeout` (milliseconds), and `maxConnections`. Configuration endpoints use the existing `_socratex` integration; library users without it can still use proxy requests.

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
