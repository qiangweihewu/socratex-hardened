import net from 'node:net';
import http from 'node:http';
import { TLSSocket, createSecureContext } from 'node:tls';
import { lookup } from 'node:dns/promises';
import { ssl } from 'utilitas';
import { route } from './web.mjs';

// Only globally routable unicast addresses are eligible for proxy egress.
export function isPublicAddress(address) {
    if (net.isIPv4(address)) {
        const [a, b, c] = address.split('.').map(Number);
        return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
            (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
            (a === 203 && b === 0 && c === 113));
    }
    // Restrict IPv6 to 2000::/3; excludes mapped IPv4, ULA, link-local,
    // multicast, NAT64 and unspecified/loopback addresses.
    if (!net.isIPv6(address) || address.includes('%')) return false;
    const first = parseInt(address.split(':')[0], 16);
    if (!Number.isFinite(first) || first < 0x2000 || first > 0x3fff) return false;
    const normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1);
    const [left, right] = normalized.split('::');
    const start = left ? left.split(':') : [];
    const end = right ? right.split(':') : [];
    const groups = right !== undefined ? [...start, ...Array(8 - start.length - end.length).fill('0'), ...end] : start;
    const second = parseInt(groups[1], 16);
    return !(first === 0x2001 && (second < 0x200 || second === 0xdb8))
        && first !== 0x2002 && !(first === 0x3fff && second < 0x1000);
}

const RAW = Symbol('raw');
// Byte-for-byte the same 404 the local web routes send for an unknown path,
// used to answer unauthenticated CONNECTs in probe-resistance mode.
const notFoundRaw = () => `HTTP/1.1 404 Not Found\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nDate: ${new Date().toUTCString()}\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nNot Found\r\n0\r\n\r\n`;
const notFound = res => { res.writeHead(404, { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', Connection: 'close' }); res.end('Not Found'); };
function fail(code, message) { return Object.assign(new Error(message), { status: code }); }
// Short-lived lookup cache with in-flight coalescing. getaddrinfo runs on the
// small libuv threadpool, so repeated lookups queue up under load. Failures
// are never cached; the address policy is re-applied on every use.
export function resolver({ dnsCacheTtl = 60000, dnsCacheSize = 4096 } = {}) {
    const cache = new Map();
    return async host => {
        const key = host.toLowerCase(), hit = cache.get(key), now = Date.now();
        if (hit && (hit.pending || hit.expires > now)) return hit.pending || hit.addresses;
        const pending = lookup(host, { all: true, verbatim: true });
        cache.set(key, { pending });
        try {
            const addresses = await pending;
            cache.delete(key); // Re-insert to keep Map order roughly LRU.
            if (dnsCacheTtl > 0) cache.set(key, { addresses, expires: Date.now() + dnsCacheTtl });
            while (cache.size > dnsCacheSize) cache.delete(cache.keys().next().value);
            return addresses;
        } catch (err) { cache.delete(key); throw err; }
    };
}
async function destination(hostname, options, resolve) {
    const host = hostname.replace(/^\[|\]$/g, '');
    const addresses = net.isIP(host) ? [{ address: host, family: net.isIP(host) }] : await resolve(host);
    if (!addresses.length || (!options.allowPrivateNetworks && addresses.some(x => !isPublicAddress(x.address)))) {
        throw fail(403, 'Destination denied');
    }
    // Only these exact checked addresses are ever dialed; no second DNS lookup.
    return addresses;
}
// Happy Eyeballs (RFC 8305) over the checked addresses: families alternate,
// a new attempt starts every `delay` ms without aborting slower earlier ones,
// and the first established socket wins. A dead IPv6 route no longer stalls
// the whole connect timeout, and high-RTT links are not cut off early.
export function connectAny(addresses, { port, localAddress, timeout, delay = 250 }) {
    const family = localAddress ? net.isIP(localAddress) : 0;
    const usable = family ? addresses.filter(x => x.family === family) : addresses;
    const order = [], first = usable[0]?.family;
    const a = usable.filter(x => x.family === first), b = usable.filter(x => x.family !== first);
    for (let i = 0; i < Math.max(a.length, b.length); i++) { if (a[i]) order.push(a[i]); if (b[i]) order.push(b[i]); }
    return new Promise((resolve, reject) => {
        if (!order.length) return reject(fail(502, 'No usable address'));
        const pending = new Set(); let next = 0, done = false, stagger;
        const finish = (err, winner) => {
            if (done) return; done = true; clearTimeout(stagger); clearTimeout(deadline);
            for (const socket of pending) if (socket !== winner) socket.destroy();
            err ? reject(err) : resolve(winner);
        };
        const deadline = setTimeout(() => finish(fail(502, 'Connect timed out')), timeout);
        const attempt = () => {
            clearTimeout(stagger);
            if (done || next >= order.length) return;
            const { address, family } = order[next++];
            const socket = net.createConnection({ host: address, family, port, localAddress });
            pending.add(socket);
            const onError = () => {
                pending.delete(socket); socket.destroy();
                if (next < order.length) attempt(); else if (!pending.size) finish(fail(502, 'Connect failed'));
            };
            socket.on('error', onError);
            socket.once('connect', () => { socket.off('error', onError); pending.delete(socket); socket.setNoDelay(true); finish(null, socket); });
            if (next < order.length) stagger = setTimeout(attempt, delay);
        };
        attempt();
    });
}
function credentials(value) {
    const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(value || '');
    if (!match) return null;
    const decoded = Buffer.from(match[1], 'base64').toString('utf8');
    const split = decoded.indexOf(':');
    return split < 0 ? null : [decoded.slice(0, split), decoded.slice(split + 1)];
}
function headers(original) {
    const result = { ...original };
    for (const name of (original.connection || '').split(',')) delete result[name.trim().toLowerCase()];
    for (const name of ['connection', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']) delete result[name];
    return result;
}

export default class Socratex extends net.Server {
    constructor(options = {}) {
        super();
        for (const name of ['upstream', 'intercept', 'injectData', 'injectResponse']) {
            if (options[name]) throw new Error(`${name} is unsupported by the hardened transport`);
        }
        options = { headerTimeout: 15000, idleTimeout: 60000, connectTimeout: 10000, maxConnections: 4096, realm: 'proxy', tunnelIdleTimeout: 600000, keepAliveDelay: 30000, ...options };
        // The realm is visible to anyone probing the port; keep it generic.
        if (typeof options.realm !== 'string' || !/^[\x20-\x21\x23-\x5b\x5d-\x7e]{1,64}$/.test(options.realm)) throw new Error('realm must be 1-64 printable ASCII characters without quotes or backslashes');
        const challenge = `Basic realm="${options.realm}"`;
        // Probe resistance (after Caddy forwardproxy): unauthenticated traffic
        // never sees a 407, so the port looks like a plain web server. Clients
        // must send credentials preemptively; browsers can trigger the login
        // prompt once by visiting http://<secret domain>/ through the proxy.
        const stealth = options.probeResistance ? { domain: String(options.probeResistance.domain || '').toLowerCase() } : null;
        const challengeFor = host => !stealth || (!!stealth.domain && String(host || '').toLowerCase() === stealth.domain);
        this.connections = {};
        const resolve = resolver(options);
        const dial = (addresses, port, localAddress) => connectAny(addresses, { port, localAddress, timeout: options.connectTimeout, delay: options.connectAttemptDelay });
        // Build the TLS context once (not per connection): avoids re-parsing
        // the key/chain on every handshake and keeps session-ticket keys stable
        // so clients can resume. Pass the same `ticketKeys` to every cluster
        // worker so tickets survive landing on a different worker.
        let context, contextSource;
        const secureContext = async () => {
            const source = options.tls || await ssl.getCert();
            if (!context || contextSource?.key !== source.key || contextSource?.cert !== source.cert) {
                const { ticketKeys, ...rest } = source;
                context = createSecureContext({ ...rest, ...(ticketKeys || options.ticketKeys ? { ticketKeys: ticketKeys || options.ticketKeys } : {}) });
                contextSource = { key: source.key, cert: source.cert };
            }
            return context;
        };
        this.maxConnections = options.maxConnections;
        const parser = http.createServer({ maxHeaderSize: 16384 });
        parser.setMaxListeners(0);
        parser.headersTimeout = options.headerTimeout;
        parser.requestTimeout = options.idleTimeout;
        parser.keepAliveTimeout = 5000;
        parser.maxRequestsPerSocket = 100;
        const authenticate = async req => {
            const pair = credentials(req.headers['proxy-authorization']);
            return !!(pair && typeof options.basicAuth === 'function' && await options.basicAuth(...pair, req.socket));
        };
        const answer = (res, status, body = '') => {
            res.writeHead(status, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', Connection: 'close', ...(status === 407 ? { 'Proxy-Authenticate': challenge } : {}) });
            res.end(body);
        };
        parser.on('request', async (req, res) => {
            let upstream;
            try {
                if (req.url.startsWith('/')) {
                    const result = await route(req.method, req.url, req.httpVersion, req);
                    const [status, ...extra] = result.status.split('\r\n');
                    const responseHeaders = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', Connection: 'close' };
                    for (const line of extra) { const i = line.indexOf(':'); if (i > 0) responseHeaders[line.slice(0, i)] = line.slice(i + 1).trim(); }
                    res.writeHead(Number(status.split(' ')[1]), responseHeaders); res.end(result.body); return;
                }
                let target; try { target = new URL(req.url); } catch { /* Rejected below. */ }
                if (!await authenticate(req)) return challengeFor(target?.hostname) ? answer(res, 407) : notFound(res);
                if (!target) throw fail(400, 'Invalid target');
                if (stealth?.domain && target.hostname.toLowerCase() === stealth.domain) return answer(res, 200, 'Proxy authentication OK');
                if (target.protocol !== 'http:' || target.username || target.password || target.hash) throw fail(400, 'Invalid target');
                const addresses = await destination(target.hostname, options, resolve);
                if (req.destroyed || res.destroyed) return;
                const outgoing = headers(req.headers); outgoing.host = target.host;
                const localAddress = typeof options.tcpOutgoingAddress === 'function' ? await options.tcpOutgoingAddress(req, req.socket) : undefined;
                const connection = await dial(addresses, Number(target.port) || 80, localAddress);
                if (req.destroyed || res.destroyed) return connection.destroy();
                upstream = http.request({ createConnection: () => connection, method: req.method, path: target.pathname + target.search, headers: outgoing }, remote => {
                    res.writeHead(remote.statusCode, headers(remote.headers)); remote.pipe(res);
                });
                upstream.setTimeout(options.idleTimeout, () => upstream.destroy());
                upstream.on('error', () => { if (!res.headersSent) answer(res, 502); else res.destroy(); });
                req.on('aborted', () => upstream.destroy()); res.on('close', () => upstream.destroy());
                req.pipe(upstream);
            } catch (err) { answer(res, err.status || 502); }
        });
        parser.on('connect', async (req, socket, head) => {
            socket.pause();
            let remote, rejected = false;
            const reject = status => { if (rejected) return; rejected = true; if (!socket.destroyed) socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\n${status === 407 ? `Proxy-Authenticate: ${challenge}\r\n` : ''}Content-Length: 0\r\n\r\n`); };
            try {
                if (!await authenticate(req)) {
                    if (challengeFor(req.url.replace(/:[0-9]*$/, '').replace(/^\[|\]$/g, ''))) return reject(407);
                    rejected = true; return socket.end(notFoundRaw());
                }
                if (!/^(?:\[[0-9a-fA-F:.]+\]|[^\s/:@?#]+):[0-9]+$/.test(req.url)) throw fail(400);
                const target = new URL(`http://${req.url}`);
                const port = Number(req.url.slice(req.url.lastIndexOf(':') + 1));
                if (port < 1 || port > 65535) throw fail(400);
                const addresses = await destination(target.hostname, options, resolve);
                if (socket.destroyed) return;
                const localAddress = typeof options.tcpOutgoingAddress === 'function' ? await options.tcpOutgoingAddress(req, socket) : undefined;
                remote = await dial(addresses, port, localAddress);
                if (socket.destroyed) return remote.destroy();
                // Established tunnels may legitimately sit idle (WebSocket, push,
                // IM). Use the longer tunnel timeout on every layer, and TCP
                // keepalive so dead peers are still detected.
                const client = socket[RAW] || socket;
                for (const s of new Set([socket, client, remote])) s.setTimeout(options.tunnelIdleTimeout, () => s.destroy());
                client.setKeepAlive(true, options.keepAliveDelay); remote.setKeepAlive(true, options.keepAliveDelay);
                remote.on('error', () => socket.destroy()); remote.on('close', () => socket.destroy());
                socket.on('close', () => remote.destroy()); socket.on('error', () => remote.destroy());
                socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                if (head.length) remote.write(head);
                socket.pipe(remote); remote.pipe(socket); socket.resume();
            } catch (err) { reject(err.status || 502); }
        });
        parser.on('clientError', (_, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'));
        this.on('connection', async raw => {
            const id = `${raw.remoteAddress}:${raw.remotePort}`;
            this.connections[id] = raw;
            raw.on('error', () => {});
            raw.setNoDelay(true);
            raw.setTimeout(options.idleTimeout, () => raw.destroy());
            const timer = setTimeout(() => raw.destroy(), options.headerTimeout); timer.unref();
            raw.once('close', () => { clearTimeout(timer); delete this.connections[id]; });
            try {
                const socket = options.https ? new TLSSocket(raw, { isServer: true, secureContext: await secureContext() }) : raw;
                if (socket !== raw) socket[RAW] = raw;
                socket.on('error', () => raw.destroy());
                socket.setTimeout(options.idleTimeout, () => socket.destroy());
                parser.emit('connection', socket);
                socket.once('data', () => { /* Parser enforces the remaining header deadline. */ });
                // A strict initial-header deadline also covers slow TLS handshakes.
                const clear = req => { if (req.socket === socket) { clearTimeout(timer); parser.off('request', clear); parser.off('connect', clear); } };
                parser.on('request', clear); parser.on('connect', clear);
                socket.once('close', () => { parser.off('request', clear); parser.off('connect', clear); });
            } catch { raw.destroy(); }
        });
    }
    getConnections() { return this.connections; }
}
