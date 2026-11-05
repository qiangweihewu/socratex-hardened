import net from 'node:net';
import http from 'node:http';
import { TLSSocket } from 'node:tls';
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

function fail(code, message) { return Object.assign(new Error(message), { status: code }); }
async function destination(hostname, options) {
    const host = hostname.replace(/^\[|\]$/g, '');
    const addresses = net.isIP(host) ? [{ address: host, family: net.isIP(host) }]
        : await lookup(host, { all: true, verbatim: true });
    if (!addresses.length || (!options.allowPrivateNetworks && addresses.some(x => !isPublicAddress(x.address)))) {
        throw fail(403, 'Destination denied');
    }
    // Connect to this exact checked address, never perform a second DNS lookup.
    return addresses[0];
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
        options = { headerTimeout: 15000, idleTimeout: 60000, connectTimeout: 10000, maxConnections: 256, ...options };
        this.connections = {};
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
            res.writeHead(status, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', Connection: 'close', ...(status === 407 ? { 'Proxy-Authenticate': 'Basic realm="Socratex"' } : {}) });
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
                if (!await authenticate(req)) return answer(res, 407);
                const target = new URL(req.url);
                if (target.protocol !== 'http:' || target.username || target.password || target.hash) throw fail(400, 'Invalid target');
                const addr = await destination(target.hostname, options);
                if (req.destroyed || res.destroyed) return;
                const outgoing = headers(req.headers); outgoing.host = target.host;
                const localAddress = typeof options.tcpOutgoingAddress === 'function' ? await options.tcpOutgoingAddress(req, req.socket) : undefined;
                upstream = http.request({ hostname: addr.address, localAddress, family: addr.family, port: target.port || 80, method: req.method, path: target.pathname + target.search, headers: outgoing, agent: false }, remote => {
                    res.writeHead(remote.statusCode, headers(remote.headers)); remote.pipe(res);
                });
                const connectTimer = setTimeout(() => upstream.destroy(), options.connectTimeout);
                connectTimer.unref();
                upstream.once('socket', socket => socket.once('connect', () => clearTimeout(connectTimer)));
                upstream.once('close', () => clearTimeout(connectTimer));
                upstream.setTimeout(options.idleTimeout, () => upstream.destroy());
                upstream.on('error', () => { if (!res.headersSent) answer(res, 502); else res.destroy(); });
                req.on('aborted', () => upstream.destroy()); res.on('close', () => upstream.destroy());
                req.pipe(upstream);
            } catch (err) { answer(res, err.status || 502); }
        });
        parser.on('connect', async (req, socket, head) => {
            socket.pause();
            let remote, established = false, rejected = false;
            const reject = status => { if (rejected) return; rejected = true; if (!socket.destroyed) socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\n${status === 407 ? 'Proxy-Authenticate: Basic realm="Socratex"\r\n' : ''}Content-Length: 0\r\n\r\n`); };
            try {
                if (!await authenticate(req)) return reject(407);
                if (!/^(?:\[[0-9a-fA-F:.]+\]|[^\s/:@?#]+):[0-9]+$/.test(req.url)) throw fail(400);
                const target = new URL(`http://${req.url}`);
                const port = Number(req.url.slice(req.url.lastIndexOf(':') + 1));
                if (port < 1 || port > 65535) throw fail(400);
                const addr = await destination(target.hostname, options);
                if (socket.destroyed) return;
                const localAddress = typeof options.tcpOutgoingAddress === 'function' ? await options.tcpOutgoingAddress(req, socket) : undefined;
                remote = net.createConnection({ host: addr.address, localAddress, family: addr.family, port });
                remote.setTimeout(options.connectTimeout, () => remote.destroy());
                remote.once('connect', () => {
                    established = true; remote.setTimeout(options.idleTimeout, () => remote.destroy());
                    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                    if (head.length) remote.write(head);
                    socket.pipe(remote); remote.pipe(socket); socket.resume();
                });
                remote.on('error', () => established ? socket.destroy() : reject(502));
                remote.on('close', () => established ? socket.destroy() : reject(502));
                socket.on('close', () => remote.destroy()); socket.on('error', () => remote.destroy());
            } catch (err) { reject(err.status || 502); }
        });
        parser.on('clientError', (_, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'));
        this.on('connection', async raw => {
            const id = `${raw.remoteAddress}:${raw.remotePort}`;
            this.connections[id] = raw;
            raw.on('error', () => {});
            raw.setTimeout(options.idleTimeout, () => raw.destroy());
            const timer = setTimeout(() => raw.destroy(), options.headerTimeout); timer.unref();
            raw.once('close', () => { clearTimeout(timer); delete this.connections[id]; });
            try {
                const socket = options.https ? new TLSSocket(raw, { isServer: true, ...(options.tls || await ssl.getCert()) }) : raw;
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
