import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import Socratex, { isPublicAddress, connectAny, resolver } from '../lib/socratex.mjs';
import { safeEqual } from '../lib/web.mjs';
const auth = 'Basic ' + Buffer.from('user:pass:word').toString('base64');
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const close = server => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); });
const request = (port, path, extra = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, headers: extra, agent: false }, res => {
        let body = ''; res.on('data', data => body += data); res.on('end', () => resolve({ status: res.statusCode, body }));
    }); req.on('error', reject); req.end();
});
const proxy = options => new Socratex({ basicAuth: async (u, p) => { await new Promise(r => setTimeout(r, 15)); return u === 'user' && p === 'pass:word'; }, ...options });
test('address policy denies nonpublic IPv4 and IPv6', () => {
    for (const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','172.31.0.1','192.168.1.1','100.64.0.1','0.0.0.0','198.18.0.1','224.0.0.1','::1','::','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2001::1','2001:0:4136:e378:8000:63bf:3fff:fdd2','3fff::1','2002:7f00:1::']) assert.equal(isPublicAddress(ip), false, ip);
    for (const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicAddress(ip), true, ip);
});
test('PAC never authorizes another socket; web routes do not issue proxy challenges', async () => {
    globalThis._socratex = { domain: 'localhost', token: 'test-token', address: 'PROXY localhost:8080' };
    const server = proxy(); const port = await listen(server);
    try {
        assert.equal((await request(port, '/proxy.pac?token=test-token')).status, 200);
        assert.equal((await request(port, 'http://example.com/')).status, 407);
        // Probe-visible routes are indistinguishable from unknown paths.
        const unknown = await request(port, '/no-such-path');
        assert.equal(unknown.status, 404);
        for (const path of ['/', '/favicon.ico', '/console', '/console?token=test-token', '/proxy.pac', '/proxy.pac?token=wrong', '/wpad.dat?token=test-tokenX']) {
            assert.deepEqual(await request(port, path), unknown, path);
        }
        assert.equal((await request(port, 'http://127.0.0.1/', { 'Proxy-Authorization': auth })).status, 403);
        assert.equal((await request(port, 'http://[::1]/', { 'Proxy-Authorization': auth })).status, 403);
    } finally { await close(server); }
});
test('HTTP streams body and preserves origin auth while stripping proxy credentials', async () => {
    const origin = http.createServer((req, res) => { assert.equal(req.headers['proxy-authorization'], undefined); assert.equal(req.headers.authorization, 'Bearer origin'); res.end(req.url); });
    const originPort = await listen(origin); const server = proxy({ allowPrivateNetworks: true }); const port = await listen(server);
    try { const result = await request(port, `http://127.0.0.1:${originPort}/hello?q=1`, { 'Proxy-Authorization': auth, Authorization: 'Bearer origin' }); assert.deepEqual(result, { status: 200, body: '/hello?q=1' }); }
    finally { await close(server); await close(origin); }
});
test('CONNECT fragmented headers and immediate binary payload survive async authentication', async () => {
    const echo = net.createServer(s => s.pipe(s)); const echoPort = await listen(echo); const server = proxy({ allowPrivateNetworks: true }); const port = await listen(server);
    const payload = Buffer.concat([Buffer.from([0, 255, 128]), Buffer.from('CONNECT fake:80 HTTP/1.1\r\n\r\n'), Buffer.alloc(65536, 42)]);
    const client = net.createConnection({ host: '127.0.0.1', port });
    try { await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Tunnel timed out')), 5000); let data = Buffer.alloc(0);
        client.on('error', reject); client.on('data', chunk => { data = Buffer.concat([data, chunk]); const end = data.indexOf('\r\n\r\n'); if (end < 0) return; assert.match(data.subarray(0, end).toString(), /200 Connection Established/); if (data.length >= end + 4 + payload.length) { assert.deepEqual(data.subarray(end + 4), payload); clearTimeout(timer); resolve(); } });
        client.once('connect', () => { const h = `CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: ${auth}\r\n\r\n`; client.write(h.slice(0, 15)); setImmediate(() => { client.write(Buffer.concat([Buffer.from(h.slice(15)), payload.subarray(0, 500)])); client.write(payload.subarray(500)); }); });
    }); } finally { client.destroy(); await close(server); await close(echo); }
});
test('CONNECT challenges missing credentials and rejects malformed authorities once', async () => {
    const server = proxy(); const port = await listen(server);
    const exchange = text => new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: '127.0.0.1', port }); let result = '';
        socket.setTimeout(2000, () => socket.destroy(new Error('Timed out')));
        socket.on('error', reject); socket.on('data', chunk => result += chunk); socket.on('end', () => resolve(result));
        socket.on('connect', () => socket.write(text));
    });
    try {
        assert.match(await exchange('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n'), /^HTTP\/1.1 407/);
        const invalid = await exchange(`CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: ${auth}\r\n\r\n`);
        assert.match(invalid, /^HTTP\/1.1 400/); assert.equal(invalid.match(/HTTP\/1.1/g).length, 1);
    } finally { await close(server); }
});
test('incomplete headers close on bounded initial deadline', async () => {
    const server = proxy({ headerTimeout: 40 }); const port = await listen(server);
    const socket = net.createConnection({ host: '127.0.0.1', port });
    try { await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Header deadline not enforced')), 1000);
        socket.on('error', reject); socket.on('close', () => { clearTimeout(timer); resolve(); });
        socket.on('connect', () => socket.write('CONNECT example.com:443 HTTP/1.1\r\n'));
    }); } finally { socket.destroy(); await close(server); }
});
test('verified outer TLS plus Basic CONNECT works; invalid credentials get 407', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'socratex-tls-'));
    let server, echo;
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
        const cert = await readFile(join(dir, 'cert.pem')); const key = await readFile(join(dir, 'key.pem'));
        echo = net.createServer(socket => socket.pipe(socket)); const echoPort = await listen(echo);
        server = proxy({ https: true, tls: { key, cert }, allowPrivateNetworks: true }); const port = await listen(server);
        const exchange = authorization => new Promise((resolve, reject) => {
            const socket = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: cert, rejectUnauthorized: true });
            let received = Buffer.alloc(0); const payload = Buffer.from([0, 255, 42, 128]);
            const timer = setTimeout(() => { socket.destroy(); reject(new Error('TLS tunnel timed out')); }, 3000);
            const finish = result => { clearTimeout(timer); socket.destroy(); resolve(result); };
            socket.on('error', err => { clearTimeout(timer); reject(err); });
            socket.on('secureConnect', () => { assert.equal(socket.authorized, true); socket.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: ${authorization}\r\n\r\n`); });
            let sent = false;
            socket.on('data', chunk => {
                received = Buffer.concat([received, chunk]); const end = received.indexOf('\r\n\r\n'); if (end < 0) return;
                const status = received.subarray(0, end).toString();
                if (status.includes('407')) return finish(407);
                assert.match(status, /200 Connection Established/);
                if (!sent) { sent = true; socket.write(payload); }
                if (received.length >= end + 4 + payload.length) { assert.deepEqual(received.subarray(end + 4), payload); finish(200); }
            });
        });
        assert.equal(await exchange(auth), 200);
        assert.equal(await exchange('Basic ' + Buffer.from('user:wrong').toString('base64')), 407);
    } finally { if (server) await close(server); if (echo) await close(echo); await rm(dir, { recursive: true, force: true }); }
});
test('TLS sessions resume, including across instances sharing ticketKeys', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'socratex-tls-'));
    const servers = [];
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
        const cert = await readFile(join(dir, 'cert.pem')); const key = await readFile(join(dir, 'key.pem'));
        const ticketKeys = Buffer.alloc(48, 7);
        for (let i = 0; i < 2; i++) servers.push(proxy({ https: true, tls: { key, cert }, ticketKeys }));
        const [portA, portB] = await Promise.all(servers.map(listen));
        const handshake = (port, session) => new Promise((resolve, reject) => {
            let ticket; const socket = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: cert, session });
            socket.on('session', s => ticket = s); socket.on('error', reject);
            socket.on('secureConnect', () => setTimeout(() => { const reused = socket.isSessionReused(); socket.destroy(); resolve({ reused, ticket }); }, 30));
        });
        const first = await handshake(portA);
        assert.equal(first.reused, false); assert.ok(first.ticket);
        assert.equal((await handshake(portA, first.ticket)).reused, true, 'same instance resumes');
        assert.equal((await handshake(portB, first.ticket)).reused, true, 'sibling worker with shared ticketKeys resumes');
    } finally { for (const s of servers) await close(s); await rm(dir, { recursive: true, force: true }); }
});
test('connectAny falls back past dead or silent addresses without waiting for the full timeout', async () => {
    const echo = net.createServer(s => s.pipe(s)); const port = await listen(echo);
    try {
        const started = Date.now();
        // ::1 refuses (echo is IPv4-only); 192.0.2.1 (TEST-NET-1) never answers.
        const socket = await connectAny([{ address: '::1', family: 6 }, { address: '192.0.2.1', family: 4 }, { address: '127.0.0.1', family: 4 }], { port, timeout: 5000, delay: 50 });
        assert.equal(socket.remoteAddress, '127.0.0.1'); assert.ok(Date.now() - started < 1000); socket.destroy();
        await assert.rejects(connectAny([{ address: '::1', family: 6 }], { port, timeout: 1000 }), { status: 502 });
        await assert.rejects(connectAny([{ address: '::1', family: 6 }], { port, timeout: 1000, localAddress: '127.0.0.1' }), { status: 502 });
    } finally { await close(echo); }
});
test('DNS lookups are cached and concurrent lookups coalesce', async () => {
    const resolve = resolver({ dnsCacheTtl: 60000 });
    const [a, b] = await Promise.all([resolve('localhost'), resolve('LOCALHOST')]);
    assert.equal(a, b); assert.equal(await resolve('localhost'), a);
    const uncached = resolver({ dnsCacheTtl: 0 });
    assert.notEqual(await uncached('localhost'), await uncached('localhost'));
});
test('secret comparison is exact and rejects empty or non-string secrets', () => {
    assert.equal(safeEqual('pass:word', 'pass:word'), true);
    for (const [a, b] of [['pass:word', 'pass:wordX'], ['', ''], ['x', ''], ['x', undefined], [null, 'x'], ['PASS:WORD', 'pass:word']]) assert.equal(safeEqual(a, b), false, `${a} vs ${b}`);
});
test('407 challenge uses a generic, configurable realm and rejects unsafe values', async () => {
    const challenge = async options => {
        const server = proxy(options); const port = await listen(server);
        try {
            const http407 = await new Promise((resolve, reject) => {
                const req = http.request({ host: '127.0.0.1', port, path: 'http://example.com/', agent: false }, res => { res.resume(); resolve(res.headers['proxy-authenticate']); });
                req.on('error', reject); req.end();
            });
            const connect407 = await new Promise((resolve, reject) => {
                const socket = net.createConnection({ host: '127.0.0.1', port }); let data = '';
                socket.on('error', reject); socket.on('data', c => data += c); socket.on('end', () => resolve(/Proxy-Authenticate: (.*)\r\n/.exec(data)?.[1]));
                socket.on('connect', () => socket.write('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n'));
            });
            return [http407, connect407];
        } finally { await close(server); }
    };
    assert.deepEqual(await challenge(), ['Basic realm="proxy"', 'Basic realm="proxy"']);
    assert.deepEqual(await challenge({ realm: 'corp gateway' }), ['Basic realm="corp gateway"', 'Basic realm="corp gateway"']);
    for (const realm of ['', 'a"b', 'a\\b', 'x\r\nInjected: 1', 'é', 'x'.repeat(65)]) assert.throws(() => proxy({ realm }), /realm/, JSON.stringify(realm));
});
const rawExchange = (port, text, { secure } = {}) => new Promise((resolve, reject) => {
    const socket = secure ? tls.connect({ host: '127.0.0.1', port, ...secure }) : net.createConnection({ host: '127.0.0.1', port });
    let data = ''; socket.setTimeout(3000, () => socket.destroy(new Error('Timed out')));
    socket.on('error', reject); socket.on('data', c => data += c); socket.on('close', () => resolve(data));
    socket.once(secure ? 'secureConnect' : 'connect', () => socket.write(text));
});
const normalizeDate = text => text.replace(/Date: [^\r]+/, 'Date: X');
test('established tunnels outlive idleTimeout but still close after tunnelIdleTimeout (plain and TLS)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'socratex-tls-'));
    const echo = net.createServer(s => s.pipe(s)); const echoPort = await listen(echo);
    try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
        const cert = await readFile(join(dir, 'cert.pem')); const key = await readFile(join(dir, 'key.pem'));
        for (const https of [false, true]) {
            const server = proxy({ allowPrivateNetworks: true, idleTimeout: 200, tunnelIdleTimeout: 700, ...(https ? { https, tls: { key, cert } } : {}) });
            const port = await listen(server);
            try {
                const socket = https ? tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: cert }) : net.createConnection({ host: '127.0.0.1', port });
                let data = '', closedAt = null; const started = Date.now();
                socket.on('data', c => data += c); socket.on('error', () => {}); socket.on('close', () => closedAt = Date.now() - started);
                await new Promise(r => socket.once(https ? 'secureConnect' : 'connect', r));
                socket.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: ${auth}\r\n\r\n`);
                await new Promise(r => setTimeout(r, 450)); // Silent for > idleTimeout.
                assert.match(data, /200 Connection Established/); assert.equal(closedAt, null, `tls=${https} closed early`);
                socket.write('ping'); await new Promise(r => setTimeout(r, 100));
                assert.ok(data.endsWith('ping'), `tls=${https} echo after idleTimeout`);
                await new Promise(r => setTimeout(r, 1200)); // Silent for > tunnelIdleTimeout.
                assert.ok(closedAt !== null, `tls=${https} tunnel should close after tunnelIdleTimeout`);
            } finally { await close(server); }
        }
    } finally { await close(echo); await rm(dir, { recursive: true, force: true }); }
});
test('probe resistance hides the proxy unless credentials or the secret domain are used', async () => {
    const echo = net.createServer(s => s.pipe(s)); const echoPort = await listen(echo);
    const server = proxy({ allowPrivateNetworks: true, probeResistance: { domain: 'Secret-Link.example' } }); const port = await listen(server);
    const bad = 'Basic ' + Buffer.from('user:wrong').toString('base64');
    try {
        const unknown = normalizeDate(await rawExchange(port, 'GET /no-such-path HTTP/1.1\r\nHost: x\r\n\r\n'));
        assert.match(unknown, /^HTTP\/1.1 404/);
        for (const [label, text] of [
            ['CONNECT no creds', 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n'],
            ['CONNECT wrong creds', `CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: ${bad}\r\n\r\n`],
            ['CONNECT malformed', 'CONNECT nonsense HTTP/1.1\r\nHost: x\r\n\r\n'],
            ['GET absolute no creds', 'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n'],
        ]) assert.equal(normalizeDate(await rawExchange(port, text)), unknown, label);
        for (const text of ['CONNECT secret-link.example:443 HTTP/1.1\r\nHost: x\r\n\r\n', 'GET http://SECRET-LINK.example/ HTTP/1.1\r\nHost: secret-link.example\r\n\r\n']) {
            assert.match(await rawExchange(port, text), /^HTTP\/1.1 407[^]*Proxy-Authenticate: Basic realm="proxy"/);
        }
        assert.deepEqual(await request(port, 'http://secret-link.example/', { 'Proxy-Authorization': auth }), { status: 200, body: 'Proxy authentication OK' });
        const tunnel = await new Promise((resolve, reject) => {
            const socket = net.createConnection({ host: '127.0.0.1', port }); let data = '';
            socket.on('error', reject); socket.on('data', c => { data += c; if (data.endsWith('ping')) { socket.destroy(); resolve(data); } });
            socket.on('connect', () => socket.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: ${auth}\r\n\r\nping`));
        });
        assert.match(tunnel, /200 Connection Established/);
    } finally { await close(server); await close(echo); }
    // Without a secret domain, nothing ever gets a challenge.
    const blind = proxy({ probeResistance: true }); const blindPort = await listen(blind);
    try { assert.match(await rawExchange(blindPort, 'CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'), /^HTTP\/1.1 404/); }
    finally { await close(blind); }
});
