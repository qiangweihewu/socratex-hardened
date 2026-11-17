// NaïveProxy padding protocol, Variant1, server side over HTTP/1.1 CONNECT.
// Reimplemented from the public specification and behaviour of
// klzgrad/naiveproxy (BSD-style license): README "Padding protocol",
// src/net/tools/naive/naive_protocol.h, naive_padding_framer.cc,
// naive_padding_socket.cc and http_proxy_server_socket.cc.
//
// Only clients that announce support get padded tunnels; every other client
// keeps the plain "200 Connection Established" byte stream.
import { Transform } from 'node:stream';
import { randomInt } from 'node:crypto';

export const FIRST_PADDINGS = 8;
const MAX_PADDING = 255;
const MAX_PAYLOAD = 65535;
const HEADER = 3;

// Returns 1 (Variant1) or 0 (none) from the CONNECT request headers.
// `padding-type-request` lists preferred types; without it, the legacy
// `padding` header alone means Variant1.
export function negotiate(headers = {}) {
    const requested = headers['padding-type-request'];
    if (typeof requested === 'string') {
        return requested.split(',').map(x => x.trim()).includes('1') ? 1 : 0;
    }
    return headers.padding !== undefined ? 1 : 0;
}

// `Padding` header value: 30-62 symbols that are pseudo-random but not
// Huffman friendly, like the reference server's response padding.
export function paddingHeaderValue() {
    const symbols = '!#$()+<>?@[]^`{}';
    const length = randomInt(30, 63);
    let value = '';
    for (let i = 0; i < length; i++) value += i < 16 ? symbols[randomInt(symbols.length)] : '~';
    return value;
}

// Server-to-client: frame and pad the first FIRST_PADDINGS frames, then pass
// data through. Small payloads (< 100 bytes) are padded up near the maximum,
// matching the reference server direction.
export class Padder extends Transform {
    constructor(options) { super(options); this.frames = 0; }
    _transform(chunk, _encoding, callback) {
        let offset = 0;
        while (offset < chunk.length && this.frames < FIRST_PADDINGS) {
            const remaining = chunk.length - offset;
            const padding = remaining < 100
                ? randomInt(MAX_PADDING - remaining, MAX_PADDING + 1)
                : randomInt(0, MAX_PADDING + 1);
            const size = Math.min(remaining, MAX_PAYLOAD);
            const frame = Buffer.alloc(HEADER + size + padding); // Zero-filled padding.
            frame[0] = size >> 8; frame[1] = size & 0xff; frame[2] = padding;
            chunk.copy(frame, HEADER, offset, offset + size);
            this.push(frame);
            offset += size; this.frames++;
        }
        if (offset < chunk.length) this.push(offset ? chunk.subarray(offset) : chunk);
        callback();
    }
}

// Client-to-server: strip framing from the first FIRST_PADDINGS frames, then
// pass data through. Frames may be split across or merged within chunks.
export class Unpadder extends Transform {
    constructor(options) {
        super(options);
        Object.assign(this, { frames: 0, state: 0, payload: 0, padding: 0 });
    }
    _transform(chunk, _encoding, callback) {
        let i = 0;
        while (i < chunk.length) {
            if (this.state === 0 && this.frames >= FIRST_PADDINGS) {
                this.push(i ? chunk.subarray(i) : chunk);
                break;
            }
            switch (this.state) {
                case 0: this.payload = chunk[i++] << 8; this.state = 1; break;
                case 1: this.payload |= chunk[i++]; this.state = 2; break;
                case 2: this.padding = chunk[i++]; this.state = this.payload ? 3 : 4; break;
                case 3: {
                    const take = Math.min(this.payload, chunk.length - i);
                    this.push(chunk.subarray(i, i + take));
                    i += take; this.payload -= take;
                    if (!this.payload) this.state = 4;
                    break;
                }
                case 4: {
                    const take = Math.min(this.padding, chunk.length - i);
                    i += take; this.padding -= take;
                    break;
                }
            }
            if (this.state === 4 && !this.padding) { this.frames++; this.state = 0; }
        }
        callback();
    }
}
