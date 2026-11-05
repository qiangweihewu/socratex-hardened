import test from 'node:test';
import assert from 'node:assert/strict';
import { fileType, math, storage, uoid, utilitas } from 'utilitas';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

test('scoped dependency overrides retain utilitas arithmetic, file and UUID APIs', async () => {
    assert.equal(math.multiply(math.bignumber('1.25'), math.divide(math.bignumber('4'), math.bignumber('2'))).toString(), '2.5');
    assert.match(uoid.create({ file: 'test.mjs' }), /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}/i);
    assert.match(uoid.getRfcUrlNamespaceUuid('https://example.com/'), /^[0-9a-f-]{36}$/);
    assert.doesNotThrow(() => utilitas.assertUuid(uoid.getRfcUrlNamespaceUuid('https://example.com/')));
    const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c636000020000050001a5f645400000000049454e44ae426082', 'hex');
    assert.equal((await fileType.fileTypeFromBuffer(png)).mime, 'image/png');
    assert.equal(await fileType.fileTypeFromBuffer(Buffer.from('not a file')), undefined);
    const dir = await mkdtemp(join(tmpdir(), 'socratex-config-'));
    try {
        const options = { config: join(dir, 'config.json') };
        await storage.setConfig({ testValue: 'roundtrip' }, options);
        assert.equal((await storage.getConfig(options)).config.testValue, 'roundtrip');
    } finally { await rm(dir, { recursive: true, force: true }); }
});
