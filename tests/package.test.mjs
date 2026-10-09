import test from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
const require = createRequire(import.meta.url);
for (const variant of ['webcrypto', 'webgl', 'webgpu', 'full']) {
  test(`${variant}: ESM, CJS, classic script; no DOM required on import`, async () => {
    const esm = await import(`../dist/wpa2-web-brute.${variant}.mjs`);
    const cjs = require(`../dist/wpa2-web-brute.${variant}.cjs`);
    const context = vm.createContext({ TextEncoder });
    vm.runInContext(await readFile(new URL(`../dist/wpa2-web-brute.${variant}.js`, import.meta.url), 'utf8'), context);
    assert.deepEqual(Object.keys(esm.default), Object.keys(cjs));
    assert.deepEqual(Object.keys(context.WPA2WebBrute), Object.keys(cjs));
    if (variant !== 'full') assert.ok(Object.keys(cjs).every(name => variant === 'webcrypto' ? /Crypto|calc_/.test(name) : name.toLowerCase().includes(variant)));
  });
}
test('WebCrypto matches independent Node crypto PMK, PTK, MIC and batch', async () => {
  const api = await import('../dist/wpa2-web-brute.webcrypto.mjs');
  const keyData = Uint8Array.from({ length: 76 }, (_, i) => i);
  const message = Uint8Array.from({ length: 128 }, (_, i) => i);
  const pmk = pbkdf2Sync('12345678', 'Test_WiFi', 4096, 32, 'sha1');
  assert.deepEqual(Buffer.from(await api.calc_pmk('12345678', 'Test_WiFi')), pmk);
  const ptk = Buffer.concat(Array.from({ length: 4 }, (_, i) => createHmac('sha1', pmk).update(Buffer.concat([Buffer.from('Pairwise key expansion\0'), keyData, Buffer.from([i])])).digest())).subarray(0, 64);
  assert.deepEqual(Buffer.from(await api.calc_ptk(pmk, keyData)), ptk);
  const mic = createHmac('sha1', ptk.subarray(0, 16)).update(message).digest().subarray(0, 16);
  assert.equal(mic.toString('hex'), 'f955d7dba6bd85b2560cf3f9d8a501e8');
  const backend = await api.WPA2WebCrypto.create();
  try {
    const { mics } = await backend.derive(['12345678', '12345678'], 'Test_WiFi', keyData, message);
    assert.equal(mics.length, 2);
    for (const item of mics) assert.deepEqual(Buffer.from(item), mic);
  } finally { backend.dispose(); }
  await assert.rejects(api.calc_pmk('short', 'ssid'));
});

test('source entry points import without accessing browser globals or publishing globals', async () => {
  const names = ['document', 'navigator', 'WPA2WebBrute', 'WebGPUPMK', 'WebGPUPTK', 'WebGPUMIC', 'WPA2WebGPU', 'WPA2WebGL', 'WebGL2PMK', 'WebGL2PTK', 'WebGL2MIC'];
  const descriptors = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  try {
    for (const name of names) Object.defineProperty(globalThis, name, {
      configurable: true,
      get() { throw new Error(`Unexpected access to ${name}`); },
      set() { throw new Error(`Unexpected write to ${name}`); },
    });
    for (const variant of ['webcrypto', 'webgl', 'webgpu', 'full']) {
      const source = await import(`../src/entries/${variant}.js`);
      const built = await import(`../dist/wpa2-web-brute.${variant}.mjs`);
      assert.deepEqual(Object.keys(source.default).sort(), Object.keys(built.default).sort());
      assert.equal(typeof source.default[Object.keys(source.default)[0]], 'function');
    }
  } finally {
    names.forEach((name, i) => {
      if (descriptors[i]) Object.defineProperty(globalThis, name, descriptors[i]);
      else delete globalThis[name];
    });
  }
});
