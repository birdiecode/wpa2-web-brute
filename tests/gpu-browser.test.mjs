import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { pbkdf2Sync, createHmac } from 'node:crypto';
import puppeteer from 'puppeteer';

const bytes = (length, seed) => Array.from({ length }, (_, i) => (i * 73 + seed * 29) & 255);
function expected({ passwords, ssid, keyData, message }) {
  return passwords.map(password => {
    const pmk = pbkdf2Sync(password, ssid, 4096, 32, 'sha1');
    const kck = createHmac('sha1', pmk).update(Buffer.concat([
      Buffer.from('Pairwise key expansion\0'), Buffer.from(keyData), Buffer.from([0]),
    ])).digest().subarray(0, 16);
    return [...createHmac('sha1', kck).update(Buffer.from(message)).digest().subarray(0, 16)];
  });
}

// Reproducible vectors; descending sizes also catch stale buffer contents on reuse.
const lengths = [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 1024, 56, 0];
const passwords = ['12345678', 'p'.repeat(63), 'я'.repeat(31) + 'x', '🔑🔑'];
const ssids = ['x', 's'.repeat(32), 'я'.repeat(16), '🔑'];
const vectors = lengths.map((length, i) => ({
  passwords: passwords.slice(0, i % 4 + 1), ssid: ssids[i % ssids.length],
  keyData: bytes(76, i), message: bytes(length, i),
}));
// Exercise partial workgroups and shrink back to a single candidate.
for (const count of [31, 32, 33, 1]) vectors.push({
  passwords: Array.from({ length: count }, (_, i) => `candidate-${i}`),
  ssid: 'batch-boundary', keyData: bytes(76, count), message: bytes(55, count),
});

for (const backend of ['webcrypto', 'webgl', 'webgpu']) test(`Chromium ${backend}: padding, UTF-8 limits, reuse and device loss`, {
  skip: process.env.WPA2_BROWSER_TEST !== '1', timeout: 360000,
}, async t => {
  const server = createServer((req, res) => res.end('<!doctype html><title>GPU tests</title>'));
  let browser;
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await puppeteer.launch({ headless: true, protocolTimeout: 300000,
      args: ['--enable-gpu', '--enable-unsafe-webgpu', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'],
    });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.addScriptTag({ path: new URL('../dist/wpa2-web-brute.full.js', import.meta.url).pathname });
    await page.evaluate(async backend => {
      window.instance = await ({ webcrypto: WPA2WebBrute.WPA2WebCrypto, webgl: WPA2WebBrute.WPA2WebGL, webgpu: WPA2WebBrute.WPA2WebGPU }[backend]).create();
      window.derive = async v => {
        const result = await instance.derive(v.passwords, v.ssid, new Uint8Array(v.keyData), new Uint8Array(v.message));
        if (Object.keys(result).join() !== 'mics' || !Array.isArray(result.mics) ||
            result.mics.length !== v.passwords.length ||
            result.mics.some(mic => !(mic instanceof Uint8Array) || mic.length !== 16))
          throw new Error('Invalid backend result contract');
        return result.mics.map(mic => [...mic]);
      };
    }, backend);
    if (backend === 'webgpu') await t.test('separate WebGPU stages reject overlapping calculations', async () => {
      const overlap = await page.evaluate(async () => {
        const api = WPA2WebBrute;
        const pmk = await api.WebGPUPMK.create();
        const ptk = await api.WebGPUPTK.create();
        const mic = await api.WebGPUMIC.create();
        const passwords = ['12345678'];
        const ssid = 'test';
        const keyData = new Uint8Array(76);
        const pmks = [new Uint8Array(32)];
        const keys = [new Uint8Array(16)];
        const message = new Uint8Array(64);
        const check = (first, second) => Promise.allSettled([first, second]).then(results =>
          results.filter(result => result.status === 'rejected').map(result => result.reason.message));
        try {
          const result = {
            pmk: await check(pmk.calculate(passwords, ssid), pmk.calculate(passwords, ssid)),
            ptk: await check(ptk.calculate(pmks, keyData), ptk.calculate(pmks, keyData)),
            mic: await check(mic.calculate(keys, message), mic.calculate(keys, message)),
          };
          pmk.dispose(); ptk.dispose(); mic.dispose();
          for (const [stage, call] of [
            ['pmk', pmk.calculate(passwords, ssid)],
            ['ptk', ptk.calculate(pmks, keyData)],
            ['mic', mic.calculate(keys, message)],
          ]) {
            try { await call; result[`${stage}Disposed`] = false; }
            catch (error) { result[`${stage}Disposed`] = /освобождён/.test(error.message); }
          }
          pmk.dispose(); ptk.dispose(); mic.dispose();
          return result;
        } finally { pmk.dispose(); ptk.dispose(); mic.dispose(); }
      });
      for (const errors of [overlap.pmk, overlap.ptk, overlap.mic]) {
        assert.equal(errors.length, 1);
        assert.match(errors[0], /Дождитесь завершения/);
      }
      assert.equal(overlap.pmkDisposed, true);
      assert.equal(overlap.ptkDisposed, true);
      assert.equal(overlap.micDisposed, true);
    });
    if (backend === 'webgl') await t.test('separate WebGL stages release contexts on dispose', async () => {
      const result = await page.evaluate(async () => {
        const ptk = new WPA2WebBrute.WebGL2PTK();
        const mic = new WPA2WebBrute.WebGL2MIC();
        ptk.dispose(); ptk.dispose(); mic.dispose(); mic.dispose();
        const errors = [];
        for (const call of [
          ptk.derive([new Uint8Array(32)], new Uint8Array(76)),
          mic.derive([new Uint8Array(16)], new Uint8Array(64)),
        ]) {
          try { await call; errors.push('ok'); } catch (error) { errors.push(error.message); }
        }
        return errors;
      });
      assert.equal(result.length, 2);
      assert.match(result[0], /освобождён/);
      assert.match(result[1], /освобождён/);
    });
    for (const [i, vector] of vectors.entries()) await t.test(`vector ${i}: message=${vector.message.length}, batch=${vector.passwords.length}`, async () => {
      assert.deepEqual(await page.evaluate(v => derive(v), vector), expected(vector));
    });
    await t.test('reject invalid byte lengths; remain reusable after rejection', async () => {
      const invalid = [
        { passwords: ['p'.repeat(7)] }, { passwords: ['p'.repeat(64)] },
        { passwords: ['я'.repeat(32)] }, { ssid: '' }, { ssid: 's'.repeat(33) },
        { ssid: 'я'.repeat(17) }, { keyData: bytes(75, 0) }, { keyData: bytes(77, 0) },
      ];
      for (const change of invalid) {
        const error = await page.evaluate(async v => {
          try { await derive(v); return null; } catch (error) { return error.message; }
        }, { ...vectors[0], ...change });
        assert.ok(error, JSON.stringify(change));
      }
      assert.deepEqual(await page.evaluate(v => derive(v), vectors[0]), expected(vectors[0]));
    });
    await t.test('common lifecycle and batch limits', async () => {
      const result = await page.evaluate(async vector => {
        const maxBatch = instance.maxBatch;
        const rejected = [];
        for (const passwords of [[], Array(maxBatch + 1).fill('12345678')]) {
          try { await derive({ ...vector, passwords }); rejected.push(false); }
          catch { rejected.push(true); }
        }
        instance.dispose();
        instance.dispose();
        try { await derive(vector); rejected.push(false); }
        catch { rejected.push(true); }
        return { maxBatch, rejected };
      }, vectors[0]);
      assert.ok(Number.isInteger(result.maxBatch) && result.maxBatch > 0);
      assert.deepEqual(result.rejected, [true, true, true]);
      await page.evaluate(async backend => {
        window.instance = await ({ webcrypto: WPA2WebBrute.WPA2WebCrypto, webgl: WPA2WebBrute.WPA2WebGL, webgpu: WPA2WebBrute.WPA2WebGPU }[backend]).create();
      }, backend);
      assert.deepEqual(await page.evaluate(v => derive(v), vectors[0]), expected(vectors[0]));
    });
    if (backend === 'webgl') await t.test('chunked WebGL results preserve the common contract and input order', async () => {
      const vector = vectors[2];
      const actual = await page.evaluate(async vector => {
        const gl = instance.gl;
        const original = gl.getParameter;
        gl.getParameter = function (name) {
          return name === gl.MAX_VIEWPORT_DIMS ? new Int32Array([2, 2]) : original.call(this, name);
        };
        try { return await derive(vector); }
        finally { gl.getParameter = original; }
      }, vector);
      assert.deepEqual(actual, expected(vector));
    });
    if (backend !== 'webcrypto') await t.test('loss rejects subsequent calls, disposal is idempotent, new instance works', async () => {
      const errors = await page.evaluate(async ({ backend, vector }) => {
        if (backend === 'webgpu') {
          instance.device.destroy();
          await instance.device.lost;
        } else {
          const extension = instance.gl.getExtension('WEBGL_lose_context');
          if (!extension) throw new Error('WEBGL_lose_context required for this test');
          extension.loseContext();
        }
        const errors = [];
        for (let i = 0; i < 2; i++) {
          try { await derive(vector); errors.push(null); } catch (error) { errors.push(error.message); }
        }
        instance.dispose();
        instance.dispose();
        try { await derive(vector); errors.push(null); } catch (error) { errors.push(error.message); }
        window.instance = await ({ webcrypto: WPA2WebBrute.WPA2WebCrypto, webgl: WPA2WebBrute.WPA2WebGL, webgpu: WPA2WebBrute.WPA2WebGPU }[backend]).create();
        return errors;
      }, { backend, vector: vectors[0] });
      assert.equal(errors.length, 3);
      for (const error of errors) assert.match(error ?? '', /потерян|недоступно|освобождён/);
      assert.deepEqual(await page.evaluate(v => derive(v), vectors[0]), expected(vectors[0]));
    });
    if (backend === 'webgpu') await t.test('loss during readback rejects pending derive and clears busy', async () => {
      const result = await page.evaluate(async v => {
        const pending = derive(v).then(() => false, () => true);
        instance.device.destroy();
        await instance.device.lost;
        return { rejected: await pending, busy: instance.busy };
      }, vectors[0]);
      assert.deepEqual(result, { rejected: true, busy: false });
    });
    await page.evaluate(() => instance.dispose());
  } finally {
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
  }
});
