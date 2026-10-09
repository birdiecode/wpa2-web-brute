import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pbkdf2Sync, createHmac } from 'node:crypto';
const exec = promisify(execFile);
const cli = new URL('../bin/wpa2-web-brute.mjs', import.meta.url).pathname;
async function run(args) {
  try { return { code: 0, ...await exec(process.execPath, [cli, ...args], { timeout: 180000 }) }; }
  catch (error) { if (typeof error.code !== 'number') throw error; return error; }
}
test('CLI help and invalid arguments work without browser startup', async () => {
  const help = await run(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /Headless Chromium/);
  for (const args of [['--backend', 'invalid'], ['--batch-size', '0'], ['--timeout', 'NaN'], ['--unknown']]) {
    const result = await run(args);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
  }
});
test('CLI rejects malformed hex before browser startup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wpa2-cli-'));
  try {
    const path = join(dir, 'input.json');
    await writeFile(path, JSON.stringify({ passwords: ['12345678'], ssid: 'test', keyData: 'zz'.repeat(76), message: '' }));
    const result = await run(['--input', path]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /keyData/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('Chromium: all backends match independent crypto across batches; mismatch exits 1', {
  skip: process.env.WPA2_BROWSER_TEST !== '1', timeout: 360000,
}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wpa2-cli-browser-'));
  try {
    const passwords = ['12345678', 'another-password', 'пароль123'];
    const keyData = Buffer.from(Array.from({ length: 76 }, (_, i) => i));
    const message = Buffer.from(Array.from({ length: 128 }, (_, i) => i));
    const ssid = 'Test_WiFi';
    const expected = passwords.map(password => {
      const pmk = pbkdf2Sync(password, ssid, 4096, 32, 'sha1');
      const kck = createHmac('sha1', pmk).update(Buffer.concat([Buffer.from('Pairwise key expansion\0'), keyData, Buffer.from([0])])).digest().subarray(0, 16);
      return createHmac('sha1', kck).update(message).digest().subarray(0, 16).toString('hex');
    });
    const path = join(dir, 'input.json');
    const input = { passwords, ssid, keyData: keyData.toString('hex'), message: message.toString('hex') };
    await writeFile(path, JSON.stringify(input));
    const result = await run(['--software', '--input', path, '--batch-size', '2']);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    const report = JSON.parse(result.stdout);
    assert.deepEqual(report.results.map(r => r.backend), ['webcrypto', 'webgl', 'webgpu']);
    for (const row of report.results) assert.deepEqual(row.mics, expected, row.backend);
    await writeFile(path, JSON.stringify({ ...input, expectedMic: '00'.repeat(16) }));
    const mismatch = await run(['--backend', 'webcrypto', '--input', path]);
    assert.equal(mismatch.code, 1, mismatch.stderr);
    assert.deepEqual(JSON.parse(mismatch.stdout).results[0].matches, [false, false, false]);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
