#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { parseArgs } from 'node:util';

const help = `Usage: wpa2-web-brute [options]

Runs PMK → PTK → MIC inside Puppeteer Headless Chromium.
Without --input, runs the built-in synthetic verification vector.

  --backend <name>          webcrypto | webgl | webgpu | all (default: all)
  --input <file>            JSON: passwords[], ssid, keyData (hex), message (hex),
                           optional expectedMic (hex, applied to every result)
  --batch-size <n>         Passwords per batch, 1–32768 (default: 1)
  --timeout <ms>           Timeout per backend (default: 120000)
  --software              Use SwiftShader software GPU
  --executable-path <path> Chromium executable (default: Puppeteer's browser)
  --browser-arg <arg>      Extra Chromium argument; repeatable, use = for --flags
  --help                  Print this help

stdout: JSON report. Exit 0: success; 1: backend failure/MIC mismatch;
2: invalid arguments/input or browser startup failure.
`;

function positive(value, max, name) {
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < 1 || Number(value) > max)
    throw new Error(`${name}: expected integer 1–${max}`);
  return Number(value);
}
function hex(value, length, name) {
  if (typeof value !== 'string' || !/^(?:[\da-f]{2})*$/i.test(value) || (length !== undefined && value.length !== length * 2))
    throw new Error(`${name}: expected ${length === undefined ? 'even-length' : length + '-byte'} hex string`);
  return value.toLowerCase();
}
function validate(input) {
  if (!input || typeof input !== 'object') throw new Error('Input must be a JSON object');
  if (!Array.isArray(input.passwords) || !input.passwords.length || input.passwords.some(p => typeof p !== 'string' || Buffer.byteLength(p) < 8 || Buffer.byteLength(p) > 63))
    throw new Error('passwords: nonempty array of strings, each 8–63 UTF-8 bytes');
  if (typeof input.ssid !== 'string' || Buffer.byteLength(input.ssid) < 1 || Buffer.byteLength(input.ssid) > 32)
    throw new Error('ssid: expected 1–32 UTF-8 bytes');
  return { passwords: input.passwords, ssid: input.ssid,
    keyData: hex(input.keyData, 76, 'keyData'), message: hex(input.message, undefined, 'message'),
    ...(input.expectedMic === undefined ? {} : { expectedMic: hex(input.expectedMic, 16, 'expectedMic') }) };
}

async function main() {
  const { values } = parseArgs({ options: {
    help: { type: 'boolean' }, backend: { type: 'string', default: 'all' },
    input: { type: 'string' }, 'batch-size': { type: 'string', default: '1' },
    timeout: { type: 'string', default: '120000' }, software: { type: 'boolean' },
    'executable-path': { type: 'string' }, 'browser-arg': { type: 'string', multiple: true },
  } });
  if (values.help) { console.log(help); return; }
  const names = ['webcrypto', 'webgl', 'webgpu'];
  if (values.backend !== 'all' && !names.includes(values.backend)) throw new Error('Unknown backend: ' + values.backend);
  const batchSize = positive(values['batch-size'], 32768, 'batch-size');
  const timeout = positive(values.timeout, 2147483647, 'timeout');
  const input = validate(values.input ? JSON.parse(await readFile(values.input, 'utf8')) : {
    passwords: ['12345678'], ssid: 'Test_WiFi',
    keyData: Buffer.from(Array.from({ length: 76 }, (_, i) => i)).toString('hex'),
    message: Buffer.from(Array.from({ length: 128 }, (_, i) => i)).toString('hex'),
    expectedMic: 'f955d7dba6bd85b2560cf3f9d8a501e8',
  });
  const source = await readFile(new URL('../dist/wpa2-web-brute.full.js', import.meta.url), 'utf8');
  const { default: puppeteer } = await import('puppeteer');
  // Loopback provides a secure context for both WebCrypto and WebGPU.
  const server = createServer((req, res) => {
    res.writeHead(req.url === '/' ? 200 : 404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(req.url === '/' ? '<!doctype html><title>WPA2 CLI</title>' : 'Not found');
  });
  let browser;
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    browser = await puppeteer.launch({ headless: true, executablePath: values['executable-path'],
      timeout, protocolTimeout: timeout,
      args: ['--enable-gpu', '--enable-unsafe-webgpu',
        ...(values.software ? ['--use-angle=swiftshader', '--enable-unsafe-swiftshader'] : []),
        ...(values['browser-arg'] ?? [])],
    });
    const report = { results: [] };
    for (const backend of values.backend === 'all' ? names : [values.backend]) {
      let page, timer;
      try {
        const run = async () => {
          page = await browser.newPage();
          await page.goto(`http://127.0.0.1:${server.address().port}/`, { timeout });
          await page.addScriptTag({ content: source });
          return page.evaluate(async ({ backend, input, batchSize }) => {
            const api = globalThis.WPA2WebBrute;
            const bytes = hex => Uint8Array.from(hex.match(/../g) ?? [], byte => parseInt(byte, 16));
            const started = performance.now();
            let instance;
            try {
              instance = backend === 'webgl' ? new api.WPA2WebGL() :
                await api[backend === 'webgpu' ? 'WPA2WebGPU' : 'WPA2WebCrypto'].create();
              const mics = [];
              const size = Math.min(batchSize, instance.maxBatch ?? batchSize);
              for (let offset = 0; offset < input.passwords.length; offset += size) {
                const result = await instance.derive(input.passwords.slice(offset, offset + size), input.ssid, bytes(input.keyData), bytes(input.message));
                for (const mic of result.mics ?? result.map(item => item.mic))
                  mics.push(Array.from(mic, b => b.toString(16).padStart(2, '0')).join(''));
              }
              const matches = input.expectedMic === undefined ? undefined : mics.map(mic => mic === input.expectedMic);
              return { backend, ok: matches === undefined || matches.every(Boolean), mics,
                ...(matches === undefined ? {} : { matches }), elapsedMs: Math.round(performance.now() - started) };
            } finally { instance?.dispose(); }
          }, { backend, input, batchSize });
        };
        report.results.push(await Promise.race([run(), new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`Backend timed out after ${timeout} ms`)), timeout);
        })]));
      } catch (error) {
        report.results.push({ backend, ok: false, error: error.message });
      } finally {
        clearTimeout(timer);
        await page?.close().catch(() => {});
      }
    }
    console.log(JSON.stringify(report, null, 2));
    if (report.results.some(result => !result.ok)) process.exitCode = 1;
  } finally {
    try { await browser?.close(); }
    finally { await new Promise(resolve => server.close(resolve)); }
  }
}
main().catch(error => { console.error(`wpa2-web-brute: ${error.message}`); process.exitCode = 2; });
