import { readFile, mkdir, writeFile, copyFile } from 'node:fs/promises';
const root = new URL('../', import.meta.url);
const read = name => readFile(new URL(name, root), 'utf8');
await mkdir(new URL('dist/', root), { recursive: true });

// Extract library branches from the original GPU implementations.
async function gpuSource(name, symbol) {
  let source = await read(`src/${name}`);
  const marker = symbol === 'WebGPUMIC'
    ? '// The computation class can be loaded without the demo page UI.'
    : '\nfunction setDisabled(disabled)';
  const end = source.indexOf(marker);
  if (end < 0) throw new Error(`Library boundary missing: ${name}`);
  source = source.slice(0, end) + '\n})();';
  source = source.replace(/^\(async \(\) => \{/, '(() => {');
  return `{ const document = { querySelector: () => null, querySelectorAll: () => [] };\n${source}\n}\nconst ${symbol} = globalThis.${symbol};\n`;
}
const cryptoSource = await read('src/webcrypto.js');
let gl = await read('src/wpa2_webgl_pmk.js');
for (const [file, symbol] of [['wpa2_webgl_ptk.js', 'WebGL2PTK'], ['wpa2_webgl_mic.js', 'WebGL2MIC'], ['wpa2_webgl.js', 'WPA2WebGL']]) {
  gl += `\n${await read(`src/${file}`)}\nconst ${symbol} = globalThis.${symbol};\n`;
}
let gpu = '';
for (const [file, symbol] of [['wpa2_webgpu_pmk.js', 'WebGPUPMK'], ['wpa2_webgpu_ptk.js', 'WebGPUPTK'], ['wpa2_webgpu_mic.js', 'WebGPUMIC']]) gpu += await gpuSource(file, symbol);
gpu += `${await read('src/wpa2_webgpu_chain.js')}\nconst WPA2WebGPU = globalThis.WPA2WebGPU;\n`;
const parts = {
  webcrypto: [cryptoSource, ['WPA2WebCrypto', 'calc_pmk', 'calc_ptk', 'calc_mic']],
  webgl: [gl, ['WPA2WebGL', 'WebGL2PMK', 'WebGL2PTK', 'WebGL2MIC']],
  webgpu: [gpu, ['WPA2WebGPU', 'WebGPUPMK', 'WebGPUPTK', 'WebGPUMIC']]
};
parts.full = [Object.values(parts).map(p => p[0]).join('\n'), Object.values(parts).flatMap(p => p[1])];
for (const [variant, [source, names]] of Object.entries(parts)) {
  const factory = `(() => {\n'use strict';\nconst globalThis = {};\n${source}\nreturn { ${names.join(', ')} };\n})()`;
  const base = `dist/wpa2-web-brute.${variant}`;
  await writeFile(new URL(`${base}.js`, root), `/* wpa2-web-brute: ${variant} */\nglobalThis.WPA2WebBrute = ${factory};\n`);
  await writeFile(new URL(`${base}.cjs`, root), `module.exports = ${factory};\n`);
  await writeFile(new URL(`${base}.mjs`, root), `const api = ${factory};\nexport default api;\nexport const { ${names.join(', ')} } = api;\n`);
}
await copyFile(new URL('demo/index.html', root), new URL('dist/index.html', root));
console.log('Built webcrypto, webgl, webgpu, full (browser / ESM / CommonJS) and dist/index.html');
