import { mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
await mkdir(new URL('dist/', root), { recursive: true });
for (const variant of ['webcrypto', 'webgl', 'webgpu', 'full']) {
  for (const [format, extension] of [['iife', 'js'], ['cjs', 'cjs'], ['esm', 'mjs']]) {
    await build({
      absWorkingDir: fileURLToPath(root),
      entryPoints: [`src/entries/${variant}.js`],
      outfile: `dist/wpa2-web-brute.${variant}.${extension}`,
      bundle: true,
      format,
      platform: 'neutral',
      target: 'es2022',
      ...(format === 'iife' ? {
        globalName: 'WPA2WebBrute',
        footer: { js: 'globalThis.WPA2WebBrute = WPA2WebBrute.default;' },
      } : format === 'cjs' ? {
        footer: { js: 'module.exports = module.exports.default;' },
      } : {}),
    });
  }
}
for (const variant of ['webcrypto', 'webgl', 'webgpu', 'full']) {
  await copyFile(new URL(`types/${variant}.d.ts`, root), new URL(`dist/wpa2-web-brute.${variant}.d.ts`, root));
}
await copyFile(new URL('types/common.d.ts', root), new URL('dist/common.d.ts', root));
await copyFile(new URL('demo/index.html', root), new URL('dist/index.html', root));
console.log('Built webcrypto, webgl, webgpu, full (browser / ESM / CommonJS), declarations and dist/index.html');
