import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../dist/wpa2-web-brute.webgl.js', import.meta.url), 'utf8');

function setup(failure) {
  const live = new Map();
  const calls = {};
  let lost = 0;
  let error = 'NO_ERROR';
  const gl = new Proxy({}, { get(_, name) {
    if (name === name.toUpperCase()) return name;
    return (...args) => {
      calls[name] = (calls[name] ?? 0) + 1;
      const point = `${name}:${calls[name]}`;
      if (failure === point) throw new Error(`injected ${point}`);
      if (failure === `flag:${point}`) error = 'INVALID_OPERATION';
      if (failure === `lost:${point}`) lost++;
      if (name === 'getError') {
        const value = error;
        error = 'NO_ERROR';
        return value;
      }
      if (/^create/.test(name)) {
        if (failure === `null:${point}`) return null;
        const value = { type: name.slice(6) };
        live.set(value, value.type);
        return value;
      }
      if (/^delete/.test(name)) {
        assert.equal(live.get(args[0]), name.slice(6), 'resource deleted exactly once');
        live.delete(args[0]);
      }
      if (name === 'isProgram') return live.has(args[0]);
      if (name === 'isContextLost') return Boolean(lost);
      if (name === 'getShaderParameter') return failure !== `compile:${calls[name]}`;
      if (name === 'getProgramParameter') return failure !== 'link';
      if (name.endsWith('InfoLog')) return 'compile/link failed';
      if (name === 'getParameter') return args[0] === 'MAX_VIEWPORT_DIMS' ? [2, 2] : 2;
      if (name === 'checkFramebufferStatus') return failure === 'framebuffer' ? 'INCOMPLETE' : 'FRAMEBUFFER_COMPLETE';
      if (name === 'getExtension') return { loseContext() { lost++; } };
    };
  } });
  const context = vm.createContext({ TextEncoder, document: { createElement: () => ({ getContext: () => gl }) } });
  vm.runInContext(source, context);
  return { Backend: context.WPA2WebBrute.WebGL2PMK, PTK: context.WPA2WebBrute.WebGL2PTK,
    MIC: context.WPA2WebBrute.WebGL2MIC, live, calls, lost: () => lost };
}

for (const [name, key] of [['PTK', 'PTK'], ['MIC', 'MIC']]) {
  for (const failure of ['compile:1', 'link']) {
    test(`${name} constructor releases context after ${failure}`, () => {
      const state = setup(failure);
      assert.throws(() => new state[key]());
      assert.equal(state.live.size, 0);
      assert.equal(state.lost(), 1);
    });
  }
}

for (const failure of ['flag:drawArrays:1', 'flag:readPixels:1', 'flag:readPixels:2',
  'lost:readPixels:1', 'lost:readPixels:2', 'flag:readPixels:4', 'lost:readPixels:4']) {
  test(`WebGL2PMK rejects non-throwing GPU failure: ${failure}`, async () => {
    const state = setup(failure);
    const backend = new state.Backend();
    const contextLost = failure.startsWith('lost:');
    // The last two cases fail in the second chunk, after one successful chunk.
    const passwords = failure.endsWith(':4') ? ['12345678', 'abcdefgh', 'password'] : ['12345678'];
    await assert.rejects(backend.derive(passwords, 'test'),
      contextLost ? /context lost/ : /PMK readback failed: INVALID_OPERATION/);
    assert.deepEqual([...state.live.values()], ['Program']);
    if (contextLost) {
      const reads = state.calls.readPixels;
      await assert.rejects(backend.derive(['12345678'], 'test'), /context lost/);
      assert.equal(state.calls.readPixels, reads);
    } else {
      // getError consumes the flag; a later successful call can reuse the backend.
      assert.equal((await backend.derive(['12345678'], 'test')).length, 1);
    }
    backend.dispose();
    backend.dispose();
    assert.equal(state.live.size, 0);
  });
}

for (const failure of ['compile:1', 'compile:2', 'link', 'attachShader:2', 'getUniformLocation:1', 'null:createShader:2', 'null:createProgram:1']) {
  test(`WebGL2PMK constructor cleans resources after ${failure}`, () => {
    const state = setup(failure);
    assert.throws(() => new state.Backend());
    assert.equal(state.live.size, 0);
    assert.equal(state.lost(), 1);
  });
}
for (const failure of [undefined, 'framebuffer', 'texStorage2D:2', 'readPixels:2', 'null:createTexture:3', 'null:createFramebuffer:1']) {
  test(`WebGL2PMK derive cleanup: ${failure ?? 'success and reuse'}`, async () => {
    const state = setup(failure);
    const backend = new state.Backend();
    assert.deepEqual([...state.live.values()], ['Program']);
    if (failure) await assert.rejects(backend.derive(['12345678'], 'test'));
    else {
      assert.equal((await backend.derive(['12345678', 'abcdefgh', 'password'], 'test')).length, 3);
      assert.equal((await backend.derive(['12345678'], 'test')).length, 1);
    }
    assert.deepEqual([...state.live.values()], ['Program']);
    backend.dispose();
    backend.dispose();
    assert.equal(state.live.size, 0);
    assert.equal(state.lost(), 1);
    await assert.rejects(backend.derive(['12345678'], 'test'), /disposed/);
  });
}
