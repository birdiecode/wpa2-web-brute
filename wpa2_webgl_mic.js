// WPA2 MIC, matching calc_mic in wpa2_brute.js: HMAC-SHA1 truncated to 16 bytes.
// Usage: await new WebGL2MIC().derive([ptk.subarray(0, 16)], message);
// Supply EAPOL bytes with the MIC field already zeroed. Input bytes are not modified.
(() => {
  const vertexSource = `#version 300 es
void main() {
    vec2 p = vec2((gl_VertexID << 1) & 2, gl_VertexID & 2);
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;
  const fragmentSource = `#version 300 es
precision highp float;
precision highp int;
uniform highp usampler2D uKeys;
uniform highp usampler2D uMessage;
uniform int uBlocks;
layout(location = 0) out uvec4 oMic;

uint rol(uint x, uint n) { return (x << n) | (x >> (32u - n)); }

void shaInit(out uint h[5]) {
    h[0] = 0x67452301u; h[1] = 0xefcdab89u; h[2] = 0x98badcfeu;
    h[3] = 0x10325476u; h[4] = 0xc3d2e1f0u;
}

void shaBlock(inout uint h[5], uint w[80]) {
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u);
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        uint t = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30u); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void main() {
    uvec4 key = texelFetch(uKeys, ivec2(int(gl_FragCoord.x), 0), 0);
    uint w[80], h[5], inner[5];
    shaInit(h);
    for (int i = 0; i < 16; i++) w[i] = 0x36363636u;
    for (int i = 0; i < 4; i++) w[i] ^= key[i];
    shaBlock(h, w);
    for (int block = 0; block < uBlocks; block++) {
        for (int i = 0; i < 4; i++) {
            uvec4 words = texelFetch(uMessage, ivec2(i, block), 0);
            for (int j = 0; j < 4; j++) w[i * 4 + j] = words[j];
        }
        shaBlock(h, w);
    }
    for (int i = 0; i < 5; i++) inner[i] = h[i];
    shaInit(h);
    for (int i = 0; i < 16; i++) w[i] = 0x5c5c5c5cu;
    for (int i = 0; i < 4; i++) w[i] ^= key[i];
    shaBlock(h, w);
    for (int i = 0; i < 16; i++) w[i] = 0u;
    for (int i = 0; i < 5; i++) w[i] = inner[i];
    w[5] = 0x80000000u;
    w[15] = 84u * 8u;
    shaBlock(h, w);
    oMic = uvec4(h[0], h[1], h[2], h[3]);
}`;

  class WebGL2MIC {
    static get shaders() {
      return { vertex: vertexSource, fragment: fragmentSource };
    }
    constructor() {
      this.canvas = document.createElement('canvas');
      this.gl = this.canvas.getContext('webgl2', {
        antialias: false, depth: false, stencil: false,
        preserveDrawingBuffer: false,
      });
      if (!this.gl) throw new Error('WebGL2 недоступен');
      const gl = this.gl;
      const shaders = [];
      const program = gl.createProgram();
      try {
        for (const [type, source] of [
          [gl.VERTEX_SHADER, vertexSource], [gl.FRAGMENT_SHADER, fragmentSource],
        ]) {
          const shader = gl.createShader(type);
          shaders.push(shader);
          gl.shaderSource(shader, source);
          gl.compileShader(shader);
          if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS))
            throw new Error(gl.getShaderInfoLog(shader));
          gl.attachShader(program, shader);
        }
        gl.linkProgram(program);
        if (!gl.getProgramParameter(program, gl.LINK_STATUS))
          throw new Error(gl.getProgramInfoLog(program));
        this.program = program;
        this.uKeys = gl.getUniformLocation(program, 'uKeys');
        this.uMessage = gl.getUniformLocation(program, 'uMessage');
        this.uBlocks = gl.getUniformLocation(program, 'uBlocks');
      } catch (error) {
        gl.deleteProgram(program);
        throw error;
      } finally {
        for (const shader of shaders) gl.deleteShader(shader);
      }
    }

    // keys: array of 16-byte Uint8Array KCKs; message: shared Uint8Array.
    // Returns one 16-byte Uint8Array MIC per key. Readback blocks the UI thread.
    async derive(keys, message) {
      if (!this.program) throw new Error('WebGL2MIC уже освобождён');
      const gl = this.gl;
      if (gl.isContextLost()) throw new Error('Контекст WebGL2 потерян');
      if (!Array.isArray(keys)) throw new TypeError('keys должен быть массивом Uint8Array');
      if (!(message instanceof Uint8Array)) throw new TypeError('message должен быть Uint8Array');
      for (const key of keys) {
        if (!(key instanceof Uint8Array) || key.length !== 16)
          throw new TypeError('Каждый KCK должен содержать ровно 16 байт (Uint8Array)');
      }
      const maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      const maxWidth = Math.min(maxTexture, gl.getParameter(gl.MAX_VIEWPORT_DIMS)[0]);
      const count = keys.length;
      const blocks = Math.ceil((message.length + 9) / 64);
      if (count > maxWidth) throw new RangeError(`Размер пачки не должен превышать ${maxWidth}`);
      if (blocks > maxTexture) throw new RangeError(`Сообщение не должно превышать ${maxTexture * 64 - 9} байт`);
      if (!count) return [];
      this.canvas.width = count;
      this.canvas.height = 1;

      const packedKeys = new Uint32Array(count * 4);
      for (let i = 0; i < count; i++) {
        const view = new DataView(keys[i].buffer, keys[i].byteOffset, 16);
        for (let j = 0; j < 4; j++) packedKeys[i * 4 + j] = view.getUint32(j * 4, false);
      }
      const padded = new Uint8Array(blocks * 64);
      padded.set(message);
      padded[message.length] = 0x80;
      const view = new DataView(padded.buffer);
      // SHA-1 bit length includes the 64-byte HMAC ipad block.
      const bitLength = (64 + message.length) * 8;
      view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000), false);
      view.setUint32(padded.length - 4, bitLength >>> 0, false);
      const packedMessage = new Uint32Array(padded.length / 4);
      for (let i = 0; i < packedMessage.length; i++) packedMessage[i] = view.getUint32(i * 4, false);

      const textures = [];
      const framebuffer = gl.createFramebuffer();
      try {
        const texture = (unit, width, height, data) => {
          gl.activeTexture(unit);
          const tex = gl.createTexture();
          textures.push(tex);
          gl.bindTexture(gl.TEXTURE_2D, tex);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
          gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, width, height);
          if (data) gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RGBA_INTEGER, gl.UNSIGNED_INT, data);
          return tex;
        };
        const input = texture(gl.TEXTURE0, count, 1, packedKeys);
        texture(gl.TEXTURE1, 4, blocks, packedMessage);
        const output = texture(gl.TEXTURE0, count, 1);
        gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, output, 0);
        gl.drawBuffers([gl.COLOR_ATTACHMENT0]);
        if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE)
          throw new Error('Не удалось создать framebuffer для MIC');
        gl.useProgram(this.program);
        gl.bindTexture(gl.TEXTURE_2D, input);
        gl.uniform1i(this.uKeys, 0);
        gl.uniform1i(this.uMessage, 1);
        gl.uniform1i(this.uBlocks, blocks);
        gl.viewport(0, 0, count, 1);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
        const readback = new Uint32Array(count * 4);
        gl.readBuffer(gl.COLOR_ATTACHMENT0);
        gl.readPixels(0, 0, count, 1, gl.RGBA_INTEGER, gl.UNSIGNED_INT, readback);
        const error = gl.getError();
        if (error !== gl.NO_ERROR || gl.isContextLost()) throw new Error(`Ошибка WebGL2: ${error}`);
        return keys.map((_, i) => {
          const mic = new Uint8Array(16);
          const view = new DataView(mic.buffer);
          for (let j = 0; j < 4; j++) view.setUint32(j * 4, readback[i * 4 + j], false);
          return mic;
        });
      } finally {
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
        for (const unit of [gl.TEXTURE0, gl.TEXTURE1]) {
          gl.activeTexture(unit);
          gl.bindTexture(gl.TEXTURE_2D, null);
        }
        gl.activeTexture(gl.TEXTURE0);
        for (const tex of textures) gl.deleteTexture(tex);
        gl.deleteFramebuffer(framebuffer);
      }
    }

    dispose() {
      if (this.program) this.gl.deleteProgram(this.program);
      this.program = null;
    }
  }
  globalThis.WebGL2MIC = WebGL2MIC;
})();
