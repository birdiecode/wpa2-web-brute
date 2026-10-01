// WPA2 PRF-512: PMK (32 bytes) + keyData (76 bytes) -> PTK (64 bytes).
// keyData = min(AP, STA) || max(AP, STA) || min(ANonce, SNonce) || max(ANonce, SNonce).
// Usage: const ptks = await new WebGL2PTK().derive([pmk], keyData);
// One fragment per PMK. The context and shader names are private to this backend.
(() => {
  const vertexSource = `#version 300 es
void main() {
    vec2 p = vec2((gl_VertexID << 1) & 2, gl_VertexID & 2);
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

  const fragmentSource = `#version 300 es
precision highp float;
precision highp int;
uniform highp usampler2D uPmks;
uniform uint uMessage[32];
layout(location = 0) out uvec4 o0;
layout(location = 1) out uvec4 o1;
layout(location = 2) out uvec4 o2;
layout(location = 3) out uvec4 o3;

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
    int id = int(gl_FragCoord.x);
    uvec4 p0 = texelFetch(uPmks, ivec2(id, 0), 0);
    uvec4 p1 = texelFetch(uPmks, ivec2(id, 1), 0);
    uint key[8] = uint[8](p0.x, p0.y, p0.z, p0.w, p1.x, p1.y, p1.z, p1.w);
    uint w[80], inner[5], outer[5];
    shaInit(inner);
    shaInit(outer);
    for (int i = 0; i < 16; i++) w[i] = 0x36363636u;
    for (int i = 0; i < 8; i++) w[i] ^= key[i];
    shaBlock(inner, w);
    for (int i = 0; i < 16; i++) w[i] = 0x5c5c5c5cu;
    for (int i = 0; i < 8; i++) w[i] ^= key[i];
    shaBlock(outer, w);

    uint result[20];
    for (int counter = 0; counter < 4; counter++) {
        uint h[5];
        for (int i = 0; i < 5; i++) h[i] = inner[i];
        // 100-byte message: label (22) + zero (1) + keyData (76) + counter (1).
        for (int i = 0; i < 16; i++) w[i] = uMessage[i];
        shaBlock(h, w);
        for (int i = 0; i < 16; i++) w[i] = uMessage[16+i];
        w[8] |= uint(counter); // Message byte 99; the base value is zero.
        shaBlock(h, w);
        for (int i = 0; i < 16; i++) w[i] = 0u;
        for (int i = 0; i < 5; i++) w[i] = h[i];
        w[5] = 0x80000000u;
        w[15] = 84u * 8u;
        for (int i = 0; i < 5; i++) h[i] = outer[i];
        shaBlock(h, w);
        for (int i = 0; i < 5; i++) result[counter * 5 + i] = h[i];
    }
    // First 64 bytes of the concatenated four SHA-1 digests.
    o0 = uvec4(result[0], result[1], result[2], result[3]);
    o1 = uvec4(result[4], result[5], result[6], result[7]);
    o2 = uvec4(result[8], result[9], result[10], result[11]);
    o3 = uvec4(result[12], result[13], result[14], result[15]);
}`;

  class WebGL2PTK {
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
        this.uPmks = gl.getUniformLocation(program, 'uPmks');
        this.uMessage = gl.getUniformLocation(program, 'uMessage[0]');
      } catch (error) {
        gl.deleteProgram(program);
        throw error;
      } finally {
        for (const shader of shaders) gl.deleteShader(shader);
      }
    }

    // pmks: Uint8Array[32][]; keyData: Uint8Array[76]. Returns Uint8Array[64][].
    // Readback is synchronous, so awaiting this method does not move work off the UI thread.
    async derive(pmks, keyData) {
      if (!this.program) throw new Error('WebGL2PTK уже освобождён');
      const gl = this.gl;
      if (gl.isContextLost()) throw new Error('Контекст WebGL2 потерян');
      if (!Array.isArray(pmks)) throw new TypeError('pmks должен быть массивом Uint8Array');
      if (!(keyData instanceof Uint8Array) || keyData.length !== 76)
        throw new TypeError('keyData должен содержать ровно 76 байт (Uint8Array)');
      for (const pmk of pmks) {
        if (!(pmk instanceof Uint8Array) || pmk.length !== 32)
          throw new TypeError('Каждый PMK должен содержать ровно 32 байта (Uint8Array)');
      }
      const count = pmks.length;
      if (!count) return [];
      const maxWidth = Math.min(gl.getParameter(gl.MAX_TEXTURE_SIZE), gl.getParameter(gl.MAX_VIEWPORT_DIMS)[0]);
      if (count > maxWidth) throw new RangeError(`Размер пачки не должен превышать ${maxWidth}`);
      this.canvas.width = count;
      this.canvas.height = 1;

      const packed = new Uint32Array(count * 8);
      for (let i = 0; i < count; i++) {
        const view = new DataView(pmks[i].buffer, pmks[i].byteOffset, 32);
        for (let j = 0; j < 8; j++)
          packed[(j >> 2) * count * 4 + i * 4 + (j & 3)] = view.getUint32(j * 4, false);
      }
      const message = new Uint8Array(128);
      message.set(new TextEncoder().encode('Pairwise key expansion'));
      message.set(keyData, 23);
      message[100] = 0x80;
      // SHA-1 length includes the 64-byte HMAC ipad block.
      new DataView(message.buffer).setUint32(124, (64 + 100) * 8, false);
      const words = new Uint32Array(32);
      const view = new DataView(message.buffer);
      for (let i = 0; i < 32; i++) words[i] = view.getUint32(i * 4, false);

      const textures = [];
      const framebuffer = gl.createFramebuffer();
      try {
        gl.activeTexture(gl.TEXTURE0);
        const texture = height => {
          const tex = gl.createTexture();
          textures.push(tex);
          gl.bindTexture(gl.TEXTURE_2D, tex);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
          gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, count, height);
          return tex;
        };
        const input = texture(2);
        gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, count, 2, gl.RGBA_INTEGER, gl.UNSIGNED_INT, packed);
        gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
        const attachments = [];
        for (let i = 0; i < 4; i++) {
          const output = texture(1);
          const attachment = gl.COLOR_ATTACHMENT0 + i;
          attachments.push(attachment);
          gl.framebufferTexture2D(gl.FRAMEBUFFER, attachment, gl.TEXTURE_2D, output, 0);
        }
        gl.drawBuffers(attachments);
        if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE)
          throw new Error('Не удалось создать framebuffer для PTK');
        gl.useProgram(this.program);
        gl.bindTexture(gl.TEXTURE_2D, input);
        gl.uniform1i(this.uPmks, 0);
        gl.uniform1uiv(this.uMessage, words);
        gl.viewport(0, 0, count, 1);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
        const result = Array.from({ length: count }, () => new Uint8Array(64));
        const readback = new Uint32Array(count * 4);
        for (let part = 0; part < 4; part++) {
          gl.readBuffer(attachments[part]);
          // readPixels waits for the draw to finish.
          gl.readPixels(0, 0, count, 1, gl.RGBA_INTEGER, gl.UNSIGNED_INT, readback);
          for (let i = 0; i < count; i++) {
            const output = new DataView(result[i].buffer);
            for (let j = 0; j < 4; j++) output.setUint32(part * 16 + j * 4, readback[i * 4 + j], false);
          }
        }
        const error = gl.getError();
        if (error !== gl.NO_ERROR || gl.isContextLost()) throw new Error(`Ошибка WebGL2: ${error}`);
        return result;
      } finally {
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
        gl.bindTexture(gl.TEXTURE_2D, null);
        for (const tex of textures) gl.deleteTexture(tex);
        gl.deleteFramebuffer(framebuffer);
      }
    }

    dispose() {
      if (this.program) this.gl.deleteProgram(this.program);
      this.program = null;
    }
  }
  globalThis.WebGL2PTK = WebGL2PTK;
})();
