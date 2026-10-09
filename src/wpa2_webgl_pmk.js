// WebGL2 PBKDF2-HMAC-SHA1 backend for 8–63-byte UTF-8 WPA2 passwords.
// One fragment = one password. Two RGBA32UI render targets = 32-byte PMK.
class WebGL2PMK {
  static get shaders() {
    return { vertex: VS, fragment: FS };
  }
  // Four RGBA32UI rows: each candidate holds 16 big-endian words (64 bytes).
  static packPasswords(passwords) {
    if (!Array.isArray(passwords)) throw new TypeError("Пароли должны быть массивом строк");
    const packed = new Uint32Array(passwords.length * 16);
    const encoder = new TextEncoder();
    passwords.forEach((password, candidate) => {
      if (typeof password !== "string") throw new TypeError("Пароль должен быть строкой");
      const bytes = encoder.encode(password);
      if (bytes.length < 8 || bytes.length > 63)
        throw new Error("Пароль должен быть 8–63 байта UTF-8");
      for (let j = 0; j < bytes.length; j++) {
        const word = j >>> 2;
        const index = (word >>> 2) * passwords.length * 4 + candidate * 4 + (word & 3);
        packed[index] |= bytes[j] << (24 - (j & 3) * 8);
      }
    });
    return packed;
  }
  constructor() {
    this.canvas = document.createElement("canvas");
    this.gl = this.canvas.getContext("webgl2", {
      antialias: false,
      depth: false,
      stencil: false,
      preserveDrawingBuffer: false,
    });
    if (!this.gl) throw new Error("WebGL2 unavailable");
    const gl = this.gl;
    this.program = null;
    this.disposed = false;
    try {
      this.program = this._program(VS, FS);
      this.uCount = gl.getUniformLocation(this.program, "uCount");
      this.uSsidLen = gl.getUniformLocation(this.program, "uSsidLen");
      this.uSsid = gl.getUniformLocation(this.program, "uSsid[0]");
    } catch (error) {
      this.dispose();
      throw error;
    }
  }
  _shader(type, src) {
    const g = this.gl;
    const s = g.createShader(type);
    if (!s) throw new Error("Unable to create WebGL shader");
    try {
      g.shaderSource(s, src);
      g.compileShader(s);
      if (!g.getShaderParameter(s, g.COMPILE_STATUS))
        throw new Error(g.getShaderInfoLog(s));
      return s;
    } catch (error) {
      g.deleteShader(s);
      throw error;
    }
  }
  _program(vs, fs) {
    const g = this.gl;
    const p = g.createProgram();
    if (!p) throw new Error("Unable to create WebGL program");
    const shaders = [];
    try {
      for (const [type, source] of [[g.VERTEX_SHADER, vs], [g.FRAGMENT_SHADER, fs]]) {
        const shader = this._shader(type, source);
        shaders.push(shader);
        g.attachShader(p, shader);
      }
      g.linkProgram(p);
      if (!g.getProgramParameter(p, g.LINK_STATUS))
        throw new Error(g.getProgramInfoLog(p));
      return p;
    } catch (error) {
      g.deleteProgram(p);
      throw error;
    } finally {
      // Detach so successfully linked programs do not retain deleted shaders.
      for (const shader of shaders) {
        if (g.isProgram(p)) g.detachShader(p, shader);
        g.deleteShader(shader);
      }
    }
  }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.gl.useProgram(null);
    if (this.program) this.gl.deleteProgram(this.program);
    this.program = null;
    this.gl.getExtension("WEBGL_lose_context")?.loseContext();
  }
  async derive(passwords, ssid) {
    if (this.disposed) throw new Error("WebGL2PMK already disposed");
    const gl = this.gl;
    if (gl.isContextLost()) throw new Error("WebGL2 context lost");
    const packed = WebGL2PMK.packPasswords(passwords);
    const n = passwords.length;
    if (!n) return [];
    const limit = Math.min(gl.getParameter(gl.MAX_TEXTURE_SIZE), gl.getParameter(gl.MAX_VIEWPORT_DIMS)[0]);
    if (n > 32768) throw new RangeError('Размер пачки не должен превышать 32768');
    // Keep each draw within hardware limits; only final results cross to JS.
    if (n > limit) {
      const result = [];
      for (let offset = 0; offset < n; offset += limit) {
        const part = await this.derive(passwords.slice(offset, offset + limit), ssid);
        for (const value of part) result.push(value);
      }
      return result;
    }
    if (typeof ssid !== "string") throw new TypeError("SSID должен быть строкой");
    const ssidBytes = new TextEncoder().encode(ssid);
    if (ssidBytes.length < 1 || ssidBytes.length > 32)
      throw new Error("SSID должен быть 1–32 байта UTF-8");
    this.canvas.width = n;
    this.canvas.height = 1;
    const textures = [];
    let fb = null;
    const texture = () => {
      const tex = gl.createTexture();
      if (!tex) throw new Error("Unable to create WebGL texture");
      textures.push(tex);
      return tex;
    };
    try {
      const inTex = texture();
      gl.bindTexture(gl.TEXTURE_2D, inTex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, n, 4);
      gl.texSubImage2D(
        gl.TEXTURE_2D,
        0,
        0,
        0,
        n,
        4,
        gl.RGBA_INTEGER,
        gl.UNSIGNED_INT,
        packed,
      );
      function mkOut() {
        const t = texture();
        gl.bindTexture(gl.TEXTURE_2D, t);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, n, 1);
        return t;
      }
      const out0 = mkOut();
      const out1 = mkOut();
      fb = gl.createFramebuffer();
      if (!fb) throw new Error("Unable to create WebGL framebuffer");
      gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
      gl.framebufferTexture2D(
        gl.FRAMEBUFFER,
        gl.COLOR_ATTACHMENT0,
        gl.TEXTURE_2D,
        out0,
        0,
      );
      gl.framebufferTexture2D(
        gl.FRAMEBUFFER,
        gl.COLOR_ATTACHMENT1,
        gl.TEXTURE_2D,
        out1,
        0,
      );
      gl.drawBuffers([gl.COLOR_ATTACHMENT0, gl.COLOR_ATTACHMENT1]);
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) {
        throw new Error("integer framebuffer incomplete");
      }
      gl.useProgram(this.program);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, inTex);
      gl.uniform1i(gl.getUniformLocation(this.program, "uPasswords"), 0);
      gl.uniform1ui(this.uCount, n);
      gl.uniform1ui(this.uSsidLen, ssidBytes.length);
      const su = new Uint32Array(32);
      for (let i = 0; i < ssidBytes.length; i++) su[i] = ssidBytes[i];
      gl.uniform1uiv(this.uSsid, su);
      gl.viewport(0, 0, n, 1);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      /*
       * ВАЖНО:
       * gl.finish() блокирует CPU до окончания GPU.
       * Для первого тестового варианта это нормально.
       */
      gl.finish();
      const a = new Uint32Array(n * 4);
      const b = new Uint32Array(n * 4);
      gl.readBuffer(gl.COLOR_ATTACHMENT0);
      gl.readPixels(0, 0, n, 1, gl.RGBA_INTEGER, gl.UNSIGNED_INT, a);
      gl.readBuffer(gl.COLOR_ATTACHMENT1);
      gl.readPixels(0, 0, n, 1, gl.RGBA_INTEGER, gl.UNSIGNED_INT, b);
      // WebGL failures usually set an error flag instead of throwing.
      // Validate both readbacks before exposing any PMK bytes.
      const error = gl.getError();
      if (gl.isContextLost()) throw new Error("WebGL2 context lost during PMK readback");
      if (error !== gl.NO_ERROR) throw new Error(`WebGL2 PMK readback failed: ${error}`);
      const result = [];
      for (let i = 0; i < n; i++) {
        const pmk = new Uint8Array(32);
        const words = [
          a[i * 4],
          a[i * 4 + 1],
          a[i * 4 + 2],
          a[i * 4 + 3],
          b[i * 4],
          b[i * 4 + 1],
          b[i * 4 + 2],
          b[i * 4 + 3],
        ];
        for (let w = 0; w < 8; w++) {
          pmk[w * 4] = words[w] >>> 24;
          pmk[w * 4 + 1] = (words[w] >>> 16) & 255;
          pmk[w * 4 + 2] = (words[w] >>> 8) & 255;
          pmk[w * 4 + 3] = words[w] & 255;
        }
        result.push(pmk);
      }
      return result;
    } finally {
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.bindTexture(gl.TEXTURE_2D, null);
      if (fb) gl.deleteFramebuffer(fb);
      for (const tex of textures) gl.deleteTexture(tex);
    }
  }
}
/*
 * ============================================================
 * Vertex shader
 * ============================================================
 */
const VS = `#version 300 es
void main() {
    vec2 p = vec2(
        (gl_VertexID << 1) & 2,
        gl_VertexID & 2
    );
    gl_Position =
        vec4(
            p * 2.0 - 1.0,
            0,
            1
        );
}
`;
/*
 * ============================================================
 * Fragment shader
 *
 * 1 fragment = 1 password
 *
 * fragment выполняет:
 *
 * PBKDF2-HMAC-SHA1(password, SSID, 4096)
 *
 * ============================================================
 */
// Generate static rounds once at script load; no schedule array or round loop on GPU.
function generateWebGLSHA120() {
  const lines = ['void sha20(inout uvec4 h, inout uint he, uvec4 m, uint me) {'];
  for (let i = 0; i < 16; i++) {
    const value = i < 4 ? 'm.' + 'xyzw'[i] : i === 4 ? 'me' :
      i === 5 ? '0x80000000u' : i === 15 ? '672u' : '0u';
    lines.push(`uint w${i} = ${value};`);
  }
  lines.push('uint a=h.x, b=h.y, c=h.z, d=h.w, e=he;');
  for (let i = 0; i < 80; i++) {
    const w = n => 'w' + (n & 15);
    if (i >= 16) lines.push(`${w(i)} = rol(${w(i-3)} ^ ${w(i-8)} ^ ${w(i-14)} ^ ${w(i)}, 1u);`);
    const f = i < 20 ? '((b & c) | ((~b) & d))' : i < 40 ? '(b ^ c ^ d)' :
      i < 60 ? '((b & c) | (b & d) | (c & d))' : '(b ^ c ^ d)';
    const k = ['0x5a827999u','0x6ed9eba1u','0x8f1bbcdcu','0xca62c1d6u'][Math.floor(i/20)];
    lines.push(`{ uint t = rol(a,5u) + ${f} + e + ${k} + ${w(i)};
      e=d; d=c; c=rol(b,30u); b=a; a=t; }`);
  }
  lines.push('h += uvec4(a,b,c,d); he += e;', '}');
  return lines.join('\n');
}
const FS = `#version 300 es
precision highp float;
precision highp int;
uniform highp usampler2D uPasswords;
uniform uint uCount;
uniform uint uSsidLen;
uniform uint uSsid[32];
layout(location = 0)
out uvec4 o0;
layout(location = 1)
out uvec4 o1;
/*
 * rotate-left
 */
uint rol(
    uint x,
    uint n
) {
    return
        (x << n) |
        (x >> (32u - n));
}
/*
 * ============================================================
 * SHA1 block
 * ============================================================
 */
void shaBlock(
    inout uvec4 h0,
    inout uint h4,
    uint W[80]
) {
    for (int i = 16; i < 80; i++) {
        W[i] = rol(
            W[i - 3] ^
            W[i - 8] ^
            W[i - 14] ^
            W[i - 16],
            1u
        );
    }
    uint a = h0.x;
    uint b = h0.y;
    uint c = h0.z;
    uint d = h0.w;
    uint e = h4;
    for (int i = 0; i < 80; i++) {
        uint f;
        uint k;
        if (i < 20) {
            f =
                (b & c) |
                ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f =
                b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f =
                (b & c) |
                (b & d) |
                (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f =
                b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint t =
            rol(a, 5u) +
            f +
            e +
            k +
            W[i];
        e = d;
        d = c;
        c = rol(b, 30u);
        b = a;
        a = t;
    }
    h0 += uvec4(
        a,
        b,
        c,
        d
    );
    h4 += e;
}
void shaInit(
    out uvec4 h,
    out uint e
) {
    h = uvec4(
        0x67452301u,
        0xEFCDAB89u,
        0x98BADCFEu,
        0x10325476u
    );
    e = 0xC3D2E1F0u;
}

// The fixed 20-byte HMAC message includes the already processed 64-byte key block.
${generateWebGLSHA120()}

void keyState(uint key[16], uint pad, out uvec4 h, out uint e) {
    uint W[80];
    for (int i=0; i<16; i++) W[i] = key[i] ^ pad;
    shaInit(h,e);
    shaBlock(h,e,W);
}
void pbkdfBlock(uvec4 ip, uint ie, uvec4 op, uint oe,
               uint blockIndex, out uvec4 result, out uint tail) {
    uint W[80];
    for (int i=0; i<16; i++) W[i]=0u;
    for (int i=0; i<32; i++) {
        if (uint(i)<uSsidLen)
            W[i >> 2] |= uSsid[i] << (24u - (uint(i) & 3u)*8u);
    }
    for (int j=0; j<4; j++) {
        uint pos=uSsidLen+uint(j);
        W[int(pos >> 2u)] |= ((blockIndex >> (24u-uint(j)*8u)) & 255u)
                             << (24u-(pos & 3u)*8u);
    }
    uint len=uSsidLen+4u;
    W[int(len >> 2u)] |= 0x80u << (24u-(len & 3u)*8u);
    W[15]=(64u+len)*8u;
    uvec4 inner=ip;
    uint innerE=ie;
    shaBlock(inner,innerE,W);
    uvec4 u=op;
    uint ue=oe;
    sha20(u,ue,inner,innerE);
    result=u; tail=ue;
    for (int i=1; i<4096; i++) {
        inner=ip; innerE=ie;
        sha20(inner,innerE,u,ue);
        u=op; ue=oe;
        sha20(u,ue,inner,innerE);
        result ^= u; tail ^= ue;
    }
}
void main() {
    uint id=uint(gl_FragCoord.x);
    if (id>=uCount) { o0=uvec4(0u); o1=uvec4(0u); return; }
    uint key[16];
    for (int row=0; row<4; row++) {
        uvec4 p=texelFetch(uPasswords,ivec2(int(id),row),0);
        key[row*4]=p.x; key[row*4+1]=p.y;
        key[row*4+2]=p.z; key[row*4+3]=p.w;
    }
    // Prepare ipad/opad once per candidate, shared by both PBKDF2 blocks.
    uvec4 ip,op;
    uint ie,oe;
    keyState(key,0x36363636u,ip,ie);
    keyState(key,0x5c5c5c5cu,op,oe);
    uvec4 a,b;
    uint ae,be;
    pbkdfBlock(ip,ie,op,oe,1u,a,ae);
    pbkdfBlock(ip,ie,op,oe,2u,b,be);
    o0=a; o1=uvec4(ae,b.xyz);
}
`;

export { WebGL2PMK };
