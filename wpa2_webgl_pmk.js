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
    this.program = this._program(VS, FS);
    this.uCount = gl.getUniformLocation(this.program, "uCount");
    this.uSsidLen = gl.getUniformLocation(this.program, "uSsidLen");
    this.uSsid = gl.getUniformLocation(this.program, "uSsid[0]");
  }
  _shader(type, src) {
    const g = this.gl;
    const s = g.createShader(type);
    g.shaderSource(s, src);
    g.compileShader(s);
    if (!g.getShaderParameter(s, g.COMPILE_STATUS))
      throw new Error(g.getShaderInfoLog(s));
    return s;
  }
  _program(vs, fs) {
    const g = this.gl;
    const p = g.createProgram();
    g.attachShader(p, this._shader(g.VERTEX_SHADER, vs));
    g.attachShader(p, this._shader(g.FRAGMENT_SHADER, fs));
    g.linkProgram(p);
    if (!g.getProgramParameter(p, g.LINK_STATUS))
      throw new Error(g.getProgramInfoLog(p));
    return p;
  }
  async derive(passwords, ssid) {
    const gl = this.gl;
    const packed = WebGL2PMK.packPasswords(passwords);
    const n = passwords.length;
    if (!n) return [];
    if (n > gl.getParameter(gl.MAX_TEXTURE_SIZE))
      throw new Error("batch too large");
    if (typeof ssid !== "string") throw new TypeError("SSID должен быть строкой");
    const ssidBytes = new TextEncoder().encode(ssid);
    if (ssidBytes.length < 1 || ssidBytes.length > 32)
      throw new Error("SSID должен быть 1–32 байта UTF-8");
    this.canvas.width = n;
    this.canvas.height = 1;
    const inTex = gl.createTexture();
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
      const t = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, t);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, n, 1);
      return t;
    }
    const out0 = mkOut();
    const out1 = mkOut();
    const fb = gl.createFramebuffer();
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
    gl.deleteTexture(inTex);
    gl.deleteTexture(out0);
    gl.deleteTexture(out1);
    gl.deleteFramebuffer(fb);
    return result;
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
/*
 * ============================================================
 * HMAC-SHA1(password, SSID || INT(block))
 *
 * Password = 8–63 байта, дополненные нулями до 64 байт
 * ============================================================
 */
void hmacPwdSalt(
    uint key[16],
    uint block,
    out uvec4 dh,
    out uint de
) {
    uint W[80];
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    /*
     * ipad
     */
    for (int i = 0; i < 16; i++)
        W[i] = key[i] ^ 0x36363636u;
    uvec4 h;
    uint e;
    shaInit(h, e);
    shaBlock(
        h,
        e,
        W
    );
    /*
     * SSID || INT(block)
     */
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    for (int i = 0; i < 32; i++) {
        if (uint(i) < uSsidLen) {
            uint wi =
                uint(i) >> 2u;
            uint sh =
                24u -
                8u *
                (uint(i) & 3u);
            W[int(wi)] |=
                (uSsid[i] & 255u)
                << sh;
        }
    }
    uint p = uSsidLen;
    /*
     * PBKDF2 block number
     *
     * big endian uint32
     */
    for (int j = 0; j < 4; j++) {
        uint v =
            (
                block >>
                (uint(3 - j) * 8u)
            ) & 255u;
        uint q =
            p +
            uint(j);
        W[int(q >> 2u)] |=
            v <<
            (
                24u -
                8u *
                (q & 3u)
            );
    }
    uint ml =
        p + 4u;
    uint q =
        ml;
    /*
     * SHA padding
     */
    W[int(q >> 2u)] |=
        0x80u <<
        (
            24u -
            8u *
            (q & 3u)
        );
    W[15] =
        (64u + ml) *
        8u;
    shaBlock(
        h,
        e,
        W
    );
    /*
     * outer HMAC
     */
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    for (int i = 0; i < 16; i++)
        W[i] = key[i] ^ 0x5c5c5c5cu;
    uvec4 oh;
    uint oe;
    shaInit(
        oh,
        oe
    );
    shaBlock(
        oh,
        oe,
        W
    );
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    W[0] = h.x;
    W[1] = h.y;
    W[2] = h.z;
    W[3] = h.w;
    W[4] = e;
    W[5] =
        0x80000000u;
    W[15] =
        (64u + 20u) *
        8u;
    shaBlock(
        oh,
        oe,
        W
    );
    dh = oh;
    de = oe;
}
/*
 * ============================================================
 * HMAC(password, previous U)
 *
 * previous U = SHA1 = 20 bytes
 * ============================================================
 */
void hmacPwd20(
    uint key[16],
    uvec4 m,
    uint me,
    out uvec4 dh,
    out uint de
) {
    uint W[80];
    /*
     * inner key
     */
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    for (int i = 0; i < 16; i++)
        W[i] = key[i] ^ 0x36363636u;
    uvec4 h;
    uint e;
    shaInit(
        h,
        e
    );
    shaBlock(
        h,
        e,
        W
    );
    /*
     * previous SHA1 result
     */
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    W[0] = m.x;
    W[1] = m.y;
    W[2] = m.z;
    W[3] = m.w;
    W[4] = me;
    W[5] =
        0x80000000u;
    W[15] =
        (64u + 20u) *
        8u;
    shaBlock(
        h,
        e,
        W
    );
    /*
     * outer
     */
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    for (int i = 0; i < 16; i++)
        W[i] = key[i] ^ 0x5c5c5c5cu;
    uvec4 oh;
    uint oe;
    shaInit(
        oh,
        oe
    );
    shaBlock(
        oh,
        oe,
        W
    );
    for (int i = 0; i < 80; i++)
        W[i] = 0u;
    W[0] = h.x;
    W[1] = h.y;
    W[2] = h.z;
    W[3] = h.w;
    W[4] = e;
    W[5] =
        0x80000000u;
    W[15] =
        (64u + 20u) *
        8u;
    shaBlock(
        oh,
        oe,
        W
    );
    dh = oh;
    de = oe;
}
/*
 * ============================================================
 * Один PBKDF2 block
 * ============================================================
 */
void pbkdfBlock(
    uint key[16],
    uint block,
    out uvec4 r,
    out uint re
) {
    uvec4 u;
    uint ue;
    /*
     * U1
     */
    hmacPwdSalt(
        key,
        block,
        u,
        ue
    );
    r = u;
    re = ue;
    /*
     * U2 ... U4096
     */
    for (int i = 1; i < 4096; i++) {
        hmacPwd20(
            key,
            u,
            ue,
            u,
            ue
        );
        r ^= u;
        re ^= ue;
    }
}
/*
 * ============================================================
 * main
 * ============================================================
 */
void main() {
    uint id =
        uint(gl_FragCoord.x);
    if (id >= uCount) {
        o0 =
            uvec4(0);
        o1 =
            uvec4(0);
        return;
    }
    /*
     * Получаем пароль
     */
    uint key[16];
    for (int row = 0; row < 4; row++) {
        uvec4 p = texelFetch(uPasswords, ivec2(int(id), row), 0);
        key[row * 4] = p.x;
        key[row * 4 + 1] = p.y;
        key[row * 4 + 2] = p.z;
        key[row * 4 + 3] = p.w;
    }
    /*
     * WPA2 PMK:
     *
     * PBKDF2-HMAC-SHA1
     *
     * output = 32 bytes
     */
    uvec4 a;
    uvec4 b;
    uint ae;
    uint be;
    pbkdfBlock(
        key,
        1u,
        a,
        ae
    );
    pbkdfBlock(
        key,
        2u,
        b,
        be
    );
    /*
     * PBKDF2 output:
     *
     * T1 = 20 bytes
     * T2 = берем первые 12 bytes
     *
     * PMK = 32 bytes
     */
    o0 = a;
    o1 = uvec4(
        ae,
        b.x,
        b.y,
        b.z
    );
}
`;
