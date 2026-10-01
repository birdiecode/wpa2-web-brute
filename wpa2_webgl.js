// Load wpa2_webgl_pmk.js, wpa2_webgl_ptk.js and wpa2_webgl_mic.js first.
// Only their shader sources are reused; no standalone backend instances are created.
// await new WPA2WebGL().derive(passwords, ssid, keyData, message) -> [{ mic }].
// PMK and full PTK stay in GPU textures. Only the final 16-byte MIC is read back.
// keyData must already be ordered; the EAPOL MIC field must already be zeroed.
(() => {
  class WPA2WebGL {
    constructor() {
      if (typeof WebGL2PMK === 'undefined' || typeof WebGL2PTK === 'undefined' || typeof WebGL2MIC === 'undefined')
        throw new Error('Сначала подключите WebGL2-модули PMK, PTK и MIC');
      this.canvas = document.createElement('canvas');
      this.gl = this.canvas.getContext('webgl2', {
        antialias: false, depth: false, stencil: false, preserveDrawingBuffer: false,
      });
      if (!this.gl) throw new Error('WebGL2 недоступен');
      this.busy = false;
      this.disposed = false;
      this.programs = [];
      try {
        this.pmk = this._program(WebGL2PMK.shaders, ['uPasswords', 'uCount', 'uSsidLen', 'uSsid[0]']);
        this.ptk = this._program(WebGL2PTK.shaders, ['uPmks', 'uPmksTail', 'uSplitPmks', 'uMessage[0]']);
        this.mic = this._program(WebGL2MIC.shaders, ['uKeys', 'uMessage', 'uBlocks']);
      } catch (error) {
        this.dispose();
        throw error;
      }
    }

    _program(sources, uniforms) {
      const gl = this.gl;
      const program = gl.createProgram();
      const shaders = [];
      this.programs.push(program);
      try {
        for (const [type, source] of [[gl.VERTEX_SHADER, sources.vertex], [gl.FRAGMENT_SHADER, sources.fragment]]) {
          const shader = gl.createShader(type);
          shaders.push(shader);
          gl.shaderSource(shader, source);
          gl.compileShader(shader);
          if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader));
          gl.attachShader(program, shader);
        }
        gl.linkProgram(program);
        if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program));
        return { program, uniforms: Object.fromEntries(uniforms.map(name => [name, gl.getUniformLocation(program, name)])) };
      } finally {
        for (const shader of shaders) gl.deleteShader(shader);
      }
    }

    // Async API for compatibility; the final readPixels still blocks the calling thread.
    async derive(passwords, ssid, keyData, message) {
      if (this.disposed) throw new Error('WPA2WebGL уже освобождён');
      if (this.busy) throw new Error('Дождитесь завершения предыдущего расчёта');
      const gl = this.gl;
      if (gl.isContextLost()) throw new Error('Контекст WebGL2 потерян');
      const encoder = new TextEncoder();
      if (!Array.isArray(passwords)) throw new TypeError('passwords должен быть массивом строк');
      const encoded = passwords.map(password => {
        if (typeof password !== 'string' || encoder.encode(password).length !== 8)
          throw new TypeError('Каждый пароль должен содержать ровно 8 байт UTF-8');
        return encoder.encode(password);
      });
      if (typeof ssid !== 'string' || encoder.encode(ssid).length > 32)
        throw new TypeError('SSID должен быть строкой длиной до 32 байт UTF-8');
      if (!(keyData instanceof Uint8Array) || keyData.length !== 76)
        throw new TypeError('keyData должен содержать ровно 76 байт (Uint8Array)');
      if (!(message instanceof Uint8Array)) throw new TypeError('message должен быть Uint8Array');
      const maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      const limit = Math.min(maxTexture, gl.getParameter(gl.MAX_VIEWPORT_DIMS)[0]);
      const count = passwords.length;
      if (count > limit) throw new RangeError(`Размер пачки не должен превышать ${limit}`);
      const blocks = Math.ceil((message.length + 9) / 64);
      if (blocks > maxTexture) throw new RangeError(`Сообщение не должно превышать ${maxTexture * 64 - 9} байт`);
      if (!count) return [];

      // CPU prepares only the original inputs and SHA-1 padding, never intermediate keys.
      const packedPasswords = new Uint32Array(count * 4);
      encoded.forEach((bytes, i) => {
        const view = new DataView(bytes.buffer, bytes.byteOffset, 8);
        packedPasswords[i * 4] = view.getUint32(0, false);
        packedPasswords[i * 4 + 1] = view.getUint32(4, false);
      });
      const ssidBytes = encoder.encode(ssid);
      const ssidWords = new Uint32Array(32);
      ssidWords.set(ssidBytes);
      const ptkMessage = new Uint8Array(128);
      ptkMessage.set(encoder.encode('Pairwise key expansion'));
      ptkMessage.set(keyData, 23);
      ptkMessage[100] = 0x80;
      new DataView(ptkMessage.buffer).setUint32(124, 164 * 8, false);
      const micMessage = new Uint8Array(blocks * 64);
      micMessage.set(message);
      micMessage[message.length] = 0x80;
      const micView = new DataView(micMessage.buffer);
      const bits = (64 + message.length) * 8;
      micView.setUint32(micMessage.length - 8, Math.floor(bits / 0x100000000), false);
      micView.setUint32(micMessage.length - 4, bits >>> 0, false);
      const words = bytes => {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        return Uint32Array.from({ length: bytes.length / 4 }, (_, i) => view.getUint32(i * 4, false));
      };

      this.busy = true;
      const textures = [];
      const framebuffers = [];
      try {
        this.canvas.width = count;
        this.canvas.height = 1;
        gl.activeTexture(gl.TEXTURE0);
        const texture = (width, height, data) => {
          const tex = gl.createTexture();
          textures.push(tex);
          gl.bindTexture(gl.TEXTURE_2D, tex);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
          gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
          gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32UI, width, height);
          if (data) gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RGBA_INTEGER, gl.UNSIGNED_INT, data);
          return tex;
        };
        const target = size => {
          const fb = gl.createFramebuffer();
          framebuffers.push(fb);
          gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
          const outputs = Array.from({ length: size }, (_, i) => {
            const tex = texture(count, 1);
            gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0 + i, gl.TEXTURE_2D, tex, 0);
            return tex;
          });
          gl.drawBuffers(outputs.map((_, i) => gl.COLOR_ATTACHMENT0 + i));
          if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE)
            throw new Error('Не удалось создать framebuffer');
          return { fb, outputs };
        };
        const input = texture(count, 1, packedPasswords);
        const messageTexture = texture(4, blocks, words(micMessage));
        const pmk = target(2);
        const ptk = target(4);
        const mic = target(1);
        const bind = (unit, tex) => {
          gl.activeTexture(gl.TEXTURE0 + unit);
          gl.bindTexture(gl.TEXTURE_2D, tex);
        };
        const begin = (stage, output) => {
          gl.bindFramebuffer(gl.FRAMEBUFFER, output.fb);
          gl.useProgram(stage.program);
          gl.viewport(0, 0, count, 1);
        };

        begin(this.pmk, pmk);
        bind(0, input);
        gl.uniform1i(this.pmk.uniforms.uPasswords, 0);
        gl.uniform1ui(this.pmk.uniforms.uCount, count);
        gl.uniform1ui(this.pmk.uniforms.uSsidLen, ssidBytes.length);
        gl.uniform1uiv(this.pmk.uniforms['uSsid[0]'], ssidWords);
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        // Two PMK render targets feed the PTK shader directly, without readback.
        begin(this.ptk, ptk);
        bind(0, pmk.outputs[0]);
        bind(1, pmk.outputs[1]);
        gl.uniform1i(this.ptk.uniforms.uPmks, 0);
        gl.uniform1i(this.ptk.uniforms.uPmksTail, 1);
        gl.uniform1i(this.ptk.uniforms.uSplitPmks, 1);
        gl.uniform1uiv(this.ptk.uniforms['uMessage[0]'], words(ptkMessage));
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        // PTK's first render target is its first 16 bytes (KCK).
        begin(this.mic, mic);
        bind(0, ptk.outputs[0]);
        bind(1, messageTexture);
        gl.uniform1i(this.mic.uniforms.uKeys, 0);
        gl.uniform1i(this.mic.uniforms.uMessage, 1);
        gl.uniform1i(this.mic.uniforms.uBlocks, blocks);
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        // The only GPU -> JS transfer in the entire pipeline: 16 bytes per password.
        const readback = new Uint32Array(count * 4);
        gl.readBuffer(gl.COLOR_ATTACHMENT0);
        gl.readPixels(0, 0, count, 1, gl.RGBA_INTEGER, gl.UNSIGNED_INT, readback);
        const error = gl.getError();
        if (error !== gl.NO_ERROR || gl.isContextLost()) throw new Error(`Ошибка WebGL2: ${error}`);
        return Array.from({ length: count }, (_, i) => {
          const mic = new Uint8Array(16);
          const view = new DataView(mic.buffer);
          for (let j = 0; j < 4; j++) view.setUint32(j * 4, readback[i * 4 + j], false);
          return { mic };
        });
      } finally {
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
        for (const unit of [0, 1]) {
          gl.activeTexture(gl.TEXTURE0 + unit);
          gl.bindTexture(gl.TEXTURE_2D, null);
        }
        gl.activeTexture(gl.TEXTURE0);
        for (const fb of framebuffers) gl.deleteFramebuffer(fb);
        for (const tex of textures) gl.deleteTexture(tex);
        this.busy = false;
      }
    }

    dispose() {
      if (this.busy) throw new Error('Нельзя освободить WPA2WebGL во время расчёта');
      if (this.disposed) return;
      this.disposed = true;
      for (const program of this.programs) this.gl.deleteProgram(program);
      this.programs = [];
      this.gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  }
  globalThis.WPA2WebGL = WPA2WebGL;
})();
