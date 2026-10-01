// Load wpa2_webgl_pmk.js, wpa2_webgl_ptk.js and wpa2_webgl_mic.js first.
// const gpu = new WPA2WebGL();
// const results = await gpu.derive(passwords, ssid, keyData, message);
// Each result is { pmk: Uint8Array(32), ptk: Uint8Array(64), mic: Uint8Array(16) }.
// keyData must already be ordered; the EAPOL MIC field must already be zeroed.
// Each stage uses its own WebGL context, with CPU readback between stages.
(() => {
  class WPA2WebGL {
    constructor() {
      if (typeof WebGL2PMK === 'undefined' || typeof WebGL2PTK === 'undefined' || typeof WebGL2MIC === 'undefined')
        throw new Error('Сначала подключите WebGL2-модули PMK, PTK и MIC');
      this.busy = false;
      this.disposed = false;
      try {
        this.pmk = new WebGL2PMK();
        this.ptk = new WebGL2PTK();
        this.mic = new WebGL2MIC();
      } catch (error) {
        this.dispose();
        throw error;
      }
    }

    async derive(passwords, ssid, keyData, message) {
      if (this.disposed) throw new Error('WPA2WebGL уже освобождён');
      if (this.busy) throw new Error('Дождитесь завершения предыдущего расчёта');
      const encoder = new TextEncoder();
      if (!Array.isArray(passwords)) throw new TypeError('passwords должен быть массивом строк');
      for (const password of passwords) {
        if (typeof password !== 'string' || encoder.encode(password).length !== 8)
          throw new TypeError('Каждый пароль должен содержать ровно 8 байт UTF-8');
      }
      if (typeof ssid !== 'string' || encoder.encode(ssid).length > 32)
        throw new TypeError('SSID должен быть строкой длиной до 32 байт UTF-8');
      if (!(keyData instanceof Uint8Array) || keyData.length !== 76)
        throw new TypeError('keyData должен содержать ровно 76 байт (Uint8Array)');
      if (!(message instanceof Uint8Array)) throw new TypeError('message должен быть Uint8Array');
      // Validate every stage before starting the expensive PBKDF2 calculation.
      for (const backend of [this.pmk, this.ptk, this.mic]) {
        const gl = backend.gl;
        if (gl.isContextLost()) throw new Error('Контекст WebGL2 потерян');
        const limit = Math.min(gl.getParameter(gl.MAX_TEXTURE_SIZE), gl.getParameter(gl.MAX_VIEWPORT_DIMS)[0]);
        if (passwords.length > limit) throw new RangeError(`Размер пачки не должен превышать ${limit}`);
      }
      const maxMessage = this.mic.gl.getParameter(this.mic.gl.MAX_TEXTURE_SIZE) * 64 - 9;
      if (message.length > maxMessage) throw new RangeError(`Сообщение не должно превышать ${maxMessage} байт`);
      if (!passwords.length) return [];
      // Snapshot inputs: callers may change them while awaiting the result.
      const inputPasswords = passwords.slice();
      const inputKeyData = keyData.slice();
      const inputMessage = message.slice();
      this.busy = true;
      try {
        const pmks = await this.pmk.derive(inputPasswords, ssid);
        const gl = this.pmk.gl;
        const error = gl.getError();
        if (error !== gl.NO_ERROR || gl.isContextLost()) throw new Error(`Ошибка WebGL2 PMK: ${error}`);
        const ptks = await this.ptk.derive(pmks, inputKeyData);
        const mics = await this.mic.derive(ptks.map(ptk => ptk.subarray(0, 16)), inputMessage);
        return pmks.map((pmk, i) => ({ pmk, ptk: ptks[i], mic: mics[i] }));
      } finally {
        this.busy = false;
      }
    }

    dispose() {
      if (this.busy) throw new Error('Нельзя освободить WPA2WebGL во время расчёта');
      if (this.disposed) return;
      this.disposed = true;
      if (this.pmk) {
        this.pmk.gl.deleteProgram(this.pmk.program);
        this.pmk.program = null;
      }
      this.ptk?.dispose();
      this.mic?.dispose();
      for (const backend of [this.pmk, this.ptk, this.mic])
        backend?.gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  }
  globalThis.WPA2WebGL = WPA2WebGL;
})();
