const enc = new TextEncoder();
async function calc_pmk(password, ssid) {
  if (typeof password !== 'string' || enc.encode(password).length < 8 || enc.encode(password).length > 63)
    throw new TypeError('Пароль: 8–63 байта UTF-8');
  if (typeof ssid !== 'string' || enc.encode(ssid).length < 1 || enc.encode(ssid).length > 32)
    throw new TypeError('SSID: 1–32 байта UTF-8');
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(ssid), iterations: 4096, hash: 'SHA-1' }, key, 256));
}
async function hmac(key, message) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, message));
}
async function calc_ptk(pmk, keyData) {
  if (!(pmk instanceof Uint8Array) || pmk.length !== 32) throw new TypeError('PMK: 32 байта');
  if (!(keyData instanceof Uint8Array) || keyData.length !== 76) throw new TypeError('keyData: 76 байт');
  const message = new Uint8Array(100);
  message.set(enc.encode('Pairwise key expansion'));
  message.set(keyData, 23);
  const result = new Uint8Array(80);
  for (let i = 0; i < 4; i++) { message[99] = i; result.set(await hmac(pmk, message), i * 20); }
  return result.slice(0, 64);
}
async function calc_mic(kck, message) {
  if (!(kck instanceof Uint8Array) || kck.length !== 16) throw new TypeError('KCK: 16 байт');
  if (!(message instanceof Uint8Array)) throw new TypeError('message: Uint8Array');
  return (await hmac(kck, message)).slice(0, 16);
}
class WPA2WebCrypto {
  static async create() { return new WPA2WebCrypto(); }
  async derive(passwords, ssid, keyData, message) {
    if (!Array.isArray(passwords) || passwords.length < 1 || passwords.length > 32768) throw new RangeError('Batch: 1–32768');
    const result = [];
    for (const password of passwords) {
      const pmk = await calc_pmk(password, ssid);
      const ptk = await calc_ptk(pmk, keyData);
      result.push({ mic: await calc_mic(ptk.slice(0, 16), message) });
    }
    return result;
  }
  dispose() {}
}
