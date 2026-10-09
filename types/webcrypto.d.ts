import type { Bytes, DeriveResult, WPA2Chain } from './common.js';

export function calc_pmk(password: string, ssid: string): Promise<Bytes>;
export function calc_ptk(pmk: Bytes, keyData: Bytes): Promise<Bytes>;
export function calc_mic(kck: Bytes, message: Bytes): Promise<Bytes>;

export class WPA2WebCrypto implements WPA2Chain {
  readonly maxBatch: 32768;
  static create(): Promise<WPA2WebCrypto>;
  derive(passwords: string[], ssid: string, keyData: Bytes, message: Bytes): Promise<DeriveResult>;
  dispose(): void;
}

declare const _default: {
  WPA2WebCrypto: typeof WPA2WebCrypto;
  calc_pmk: typeof calc_pmk;
  calc_ptk: typeof calc_ptk;
  calc_mic: typeof calc_mic;
};
export default _default;
