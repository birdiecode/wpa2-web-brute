import type { Bytes, DeriveResult, TimedMicsResult, TimedPmksResult, TimedPtksResult, WPA2Chain } from './common.js';

export interface WebGLShaders {
  vertex: string;
  fragment: string;
}

export class WebGL2PMK {
  static readonly shaders: WebGLShaders;
  static packPasswords(passwords: string[]): Uint32Array;
  readonly disposed: boolean;
  constructor();
  derive(passwords: string[], ssid: string): Promise<Bytes[]>;
  dispose(): void;
}

export class WebGL2PTK {
  static readonly shaders: WebGLShaders;
  readonly disposed: boolean;
  constructor();
  derive(pmks: Bytes[], keyData: Bytes): Promise<Bytes[]>;
  dispose(): void;
}

export class WebGL2MIC {
  static readonly shaders: WebGLShaders;
  readonly disposed: boolean;
  constructor();
  derive(keys: Bytes[], message: Bytes): Promise<Bytes[]>;
  dispose(): void;
}

export class WPA2WebGL implements WPA2Chain {
  readonly maxBatch: number;
  static create(): Promise<WPA2WebGL>;
  derive(passwords: string[], ssid: string, keyData: Bytes, message: Bytes): Promise<DeriveResult>;
  dispose(): void;
}

declare const _default: {
  WPA2WebGL: typeof WPA2WebGL;
  WebGL2PMK: typeof WebGL2PMK;
  WebGL2PTK: typeof WebGL2PTK;
  WebGL2MIC: typeof WebGL2MIC;
};
export default _default;
