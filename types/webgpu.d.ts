import type { BatchBackend, Bytes, DeriveResult, TimedMicsResult, TimedPmksResult, TimedPtksResult, WPA2Chain } from './common.js';

export interface WebGPUMICOptions {
  lite?: boolean;
}

export interface WebGPUPMK extends BatchBackend<[passwords: string[], ssid: string], TimedPmksResult> {
  calculate(passwords: string[], ssid: string): Promise<TimedPmksResult>;
  dispose(): void;
}

export const WebGPUPMK: {
  readonly shader: string;
  readonly inputSize: number;
  create(): Promise<WebGPUPMK>;
};

export interface WebGPUPTK extends BatchBackend<[pmks: Bytes[], keyData: Bytes], TimedPtksResult> {
  calculate(pmks: Bytes[], keyData: Bytes): Promise<TimedPtksResult>;
  dispose(): void;
}

export const WebGPUPTK: {
  readonly shader: string;
  create(): Promise<WebGPUPTK>;
};

export class WebGPUMIC implements BatchBackend<[
  keys: Bytes[],
  message: Bytes,
  variant?: 'baseline' | 'scalar',
  workgroupSize?: number,
], TimedMicsResult> {
  static readonly ptkShader: string;
  readonly maxBatch: number;
  readonly groupSizes: number[];
  readonly defaultWorkgroupSize: number;
  static create(options?: WebGPUMICOptions): Promise<WebGPUMIC>;
  calculate(keys: Bytes[], message: Bytes, variant?: 'baseline' | 'scalar', workgroupSize?: number): Promise<TimedMicsResult>;
  dispose(): void;
}

export class WPA2WebGPU implements WPA2Chain {
  readonly maxBatch: number;
  static create(): Promise<WPA2WebGPU>;
  derive(passwords: string[], ssid: string, keyData: Bytes, message: Bytes): Promise<DeriveResult>;
  dispose(): void;
}

declare const _default: {
  WPA2WebGPU: typeof WPA2WebGPU;
  WebGPUPMK: typeof WebGPUPMK;
  WebGPUPTK: typeof WebGPUPTK;
  WebGPUMIC: typeof WebGPUMIC;
};
export default _default;
