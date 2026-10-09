export type Bytes = Uint8Array;

export interface DeriveResult {
  mics: Bytes[];
}

export interface TimedMicsResult extends DeriveResult {
  time: number;
}

export interface TimedPmksResult {
  pmks: Bytes[];
  time: number;
}

export interface TimedPtksResult {
  ptks: Bytes[];
  time: number;
}

export interface WPA2Chain {
  readonly maxBatch: number;
  derive(passwords: string[], ssid: string, keyData: Bytes, message: Bytes): Promise<DeriveResult>;
  dispose(): void;
}

export interface BatchBackend<Result> {
  calculate(...args: any[]): Promise<Result>;
  dispose(): void;
}
