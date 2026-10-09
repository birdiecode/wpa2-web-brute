export * from './webcrypto.js';
export * from './webgl.js';
export * from './webgpu.js';

import webcrypto from './webcrypto.js';
import webgl from './webgl.js';
import webgpu from './webgpu.js';

declare const _default: typeof webcrypto & typeof webgl & typeof webgpu;
export default _default;
