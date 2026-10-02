(async () => {
'use strict';

// PBKDF2-HMAC-SHA1: 4096 iterations, 32-byte PMK, 8–63-byte UTF-8 password.
const WGSL = /* wgsl */ `
struct Input {
    password: array<u32, 64>,
    ssid: array<u32, 32>,
    ssidLen: u32,
}
struct Output { pmk: array<u32, 8>, }
@group(0) @binding(0) var<storage, read> inputs: array<Input>;
var<private> input: Input;
@group(0) @binding(1) var<storage, read_write> outputs: array<Output>;

fn rol(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}
fn sha1_init() -> array<u32, 5> {
    return array<u32, 5>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u);
}
fn sha1_compress(stateIn: array<u32, 5>, blockIn: array<u32, 16>) -> array<u32, 5> {
    // SHA-1 only needs the previous 16 schedule words.
    var w = blockIn;
    var a = stateIn[0];
    var b = stateIn[1];
    var c = stateIn[2];
    var d = stateIn[3];
    var e = stateIn[4];
    for (var i = 0u; i < 80u; i++) {
        let j = i & 15u;
        if (i >= 16u) {
            w[j] = rol(w[(i - 3u) & 15u] ^ w[(i - 8u) & 15u] ^
                       w[(i - 14u) & 15u] ^ w[j], 1u);
        }
        var f: u32;
        var k: u32;
        if (i < 20u) {
            f = (b & c) | ((~b) & d); k = 0x5a827999u;
        } else if (i < 40u) {
            f = b ^ c ^ d; k = 0x6ed9eba1u;
        } else if (i < 60u) {
            f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d; k = 0xca62c1d6u;
        }
        let temp = rol(a, 5u) + f + e + k + w[j];
        e = d; d = c; c = rol(b, 30u); b = a; a = temp;
    }
    return array<u32, 5>(stateIn[0]+a, stateIn[1]+b, stateIn[2]+c, stateIn[3]+d, stateIn[4]+e);
}

// Precompute the SHA1 state after the 64-byte HMAC ipad/opad.
fn hmac_state(pad: u32) -> array<u32, 5> {
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = pad; }
    for (var i = 0u; i < 64u; i++) {
        let word = i >> 2u;
        let shift = 24u - ((i & 3u) * 8u);
        block[word] = block[word] ^ (input.password[i] << shift);
    }
    return sha1_compress(sha1_init(), block);
}

// Finish SHA1 with a 20-byte digest after an already processed pad block.
fn hash20(base: array<u32, 5>, msg: array<u32, 5>) -> array<u32, 5> {
    var block: array<u32, 16>;
    for (var i = 0u; i < 5u; i++) { block[i] = msg[i]; }
    block[5] = 0x80000000u;
    block[15] = 84u * 8u;
    return sha1_compress(base, block);
}
fn hmac20(innerBase: array<u32, 5>, outerBase: array<u32, 5>, msg: array<u32, 5>) -> array<u32, 5> {
    return hash20(outerBase, hash20(innerBase, msg));
}
fn pbkdf2_u1(innerBase: array<u32, 5>, outerBase: array<u32, 5>, blockIndex: u32) -> array<u32, 5> {
    // WGSL zero-initializes the block. SSID + INT32_BE fits in one SHA1 block.
    var b: array<u32, 16>;
    for (var i = 0u; i < input.ssidLen; i++) {
        let word = i >> 2u;
        let shift = 24u - ((i & 3u) * 8u);
        b[word] = b[word] | (input.ssid[i] << shift);
    }
    for (var j = 0u; j < 4u; j++) {
        let value = (blockIndex >> (24u - j * 8u)) & 0xffu;
        let pos = input.ssidLen + j;
        let word = pos >> 2u;
        let shift = 24u - ((pos & 3u) * 8u);
        b[word] = b[word] | (value << shift);
    }
    let msgLen = input.ssidLen + 4u;
    let word = msgLen >> 2u;
    let shift = 24u - ((msgLen & 3u) * 8u);
    b[word] = b[word] | (0x80u << shift);
    b[15] = (64u + msgLen) * 8u;
    return hash20(outerBase, sha1_compress(innerBase, b));
}
fn pbkdf2_block(innerBase: array<u32, 5>, outerBase: array<u32, 5>, blockIndex: u32) -> array<u32, 5> {
    var u = pbkdf2_u1(innerBase, outerBase, blockIndex);
    var t = u;
    for (var i = 1u; i < 4096u; i++) {
        u = hmac20(innerBase, outerBase, u);
        for (var j = 0u; j < 5u; j++) { t[j] = t[j] ^ u[j]; }
    }
    return t;
}
@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    input = inputs[id.x];
    let innerBase = hmac_state(0x36363636u);
    let outerBase = hmac_state(0x5c5c5c5cu);
    let t1 = pbkdf2_block(innerBase, outerBase, 1u);
    let t2 = pbkdf2_block(innerBase, outerBase, 2u);
    for (var i = 0u; i < 5u; i++) { outputs[id.x].pmk[i] = t1[i]; }
    for (var i = 0u; i < 3u; i++) { outputs[id.x].pmk[5u+i] = t2[i]; }
}
`;

// Keep the original schedule for controlled comparisons on the same device.
const WGSL80 = WGSL
    .replace('var w = blockIn;', `var w: array<u32, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = blockIn[i]; }
    for (var i = 16u; i < 80u; i++) {
        w[i] = rol(w[i-3u] ^ w[i-8u] ^ w[i-14u] ^ w[i-16u], 1u);
    }`)
    .replace(/        let j = i & 15u;[\s\S]*?        var f: u32;/,
        '        var f: u32;')
    .replace('+ k + w[j]', '+ k + w[i]');

const SPLIT_WGSL = WGSL.slice(0, WGSL.indexOf('fn pbkdf2_block')) + /* wgsl */ `
struct Tmp {
    ipad: array<u32, 5>,
    opad: array<u32, 5>,
    dgst1: array<u32, 5>,
    dgst2: array<u32, 5>,
    out1: array<u32, 5>,
    out2: array<u32, 5>,
}
@group(0) @binding(2) var<storage, read_write> tmps: array<Tmp>;
override LOOP_COUNT: u32 = 128u;

@compute @workgroup_size(1)
fn init(@builtin(global_invocation_id) id: vec3<u32>) {
    input = inputs[id.x];
    var tmp: Tmp;
    tmp.ipad = hmac_state(0x36363636u);
    tmp.opad = hmac_state(0x5c5c5c5cu);
    tmp.dgst1 = pbkdf2_u1(tmp.ipad, tmp.opad, 1u);
    tmp.dgst2 = pbkdf2_u1(tmp.ipad, tmp.opad, 2u);
    tmp.out1 = tmp.dgst1;
    tmp.out2 = tmp.dgst2;
    tmps[id.x] = tmp;
}
@compute @workgroup_size(1)
fn loop_chunk(@builtin(global_invocation_id) id: vec3<u32>) {
    var tmp = tmps[id.x];
    for (var j = 0u; j < LOOP_COUNT; j++) {
        tmp.dgst1 = hmac20(tmp.ipad, tmp.opad, tmp.dgst1);
        tmp.dgst2 = hmac20(tmp.ipad, tmp.opad, tmp.dgst2);
        for (var k = 0u; k < 5u; k++) {
            tmp.out1[k] ^= tmp.dgst1[k];
            tmp.out2[k] ^= tmp.dgst2[k];
        }
    }
    tmps[id.x] = tmp;
}
@compute @workgroup_size(1)
fn finish(@builtin(global_invocation_id) id: vec3<u32>) {
    for (var k = 0u; k < 5u; k++) { outputs[id.x].pmk[k] = tmps[id.x].out1[k]; }
    for (var k = 0u; k < 3u; k++) { outputs[id.x].pmk[5u+k] = tmps[id.x].out2[k]; }
}
`;
// Generate once, before pipeline compilation. The emitted hot compression has
// 16 scalar schedule registers and 80 static rounds: no array indexing/round loop.
function generateSHA120() {
    const lines = [
        'fn sha1_20(state: array<u32, 5>, m0: u32, m1: u32, m2: u32, m3: u32, m4: u32) -> array<u32, 5> {',
    ];
    for (let i = 0; i < 16; i++) {
        const value = i < 5 ? `m${i}` : i === 5 ? '0x80000000u' : i === 15 ? '672u' : '0u';
        lines.push(`    var w${i}: u32 = ${value};`);
    }
    for (const [i, name] of ['a', 'b', 'c', 'd', 'e'].entries()) {
        lines.push(`    var ${name} = state[${i}];`);
    }
    for (let i = 0; i < 80; i++) {
        const j = i & 15;
        if (i >= 16) {
            lines.push(`    w${j} = rol(w${(i - 3) & 15} ^ w${(i - 8) & 15} ^ w${(i - 14) & 15} ^ w${j}, 1u);`);
        }
        const f = i < 20 ? '((b & c) | ((~b) & d))' : i < 40 ? '(b ^ c ^ d)' :
            i < 60 ? '((b & c) | (b & d) | (c & d))' : '(b ^ c ^ d)';
        const k = ['0x5a827999u', '0x6ed9eba1u', '0x8f1bbcdcu', '0xca62c1d6u'][Math.floor(i / 20)];
        lines.push(`    { // Round ${i}
        let next = rol(a, 5u) + ${f} + e + ${k} + w${j};
        e = d; d = c; c = rol(b, 30u); b = a; a = next;
    }`);
    }
    lines.push('    return array<u32, 5>(state[0]+a, state[1]+b, state[2]+c, state[3]+d, state[4]+e);', '}');
    return lines.join('\n');
}
// Retain A's generic w[80] for key setup and U1; specialize only U2..U4096.
const SCALAR_WGSL = WGSL80.slice(0, WGSL80.indexOf('fn hmac20(')) +
    generateSHA120() + `
fn hmac20(innerBase: array<u32, 5>, outerBase: array<u32, 5>, msg: array<u32, 5>) -> array<u32, 5> {
    let h = sha1_20(innerBase, msg[0], msg[1], msg[2], msg[3], msg[4]);
    return sha1_20(outerBase, h[0], h[1], h[2], h[3], h[4]);
}
` + WGSL80.slice(WGSL80.indexOf('fn pbkdf2_u1('));

// Two independent scalar SHA-1 streams, interleaved round by round.
// This exposes ILP; two complete sequential PBKDF2 calls would not do that.
function generateSHA120Pair() {
    const lines = [`struct DigestPair { left: array<u32, 5>, right: array<u32, 5>, }
fn sha1_20_pair(s0: array<u32, 5>, s1: array<u32, 5>, m0: array<u32, 5>, m1: array<u32, 5>) -> DigestPair {`];
    for (let lane = 0; lane < 2; lane++) {
        for (let i = 0; i < 16; i++) {
            const value = i < 5 ? `m${lane}[${i}]` : i === 5 ? '0x80000000u' : i === 15 ? '672u' : '0u';
            lines.push(`    var w${lane}_${i}: u32 = ${value};`);
        }
        for (const [i, name] of ['a', 'b', 'c', 'd', 'e'].entries()) {
            lines.push(`    var ${name}${lane} = s${lane}[${i}];`);
        }
    }
    for (let i = 0; i < 80; i++) {
        for (let lane = 0; lane < 2; lane++) {
            const w = n => `w${lane}_${n & 15}`;
            if (i >= 16) lines.push(`    ${w(i)} = rol(${w(i-3)} ^ ${w(i-8)} ^ ${w(i-14)} ^ ${w(i)}, 1u);`);
            const b = `b${lane}`, c = `c${lane}`, d = `d${lane}`;
            const f = i < 20 ? `((${b} & ${c}) | ((~${b}) & ${d}))` : i < 40 ? `(${b} ^ ${c} ^ ${d})` :
                i < 60 ? `((${b} & ${c}) | (${b} & ${d}) | (${c} & ${d}))` : `(${b} ^ ${c} ^ ${d})`;
            const k = ['0x5a827999u', '0x6ed9eba1u', '0x8f1bbcdcu', '0xca62c1d6u'][Math.floor(i / 20)];
            lines.push(`    { // Round ${i}, candidate ${lane}
        let next = rol(a${lane}, 5u) + ${f} + e${lane} + ${k} + ${w(i)};
        e${lane} = d${lane}; d${lane} = c${lane}; c${lane} = rol(b${lane}, 30u); b${lane} = a${lane}; a${lane} = next;
    }`);
        }
    }
    lines.push('    return DigestPair(');
    for (let lane = 0; lane < 2; lane++) {
        const words = ['a', 'b', 'c', 'd', 'e'].map((name, i) => `s${lane}[${i}]+${name}${lane}`);
        lines.push(`        array<u32, 5>(${words.join(', ')})${lane === 0 ? ',' : ''}`);
    }
    lines.push('    );', '}');
    return lines.join('\n');
}
const ILP2_WGSL = SCALAR_WGSL.slice(0, SCALAR_WGSL.indexOf('@compute @workgroup_size(1)')) +
    generateSHA120Pair() + /* wgsl */ `
fn pbkdf2_pair(ip0: array<u32, 5>, op0: array<u32, 5>, ip1: array<u32, 5>, op1: array<u32, 5>,
               first0: array<u32, 5>, first1: array<u32, 5>) -> DigestPair {
    var u = DigestPair(first0, first1);
    var t = u;
    for (var i = 1u; i < 4096u; i++) {
        let inner = sha1_20_pair(ip0, ip1, u.left, u.right);
        u = sha1_20_pair(op0, op1, inner.left, inner.right);
        for (var j = 0u; j < 5u; j++) {
            t.left[j] ^= u.left[j];
            t.right[j] ^= u.right[j];
        }
    }
    return t;
}
@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let first = id.x * 2u;
    // Input binding is limited to the actual batch, not the buffer capacity.
    let second = min(first + 1u, arrayLength(&inputs) - 1u);
    input = inputs[first];
    let ip0 = hmac_state(0x36363636u);
    let op0 = hmac_state(0x5c5c5c5cu);
    let u10 = pbkdf2_u1(ip0, op0, 1u);
    let u20 = pbkdf2_u1(ip0, op0, 2u);
    input = inputs[second];
    let ip1 = hmac_state(0x36363636u);
    let op1 = hmac_state(0x5c5c5c5cu);
    let u11 = pbkdf2_u1(ip1, op1, 1u);
    let u21 = pbkdf2_u1(ip1, op1, 2u);
    let t1 = pbkdf2_pair(ip0, op0, ip1, op1, u10, u11);
    let t2 = pbkdf2_pair(ip0, op0, ip1, op1, u20, u21);
    for (var k = 0u; k < 5u; k++) { outputs[first].pmk[k] = t1.left[k]; }
    for (var k = 0u; k < 3u; k++) { outputs[first].pmk[5u+k] = t2.left[k]; }
    if (second != first) {
        for (var k = 0u; k < 5u; k++) { outputs[second].pmk[k] = t1.right[k]; }
        for (var k = 0u; k < 3u; k++) { outputs[second].pmk[5u+k] = t2.right[k]; }
    }
}
`;

// Same D hot loop; only launch geometry changes. Bound input size supplies count.
const WORKGROUP_SIZES = [1, 32, 64, 128, 256, 512];
const GROUP_WGSL = SCALAR_WGSL
    .replace('@compute @workgroup_size(1)',
        'override WORKGROUP_SIZE: u32 = 32u;\n@compute @workgroup_size(WORKGROUP_SIZE)')
    .replace('    input = inputs[id.x];',
        '    if (id.x >= arrayLength(&inputs)) { return; }\n    input = inputs[id.x];');

const VARIANTS = {
    mono80: 'A: Монолитный w[80]',
    mono16: 'B: Монолитный w[16]',
    split128: 'C: init → loop(128) → final, w[16]',
    scalar: 'D: Монолитный scalar/unrolled (baseline)',
    ilp2: 'E: Scalar/unrolled, 2 кандидата на invocation',
};

const INPUT_SIZE = (64 + 32 + 1) * 4; // 388 bytes
const OUTPUT_SIZE = 32;
const MAX_BATCH = 4096;
const standaloneUI = !!document.querySelector('#pmk-form');
const out = standaloneUI ? document.querySelector('#out') : null;
const status = standaloneUI ? document.querySelector('#status') : null;
const buttons = standaloneUI ? document.querySelectorAll('button:not(#stop), select, input') : [];
let stopRequested = false;
if (standaloneUI) document.querySelector('#stop').addEventListener('click', () => { stopRequested = true; });

async function initWebGPU(lite = false) {
    if (!navigator.gpu) throw new Error('WebGPU недоступен. Откройте страницу через HTTPS или localhost в браузере с поддержкой WebGPU.');
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) throw new Error('WebGPU adapter не найден');
    const groupLimit = Math.min(512, adapter.limits.maxComputeInvocationsPerWorkgroup,
        adapter.limits.maxComputeWorkgroupSizeX);
    const device = await adapter.requestDevice({ requiredLimits: {
        maxComputeInvocationsPerWorkgroup: groupLimit,
        maxComputeWorkgroupSizeX: groupLimit,
    } });
    try {
        const bindGroupLayout = device.createBindGroupLayout({ entries: [
            { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'read-only-storage' } },
            { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'storage' } },
            { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'storage' } },
        ] });
        const layout = device.createPipelineLayout({ bindGroupLayouts: [bindGroupLayout] });
        const pipelines = {};
        async function compile(code, entries) {
            const module = device.createShaderModule({ code });
            const info = await module.getCompilationInfo();
            const errors = info.messages.filter(message => message.type === 'error');
            if (errors.length) throw new Error(errors.map(m => `${m.lineNum}:${m.linePos} ${m.message}`).join('\n'));
            for (const [name, entryPoint, constants = {}] of entries) {
                pipelines[name] = await device.createComputePipelineAsync({
                    label: name, layout, compute: { module, entryPoint, constants },
                });
            }
        }
        const workgroupSizes = WORKGROUP_SIZES.filter(size => size <= groupLimit);
        if (lite) {
            await compile(SCALAR_WGSL, [['scalar', 'main']]);
            await compile(GROUP_WGSL, workgroupSizes.filter(size => size === 32).map(size =>
                [`scalar${size}`, 'main', { WORKGROUP_SIZE: size }]));
        } else {
            await compile(WGSL80, [['mono80', 'main']]);
            await compile(WGSL, [['mono16', 'main']]);
            await compile(SCALAR_WGSL, [['scalar', 'main']]);
            await compile(ILP2_WGSL, [['ilp2', 'main']]);
            await compile(GROUP_WGSL, workgroupSizes.filter(size => size > 1).map(size =>
                [`scalar${size}`, 'main', { WORKGROUP_SIZE: size }]));
            await compile(SPLIT_WGSL, [
                ['init', 'init'], ['loop128', 'loop_chunk', { LOOP_COUNT: 128 }],
                ['loop127', 'loop_chunk', { LOOP_COUNT: 127 }], ['finish', 'finish'],
            ]);
        }
        const inputBuffer = device.createBuffer({ size: INPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        const outputBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
        const readBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
        const tmpBuffer = device.createBuffer({ size: 120 * MAX_BATCH, usage: GPUBufferUsage.STORAGE });
        const bindGroup = device.createBindGroup({
            layout: bindGroupLayout,
            entries: [
                { binding: 0, resource: { buffer: inputBuffer } },
                { binding: 1, resource: { buffer: outputBuffer } },
                { binding: 2, resource: { buffer: tmpBuffer } }
            ]
        });
        return { device, pipelines, inputBuffer, outputBuffer, readBuffer, bindGroup, tmpBuffer, workgroupSizes };
    } catch (error) {
        device.destroy();
        throw error;
    }
}

function packInput(password, ssidText) {
    const enc = new TextEncoder();
    if (typeof password !== 'string' || typeof ssidText !== 'string') throw new TypeError('Пароль и SSID должны быть строками');
    const pw = enc.encode(password);
    const ssid = enc.encode(ssidText);
    if (pw.length < 8 || pw.length > 63) throw new Error('Пароль должен быть 8–63 байта UTF-8');
    if (ssid.length < 1 || ssid.length > 32) throw new Error('SSID должен быть 1..32 байта UTF-8');
    const data = new Uint32Array(INPUT_SIZE / 4);
    data.set(pw);
    data.set(ssid, 64);
    data[96] = ssid.length;
    return data;
}
function readInput() { return packInput(document.querySelector('#password').value, document.querySelector('#ssid').value); }
// D uses one candidate per invocation; E interleaves two. Batch counts always mean candidates.
async function calculateBatch(gpu, data, variant = 'scalar', workgroupSize = 1) {
    if (!Object.hasOwn(VARIANTS, variant)) throw new Error('Неизвестный вариант PMK');
    if (workgroupSize !== 1 && (variant !== 'scalar' || !gpu.workgroupSizes.includes(workgroupSize))) {
        throw new Error('Этот размер workgroup недоступен для выбранного варианта');
    }
    const count = data.length / (INPUT_SIZE / 4);
    if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH) {
        throw new Error(`Размер batch должен быть от 1 до ${MAX_BATCH}`);
    }
    const { device, pipelines, inputBuffer, outputBuffer, readBuffer, bindGroup, tmpBuffer } = gpu;
    device.queue.writeBuffer(inputBuffer, 0, data);
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    const pipelineName = variant === 'ilp2' ? 'ilp2' : workgroupSize > 1 ? `scalar${workgroupSize}` : variant;
    const activeBindGroup = variant === 'ilp2' || workgroupSize > 1 ? device.createBindGroup({
        layout: pipelines[pipelineName].getBindGroupLayout(0),
        entries: [
            { binding: 0, resource: { buffer: inputBuffer, size: data.byteLength } },
            { binding: 1, resource: { buffer: outputBuffer } },
            { binding: 2, resource: { buffer: tmpBuffer } },
        ],
    }) : bindGroup;
    pass.setBindGroup(0, activeBindGroup);
    const dispatch = name => {
        pass.setPipeline(pipelines[name]);
        pass.dispatchWorkgroups(variant === 'ilp2' ? Math.ceil(count / 2) : Math.ceil(count / workgroupSize));
    };
    if (variant === 'split128') {
        dispatch('init');
        // U1 is already calculated: 31 * 128 + 127 = 4095 remaining rounds.
        // Dispatch boundaries order storage writes before the next chunk reads them.
        for (let i = 0; i < 31; i++) dispatch('loop128');
        dispatch('loop127');
        dispatch('finish');
    } else {
        dispatch(pipelineName);
    }
    pass.end();
    const byteLength = OUTPUT_SIZE * count;
    encoder.copyBufferToBuffer(outputBuffer, 0, readBuffer, 0, byteLength);
    const start = performance.now();
    device.queue.submit([encoder.finish()]);
    await readBuffer.mapAsync(GPUMapMode.READ, 0, byteLength);
    const time = performance.now() - start;
    try {
        return { words: new Uint32Array(readBuffer.getMappedRange(0, byteLength).slice(0)), time };
    } finally {
        readBuffer.unmap();
    }
}
function hex(words) {
    return Array.from(words, word => word.toString(16).padStart(8, '0')).join('');
}
function makeBatch(base, count) {
    const stride = INPUT_SIZE / 4;
    const data = new Uint32Array(stride * count);
    for (let i = 0; i < count; i++) {
        const offset = i * stride;
        data.set(base, offset);
        data.fill(0, offset, offset + 64);
        data.set(new TextEncoder().encode(String(i).padStart(8, '0')), offset);
    }
    return data;
}
function median(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
async function compareVariants(gpu, base, comparison = 'all') {
    const repeats = Number(document.querySelector('#repeats').value);
    const variants = comparison === 'ad' ? ['mono80', 'scalar'] : comparison === 'de' ? ['scalar', 'ilp2'] : Object.keys(VARIANTS);
    out.textContent = `Сравнение: ${repeats} замеров после одного прогрева каждого варианта на каждом batch.\n` +
        'Время: загрузка, кодирование команд, вычисление, чтение; данные подготовлены заранее.\n' +
        'Порядок вариантов чередуется. Результаты каждого запуска сверяются целиком.\n\n';
    const checkStop = () => {
        if (stopRequested) throw new Error('Остановлено пользователем');
    };
    for (const count of (comparison === 'all' ? [512, 1024, 4096] : [4096])) {
        const data = makeBatch(base, count);
        const samples = Object.fromEntries(variants.map(v => [v, []]));
        let expected;
        const verify = words => {
            if (!expected) expected = words;
            else if (words.some((word, i) => word !== expected[i])) {
                throw new Error(`Результаты вариантов не совпали при batch=${count}`);
            }
        };
        for (const v of variants) {
            checkStop();
            status.textContent = `Прогрев: batch=${count}, ${VARIANTS[v]}`;
            await new Promise(resolve => setTimeout(resolve, 0));
            verify((await calculateBatch(gpu, data, v)).words);
        }
        for (let round = 0; round < repeats; round++) {
            for (let j = 0; j < variants.length; j++) {
                checkStop();
                const v = variants[(j + round) % variants.length];
                status.textContent = `batch=${count}, ${VARIANTS[v]}, замер ${round + 1}/${repeats}`;
                await new Promise(resolve => setTimeout(resolve, 0));
                const start = performance.now();
                const result = await calculateBatch(gpu, data, v);
                samples[v].push(performance.now() - start);
                verify(result.words); // Excluded from measured time.
                checkStop();
            }
        }
        for (const v of variants) {
            const values = samples[v];
            const med = median(values);
            out.textContent += `batch=${count}  ${VARIANTS[v]}\n` +
                `median=${med.toFixed(2)} ms  rate=${(count * 1000 / med).toFixed(2)} PMK/s  ` +
                `min=${Math.min(...values).toFixed(2)}  max=${Math.max(...values).toFixed(2)} ms\n` +
                `samples: ${values.map(x => x.toFixed(2)).join(', ')} ms\n\n`;
        }
    }
}
async function compareWorkgroups(gpu, base) {
    const count = 4096;
    const repeats = 5;
    const sizes = gpu.workgroupSizes;
    const data = makeBatch(base, count);
    const samples = Object.fromEntries(sizes.map(size => [size, []]));
    let expected;
    out.textContent = 'D: batch=4096, один прогрев каждого размера, 5 замеров с чередованием порядка.\n' +
        'Время включает загрузку, команды, вычисление и чтение; компиляция и подготовка входов исключены.\n' +
        'Все PMK сверяются с исходным D (workgroup=1) вне измерения.\n\n';
    for (const size of WORKGROUP_SIZES.filter(size => !sizes.includes(size))) {
        out.textContent += `workgroup=${size}: пропущен — превышает лимит адаптера.\n`;
    }
    const check = words => {
        if (!expected) expected = words;
        else if (words.some((word, i) => word !== expected[i])) throw new Error('PMK не совпали между workgroup');
        if (stopRequested) throw new Error('Остановлено пользователем');
    };
    for (const size of sizes) {
        if (stopRequested) throw new Error('Остановлено пользователем');
        status.textContent = `Прогрев D: workgroup=${size}`;
        await new Promise(resolve => setTimeout(resolve, 0));
        check((await calculateBatch(gpu, data, 'scalar', size)).words);
    }
    for (let round = 0; round < repeats; round++) {
        for (let j = 0; j < sizes.length; j++) {
            if (stopRequested) throw new Error('Остановлено пользователем');
            const size = sizes[(j + round) % sizes.length];
            status.textContent = `D: workgroup=${size}, замер ${round + 1}/${repeats}`;
            await new Promise(resolve => setTimeout(resolve, 0));
            const start = performance.now();
            const result = await calculateBatch(gpu, data, 'scalar', size);
            samples[size].push(performance.now() - start);
            check(result.words);
        }
    }
    for (const size of sizes) {
        const times = samples[size];
        const med = median(times);
        out.textContent += `workgroup=${size}  dispatchWorkgroups=${Math.ceil(count / size)}\n` +
            `median=${med.toFixed(2)} ms  rate=${(count * 1000 / med).toFixed(2)} PMK/s  ` +
            `min=${Math.min(...times).toFixed(2)}  max=${Math.max(...times).toFixed(2)} ms\n` +
            `samples: ${times.map(t => t.toFixed(2)).join(', ')} ms\n\n`;
    }
}
if (!standaloneUI) {
    globalThis.WebGPUPMK = {
        shader: GROUP_WGSL,
        inputSize: INPUT_SIZE,
        async create() {
            const gpu = await initWebGPU(true);
            return {
                async calculate(passwords, ssid) {
                    if (!Array.isArray(passwords) || passwords.length < 1 || passwords.length > MAX_BATCH)
                        throw new RangeError(`Число паролей должно быть от 1 до ${MAX_BATCH}`);
                    const data = new Uint32Array((INPUT_SIZE / 4) * passwords.length);
                    for (let i = 0; i < passwords.length; i++) data.set(packInput(passwords[i], ssid), i * (INPUT_SIZE / 4));
                    const wg = gpu.workgroupSizes.includes(32) ? 32 : 1;
                    const result = await calculateBatch(gpu, data, 'scalar', wg);
                    const pmks = Array.from({ length: passwords.length }, (_, i) => {
                        const bytes = new Uint8Array(32), view = new DataView(bytes.buffer);
                        for (let j = 0; j < 8; j++) view.setUint32(j * 4, result.words[i * 8 + j], false);
                        return bytes;
                    });
                    return { pmks, time: result.time };
                },
                dispose() {
                    for (const buffer of [gpu.inputBuffer, gpu.outputBuffer, gpu.readBuffer, gpu.tmpBuffer]) buffer.destroy();
                    gpu.device.destroy();
                },
            };
        },
    };
    return;
}
function setDisabled(disabled) {
    buttons.forEach(button => { button.disabled = disabled; });
}
function showError(error) {
    console.error(error);
    status.className = 'error';
    status.textContent = `Ошибка: ${error.message}`;
}

try {
    const gpu = await initWebGPU();
    for (const option of document.querySelector('#workgroup').options) {
        option.disabled = !gpu.workgroupSizes.includes(Number(option.value));
    }
    let deviceLost = false;
    let busy = false;
    gpu.device.lost.then(info => {
        deviceLost = true;
        setDisabled(true);
        showError(new Error(`Устройство WebGPU потеряно: ${info.message}. Перезагрузите страницу.`));
    });
    async function run(mode = 'single') {
        if (busy || deviceLost) return;
        busy = true;
        stopRequested = false;
        document.querySelector('#stop').disabled = false;
        setDisabled(true);
        status.className = '';
        status.textContent = 'Вычисление...';
        out.textContent = '';
        try {
            const base = readInput();
            const variant = document.querySelector('#variant').value;
            const workgroupSize = variant === 'scalar' ? Number(document.querySelector('#workgroup').value) : 1;
            if (mode === 'compare' || mode === 'compare-ad' || mode === 'compare-de') {
                await compareVariants(gpu, base, mode === 'compare-ad' ? 'ad' : mode === 'compare-de' ? 'de' : 'all');
            } else if (mode === 'workgroups') {
                await compareWorkgroups(gpu, base);
            } else if (mode === 'benchmark') {
                out.textContent = `${VARIANTS[variant]}, workgroup=${workgroupSize}\n` + 'Пароли для бенчмарка: 00000000 … 00004095; SSID из поля.\nВремя включает подготовку и загрузку данных, расчёт и чтение результата; без компиляции и выделения GPU-буферов.\n\n';
                status.textContent = 'Прогрев...';
                await calculateBatch(gpu, makeBatch(base, 1), variant, workgroupSize);
                for (let count = 1; count <= MAX_BATCH; count *= 2) {
                    if (deviceLost) return;
                    if (stopRequested) throw new Error('Остановлено пользователем');
                    status.textContent = `Бенчмарк: batch=${count} / ${MAX_BATCH}`;
                    await new Promise(resolve => setTimeout(resolve, 0));
                    const start = performance.now();
                    await calculateBatch(gpu, makeBatch(base, count), variant, workgroupSize);
                    if (deviceLost) return;
                    if (stopRequested) throw new Error('Остановлено пользователем');
                    const elapsed = performance.now() - start;
                    const rate = elapsed > 0 ? (count * 1000 / elapsed).toFixed(2) : '—';
                    out.textContent += `batch=${String(count).padStart(4)}  time=${elapsed.toFixed(2)} ms  rate=${rate} PMK/s\n`;
                }
            } else {
                const result = await calculateBatch(gpu, base, variant, workgroupSize);
                if (deviceLost) return;
                if (stopRequested) throw new Error('Остановлено пользователем');
                const value = hex(result.words);
                
                out.textContent = `${VARIANTS[variant]}, workgroup=${workgroupSize}\n\nPMK (32 байта):\n${value}\n\nGPU dispatch + readback:\n${result.time.toFixed(2)} ms`;
            }
            status.className = 'ok';
            status.textContent = '✓ Готово';
        } catch (error) {
            showError(error);
        } finally {
            busy = false;
            document.querySelector('#stop').disabled = true;
            setDisabled(deviceLost);
        }
    }
    document.querySelector('#pmk-form').addEventListener('submit', event => {
        event.preventDefault();
        void run();
    });
    document.querySelector('#benchmark').addEventListener('click', () => { void run('benchmark'); });
    
    document.querySelector('#workgroups').addEventListener('click', () => { void run('workgroups'); });
    document.querySelector('#compare-de').addEventListener('click', () => { void run('compare-de'); });
    document.querySelector('#compare-ad').addEventListener('click', () => { void run('compare-ad'); });
    document.querySelector('#compare').addEventListener('click', () => { void run('compare'); });
    status.textContent = 'Готово.';
    setDisabled(false);
} catch (error) {
    showError(error);
}

})();
