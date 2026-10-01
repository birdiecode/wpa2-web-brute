(function () {
'use strict';

const WGSL = /* wgsl */ `
struct Key { words: array<u32, 4>, }
struct Output { words: array<u32, 4>, }
struct Params { blockCount: u32, _pad0: u32, _pad1: u32, _pad2: u32, }
@group(0) @binding(0) var<storage, read> keys: array<Key>;
@group(0) @binding(1) var<storage, read> message: array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<Output>;
@group(0) @binding(3) var<uniform> params: Params;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }
fn sha1_init() -> array<u32, 5> {
    return array<u32, 5>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u);
}
fn sha1_compress(stateIn: array<u32, 5>, blockIn: array<u32, 16>) -> array<u32, 5> {
    var w: array<u32, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = blockIn[i]; }
    for (var i = 16u; i < 80u; i++) { w[i] = rol(w[i-3u] ^ w[i-8u] ^ w[i-14u] ^ w[i-16u], 1u); }
    var a = stateIn[0]; var b = stateIn[1]; var c = stateIn[2]; var d = stateIn[3]; var e = stateIn[4];
    for (var i = 0u; i < 80u; i++) {
        var f: u32; var k: u32;
        if (i < 20u) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
        else if (i < 40u) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60u) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        let next = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30u); b = a; a = next;
    }
    return array<u32, 5>(stateIn[0]+a, stateIn[1]+b, stateIn[2]+c, stateIn[3]+d, stateIn[4]+e);
}
fn calculate_mic(id: u32) -> array<u32, 4> {
    let key = keys[id];
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = 0x36363636u; }
    for (var i = 0u; i < 4u; i++) { block[i] ^= key.words[i]; }
    var inner = sha1_compress(sha1_init(), block);
    for (var n = 0u; n < params.blockCount; n++) {
        for (var i = 0u; i < 16u; i++) { block[i] = message[n * 16u + i]; }
        inner = sha1_compress(inner, block);
    }
    var outerBlock: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { outerBlock[i] = 0x5c5c5c5cu; }
    for (var i = 0u; i < 4u; i++) { outerBlock[i] ^= key.words[i]; }
    let outer = sha1_compress(sha1_init(), outerBlock);
    for (var i = 0u; i < 16u; i++) { block[i] = 0u; }
    for (var i = 0u; i < 5u; i++) { block[i] = inner[i]; }
    block[5] = 0x80000000u;
    block[15] = 672u;
    let digest = sha1_compress(outer, block);
    return array<u32, 4>(digest[0], digest[1], digest[2], digest[3]);
}
@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    if (id.x >= arrayLength(&keys)) { return; }
    let mic = calculate_mic(id.x);
    for (var i = 0u; i < 4u; i++) { outputs[id.x].words[i] = mic[i]; }
}
`;

function generateSHA1Unrolled() {
    const lines = ['fn sha1_unrolled(stateIn: array<u32, 5>, blockIn: array<u32, 16>) -> array<u32, 5> {'];
    for (let i = 0; i < 16; i++) lines.push(`    var w${i}: u32 = blockIn[${i}];`);
    for (const [i, name] of ['a', 'b', 'c', 'd', 'e'].entries()) lines.push(`    var ${name} = stateIn[${i}];`);
    for (let i = 0; i < 80; i++) {
        const j = i & 15;
        if (i >= 16) lines.push(`    w${j} = rol(w${(i - 3) & 15} ^ w${(i - 8) & 15} ^ w${(i - 14) & 15} ^ w${j}, 1u);`);
        const f = i < 20 ? '((b & c) | ((~b) & d))' : i < 40 ? '(b ^ c ^ d)' : i < 60 ? '((b & c) | (b & d) | (c & d))' : '(b ^ c ^ d)';
        const k = ['0x5a827999u', '0x6ed9eba1u', '0x8f1bbcdcu', '0xca62c1d6u'][Math.floor(i / 20)];
        lines.push(`    { let next = rol(a, 5u) + ${f} + e + ${k} + w${j}; e = d; d = c; c = rol(b, 30u); b = a; a = next; }`);
    }
    lines.push('    return array<u32, 5>(stateIn[0]+a, stateIn[1]+b, stateIn[2]+c, stateIn[3]+d, stateIn[4]+e);', '}');
    return lines.join('\n');
}
const start = WGSL.indexOf('fn sha1_compress(');
const end = WGSL.indexOf('\n}\n', start) + 3;
const scalarWGSL = (WGSL.slice(0, start) + generateSHA1Unrolled() + WGSL.slice(end)).replaceAll('sha1_compress(', 'sha1_unrolled(');
const GROUP_SIZES = [1, 32, 64, 128, 256, 512];
const groupWGSL = scalarWGSL
    .replace('@compute @workgroup_size(1)', 'override WORKGROUP_SIZE: u32 = 256u;\n@compute @workgroup_size(WORKGROUP_SIZE)');

class WebGPUMIC {
    static async create() {
        if (!navigator.gpu) throw new Error('WebGPU недоступен; используйте поддерживаемый браузер через HTTPS или localhost.');
        const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
        if (!adapter) throw new Error('WebGPU adapter не найден');
        const limit = Math.min(512, adapter.limits.maxComputeInvocationsPerWorkgroup, adapter.limits.maxComputeWorkgroupSizeX);
        const device = await adapter.requestDevice({ requiredLimits: {
            maxComputeInvocationsPerWorkgroup: limit, maxComputeWorkgroupSizeX: limit,
        } });
        try { return new WebGPUMIC(device, adapter, limit); }
        catch (error) { device.destroy(); throw error; }
    }

    constructor(device, _adapter, groupLimit) {
        this.device = device;
        this.maxBatch = Math.min(4096, Math.floor(device.limits.maxStorageBufferBindingSize / 16));
        this.groupSizes = GROUP_SIZES.filter(size => size <= groupLimit);
        const bgl = device.createBindGroupLayout({ entries: [
            { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'read-only-storage' } },
            { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'read-only-storage' } },
            { binding: 2, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'storage' } },
            { binding: 3, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'uniform' } },
        ] });
        const layout = device.createPipelineLayout({ bindGroupLayouts: [bgl] });
        this.pipelines = {};
        const compile = async (code, entries) => {
            const module = device.createShaderModule({ code });
            const info = await module.getCompilationInfo();
            const errors = info.messages.filter(m => m.type === 'error');
            if (errors.length) throw new Error(errors.map(m => `${m.lineNum}:${m.linePos} ${m.message}`).join('\n'));
            for (const [name, constants = {}] of entries) this.pipelines[name] = await device.createComputePipelineAsync({
                label: name, layout, compute: { module, entryPoint: 'main', constants },
            });
        };
        this.ready = (async () => {
            await compile(WGSL, [['baseline']]);
            await compile(groupWGSL, this.groupSizes.map(size => [`scalar${size}`, { WORKGROUP_SIZE: size }]));
        })();
        this.bindGroupLayout = bgl;
        this.keyBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        this.outputBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
        this.readBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
        this.paramsBuffer = device.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
        this.messageBuffer = null;
        this.messageCapacity = 0;
        this.disposed = false;
    }

    async calculate(keys, messageBytes, variant = 'scalar', workgroupSize = 256) {
        await this.ready;
        if (this.disposed) throw new Error('WebGPUMIC уже освобождён');
        if (!Array.isArray(keys) || keys.length < 1 || keys.length > this.maxBatch) throw new RangeError(`Количество KCK должно быть от 1 до ${this.maxBatch}`);
        if (!(messageBytes instanceof Uint8Array)) throw new TypeError('EAPOL message должен быть Uint8Array');
        if (variant !== 'baseline' && variant !== 'scalar') throw new Error('Неизвестная реализация MIC');
        if (variant === 'baseline') workgroupSize = 1;
        if (!this.groupSizes.includes(workgroupSize)) throw new Error('Этот размер workgroup недоступен');
        for (const key of keys) if (!(key instanceof Uint8Array) || key.byteLength !== 16) throw new TypeError('Каждый KCK должен содержать ровно 16 байт');

        const maxStorage = this.device.limits.maxStorageBufferBindingSize;
        const blockCount = Math.max(1, Math.ceil((messageBytes.length + 9) / 64));
        const paddedLength = blockCount * 64;
        if (paddedLength > maxStorage) throw new RangeError(`Сообщение слишком большое; после SHA-1 padding нужно ${paddedLength} байт, лимит storage buffer — ${maxStorage}`);
        const padded = new Uint8Array(paddedLength);
        padded.set(messageBytes);
        padded[messageBytes.length] = 0x80;
        const bitLength = (64 + messageBytes.length) * 8;
        const paddedView = new DataView(padded.buffer);
        paddedView.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
        paddedView.setUint32(paddedLength - 4, bitLength >>> 0, false);
        const messageWords = new Uint32Array(paddedLength / 4);
        for (let i = 0; i < messageWords.length; i++) messageWords[i] = paddedView.getUint32(i * 4, false);
        if (this.messageCapacity < paddedLength) {
            this.messageBuffer?.destroy();
            this.messageCapacity = Math.min(maxStorage, 2 ** Math.ceil(Math.log2(paddedLength)));
            this.messageBuffer = this.device.createBuffer({ size: this.messageCapacity, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        }
        const packedKeys = new Uint32Array(keys.length * 4);
        for (let i = 0; i < keys.length; i++) {
            const v = new DataView(keys[i].buffer, keys[i].byteOffset, 16);
            for (let j = 0; j < 4; j++) packedKeys[i * 4 + j] = v.getUint32(j * 4, false);
        }
        const started = performance.now();
        this.device.queue.writeBuffer(this.keyBuffer, 0, packedKeys);
        this.device.queue.writeBuffer(this.messageBuffer, 0, messageWords);
        this.device.queue.writeBuffer(this.paramsBuffer, 0, new Uint32Array([blockCount, 0, 0, 0]));
        const pipeline = this.pipelines[variant === 'baseline' ? 'baseline' : `scalar${workgroupSize}`];
        const bindGroup = this.device.createBindGroup({ layout: this.bindGroupLayout, entries: [
            { binding: 0, resource: { buffer: this.keyBuffer, size: packedKeys.byteLength } },
            { binding: 1, resource: { buffer: this.messageBuffer, size: paddedLength } },
            { binding: 2, resource: { buffer: this.outputBuffer } },
            { binding: 3, resource: { buffer: this.paramsBuffer } },
        ] });
        const encoder = this.device.createCommandEncoder();
        const pass = encoder.beginComputePass();
        pass.setPipeline(pipeline);
        pass.setBindGroup(0, bindGroup);
        pass.dispatchWorkgroups(Math.ceil(keys.length / workgroupSize));
        pass.end();
        encoder.copyBufferToBuffer(this.outputBuffer, 0, this.readBuffer, 0, keys.length * 16);
        this.device.queue.submit([encoder.finish()]);
        await this.readBuffer.mapAsync(GPUMapMode.READ, 0, keys.length * 16);
        const elapsed = performance.now() - started;
        const words = new Uint32Array(this.readBuffer.getMappedRange(0, keys.length * 16).slice(0));
        this.readBuffer.unmap();
        const mics = Array.from({ length: keys.length }, (_, i) => {
            const bytes = new Uint8Array(16), view = new DataView(bytes.buffer);
            for (let j = 0; j < 4; j++) view.setUint32(j * 4, words[i * 4 + j], false);
            return bytes;
        });
        return { mics, time: elapsed };
    }

    dispose() {
        if (this.disposed) return;
        this.disposed = true;
        for (const buffer of [this.keyBuffer, this.outputBuffer, this.readBuffer, this.paramsBuffer, this.messageBuffer]) buffer?.destroy();
        this.device.destroy();
    }
}
globalThis.WebGPUMIC = WebGPUMIC;

// The computation class can be loaded without the demo page UI.
if (!document.querySelector('#mic-form')) return;

const vector = {
    key: '000102030405060708090a0b0c0d0e0f',
    message: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
    mic: 'fe0df1fd9defde5f0be6882c3ddd0827',
};
document.querySelector('#key').value = vector.key;
document.querySelector('#message').value = vector.message;
const out = document.querySelector('#out');
const status = document.querySelector('#status');
const controls = document.querySelectorAll('button:not(#stop), select');
let gpu;
let busy = false;
let stopRequested = false;
document.querySelector('#stop').addEventListener('click', () => { stopRequested = true; });

function fromHex(text, name) {
    const value = text.replace(/\s/g, '');
    if (!/^[0-9a-f]*$/i.test(value) || value.length % 2) throw new Error(`${name}: требуется hex-строка с чётным числом символов`);
    return Uint8Array.from(value.match(/../g) || [], x => parseInt(x, 16));
}
function hex(bytes) { return Array.from(bytes, x => x.toString(16).padStart(2, '0')).join(''); }
function inputData(selfTest = false) {
    const key = selfTest ? fromHex(vector.key, 'KCK') : fromHex(document.querySelector('#key').value, 'KCK');
    if (key.length !== 16) throw new Error('KCK должен содержать ровно 16 байт (32 hex-символа)');
    const message = selfTest ? fromHex(vector.message, 'EAPOL') : fromHex(document.querySelector('#message').value, 'EAPOL');
    if (!selfTest && document.querySelector('#zero-mic').checked) {
        const offset = Number(document.querySelector('#mic-offset').value);
        if (!Number.isInteger(offset) || offset < 0 || offset + 16 > message.length) throw new Error('Смещение MIC должно указывать на 16 байт внутри сообщения');
        message.fill(0, offset, offset + 16);
    }
    return { key, message };
}
async function ensureGPU() {
    if (!gpu) {
        gpu = await WebGPUMIC.create();
        for (const option of document.querySelector('#workgroup').options) option.disabled = !gpu.groupSizes.includes(Number(option.value));
        document.querySelector('#workgroup').value = gpu.groupSizes.includes(256) ? '256' : String(gpu.groupSizes[gpu.groupSizes.length - 1]);
        status.textContent = 'Готово.';
    }
    await gpu.ready;
}
function setBusy(value) {
    controls.forEach(control => { control.disabled = value; });
    document.querySelector('#stop').disabled = !value;
}
async function run(mode) {
    if (busy) return;
    busy = true; stopRequested = false; setBusy(true);
    status.className = ''; status.textContent = 'Подготовка WebGPU…'; out.textContent = '';
    try {
        await ensureGPU();
        const { key, message } = inputData(mode === 'self-test');
        const variant = document.querySelector('#variant').value;
        const workgroup = Number(document.querySelector('#workgroup').value);
        if (mode === 'workgroups') {
            const count = 4096;
            const keys = Array.from({ length: count }, (_, i) => { const k = key.slice(); k[14] ^= i >>> 8; k[15] ^= i; return k; });
            const expected = (await gpu.calculate(keys, message, 'baseline', 1)).mics.map(hex);
            const variants = [{ name: 'baseline, workgroup=1', type: 'baseline', size: 1 },
                ...gpu.groupSizes.map(size => ({ name: `scalar, workgroup=${size}`, type: 'scalar', size }))];
            const samples = Object.fromEntries(variants.map(v => [v.name, []]));
            for (const v of variants) {
                if (stopRequested) throw new Error('Остановлено пользователем');
                const warm = await gpu.calculate(keys, message, v.type, v.size);
                if (warm.mics.some((mic, i) => hex(mic) !== expected[i])) throw new Error(`${v.name}: MIC не совпали с baseline`);
            }
            for (let round = 0; round < 5; round++) {
                for (let j = 0; j < variants.length; j++) {
                    if (stopRequested) throw new Error('Остановлено пользователем');
                    const v = variants[(j + round) % variants.length];
                    status.textContent = `${v.name}: ${round + 1}/5`;
                    await new Promise(resolve => setTimeout(resolve, 0));
                    const started = performance.now();
                    const result = await gpu.calculate(keys, message, v.type, v.size);
                    samples[v.name].push(performance.now() - started);
                    if (result.mics.some((mic, i) => hex(mic) !== expected[i])) throw new Error(`${v.name}: MIC не совпали с baseline`);
                }
            }
            const rows = variants.map(v => {
                const values = samples[v.name], sorted = [...values].sort((a, b) => a - b), median = sorted[2];
                return `${v.name}  median=${median.toFixed(2)} ms  rate=${(count * 1000 / median).toFixed(0)} MIC/s  min=${Math.min(...values).toFixed(2)}  max=${Math.max(...values).toFixed(2)} ms\nsamples: ${values.map(x => x.toFixed(2)).join(', ')} ms`;
            });
            out.textContent = `MIC, batch=${count}, прогрев каждого варианта и 5 чередуемых замеров. Все outputs сверены с baseline.\n` + rows.join('\n\n');
        } else if (mode === 'benchmark') {
            const counts = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096].filter(n => n <= gpu.maxBatch);
            out.textContent = `${variant === 'baseline' ? 'Baseline w[80]' : 'Scalar/unrolled'}, workgroup=${variant === 'baseline' ? 1 : workgroup}\n` +
                'KCKи различаются последним байтом; EAPOL message общий. Время включает загрузку, dispatch и readback, без компиляции shader.\n\n';
            await gpu.calculate([key], message, variant, workgroup);
            for (const count of counts) {
                if (stopRequested) throw new Error('Остановлено пользователем');
                const keys = Array.from({ length: count }, (_, i) => { const k = key.slice(); k[14] ^= i >>> 8; k[15] ^= i; return k; });
                status.textContent = `Бенчмарк: batch=${count} / ${counts[counts.length - 1]}`;
                await new Promise(resolve => setTimeout(resolve, 0));
                const start = performance.now();
                const result = await gpu.calculate(keys, message, variant, workgroup);
                out.textContent += `batch=${String(count).padStart(4)}  time=${result.time.toFixed(2)} ms  rate=${(count * 1000 / result.time).toFixed(2)} MIC/s\n`;
            }
        } else {
            const result = await gpu.calculate([key], message, variant, workgroup);
            const value = hex(result.mics[0]);
            if (mode === 'self-test' && value !== vector.mic) throw new Error(`Тестовый MIC не совпал: ${value}`);
            out.textContent = `${variant === 'baseline' ? 'Baseline w[80]' : 'Scalar/unrolled'}, workgroup=${variant === 'baseline' ? 1 : workgroup}\nMIC (16 байт):\n${value}\n\nВремя upload + GPU dispatch + readback: ${result.time.toFixed(2)} ms`;
            if (mode === 'self-test') out.textContent += '\n\nТестовый вектор совпадает.';
        }
        status.className = 'ok'; status.textContent = '✓ Готово';
    } catch (error) {
        console.error(error); status.className = 'error'; status.textContent = `Ошибка: ${error.message}`;
    } finally { busy = false; setBusy(false); }
}
document.querySelector('#mic-form').addEventListener('submit', event => { event.preventDefault(); void run('single'); });
document.querySelector('#self-test').addEventListener('click', () => void run('self-test'));
document.querySelector('#workgroups').addEventListener('click', () => void run('workgroups'));
document.querySelector('#benchmark').addEventListener('click', () => void run('benchmark'));
window.addEventListener('pagehide', () => gpu?.dispose());
})();
