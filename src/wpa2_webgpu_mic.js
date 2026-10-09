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
    // Full PTK records have a 64-byte stride; only words 0..3 are KCK.
    static get ptkShader() {
        return groupWGSL.replace('struct Key { words: array<u32, 4>, }',
            'struct Key { words: array<u32, 16>, }');
    }
    static async create(options = {}) {
        if (!navigator.gpu) throw new Error('WebGPU недоступен; используйте поддерживаемый браузер через HTTPS или localhost.');
        const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
        if (!adapter) throw new Error('WebGPU adapter не найден');
        const limit = Math.min(512, adapter.limits.maxComputeInvocationsPerWorkgroup, adapter.limits.maxComputeWorkgroupSizeX);
        const device = await adapter.requestDevice({ requiredLimits: {
            maxComputeInvocationsPerWorkgroup: limit, maxComputeWorkgroupSizeX: limit,
        } });
        let instance;
        try {
            instance = new WebGPUMIC(device, adapter, limit, options.lite === true);
            // Shader compilation is part of creation. Do not publish an instance
            // whose pipelines are still pending or whose ready promise may reject.
            await instance.ready;
            return instance;
        } catch (error) {
            if (instance) instance.dispose();
            else device.destroy();
            throw error;
        }
    }

    constructor(device, _adapter, groupLimit, lite = false) {
        this.device = device;
        this.maxBatch = Math.min(4096, Math.floor(device.limits.maxStorageBufferBindingSize / 16));
        this.groupSizes = GROUP_SIZES.filter(size => size <= groupLimit);
        this.defaultWorkgroupSize = this.groupSizes.includes(256) ? 256 : this.groupSizes[this.groupSizes.length - 1];
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
            if (!lite) await compile(WGSL, [['baseline']]);
            const sizes = lite ? [this.defaultWorkgroupSize] : this.groupSizes;
            await compile(groupWGSL, sizes.map(size => [`scalar${size}`, { WORKGROUP_SIZE: size }]));
        })();
        this.bindGroupLayout = bgl;
        this.keyBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        this.outputBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
        this.readBuffer = device.createBuffer({ size: 16 * this.maxBatch, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
        this.paramsBuffer = device.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
        this.messageBuffer = null;
        this.messageCapacity = 0;
        this.disposed = false;
        this.busy = false;
    }

    async calculate(keys, messageBytes, variant = 'scalar', workgroupSize = 256) {
        await this.ready;
        if (this.disposed) throw new Error('WebGPUMIC уже освобождён');
        if (this.busy) throw new Error('Дождитесь завершения предыдущего расчёта');
        this.busy = true;
        try {
        return await this._calculate(keys, messageBytes, variant, workgroupSize);
        } finally {
            this.busy = false;
        }
    }

    async _calculate(keys, messageBytes, variant = 'scalar', workgroupSize = 256) {
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
export { WebGPUMIC };
