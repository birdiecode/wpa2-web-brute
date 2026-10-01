(async () => {
'use strict';

// WPA2 PRF-512: PMK (32 bytes) + ordered keyData (76 bytes) -> PTK (64 bytes).
const WGSL = /* wgsl */ `
struct Input {
    pmk: array<u32, 8>,
    message: array<u32, 32>,
}
struct Output { ptk: array<u32, 16>, }
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
    var w: array<u32, 80>;
    for (var i = 0u; i < 16u; i++) { w[i] = blockIn[i]; }
    for (var i = 16u; i < 80u; i++) {
        w[i] = rol(w[i-3u] ^ w[i-8u] ^ w[i-14u] ^ w[i-16u], 1u);
    }
    var a = stateIn[0];
    var b = stateIn[1];
    var c = stateIn[2];
    var d = stateIn[3];
    var e = stateIn[4];
    for (var i = 0u; i < 80u; i++) {
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
        let temp = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30u); b = a; a = temp;
    }
    return array<u32, 5>(stateIn[0]+a, stateIn[1]+b, stateIn[2]+c, stateIn[3]+d, stateIn[4]+e);
}


fn hmac_state(pad: u32) -> array<u32, 5> {
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = pad; }
    for (var i = 0u; i < 8u; i++) { block[i] ^= input.pmk[i]; }
    return sha1_compress(sha1_init(), block);
}
@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    input = inputs[id.x];
    let innerBase = hmac_state(0x36363636u);
    let outerBase = hmac_state(0x5c5c5c5cu);
    var first: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { first[i] = input.message[i]; }
    let innerFirst = sha1_compress(innerBase, first);
    // PRF counters start at zero. Concatenate four HMAC-SHA1 digests.
    for (var counter = 0u; counter < 4u; counter++) {
        var tail: array<u32, 16>;
        for (var i = 0u; i < 16u; i++) { tail[i] = input.message[16u+i]; }
        tail[8] |= counter; // Byte 99: one-byte counter after the 76-byte keyData.
        let innerHash = sha1_compress(innerFirst, tail);
        var outer: array<u32, 16>;
        for (var i = 0u; i < 5u; i++) { outer[i] = innerHash[i]; }
        outer[5] = 0x80000000u;
        outer[15] = 84u * 8u;
        let digest = sha1_compress(outerBase, outer);
        for (var i = 0u; i < 5u; i++) {
            let index = counter * 5u + i;
            if (index < 16u) { outputs[id.x].ptk[index] = digest[i]; }
        }
    }
}
`;

// Emit a universal SHA-1 compression with scalar schedule words and 80 static rounds.
function generateSHA1Unrolled() {
    const lines = ['fn sha1_unrolled(stateIn: array<u32, 5>, blockIn: array<u32, 16>) -> array<u32, 5> {'];
    for (let i = 0; i < 16; i++) lines.push(`    var w${i}: u32 = blockIn[${i}];`);
    for (const [i, name] of ['a', 'b', 'c', 'd', 'e'].entries()) lines.push(`    var ${name} = stateIn[${i}];`);
    for (let i = 0; i < 80; i++) {
        const j = i & 15;
        if (i >= 16) lines.push(`    w${j} = rol(w${(i - 3) & 15} ^ w${(i - 8) & 15} ^ w${(i - 14) & 15} ^ w${j}, 1u);`);
        const f = i < 20 ? '((b & c) | ((~b) & d))' : i < 40 ? '(b ^ c ^ d)' :
            i < 60 ? '((b & c) | (b & d) | (c & d))' : '(b ^ c ^ d)';
        const k = ['0x5a827999u', '0x6ed9eba1u', '0x8f1bbcdcu', '0xca62c1d6u'][Math.floor(i / 20)];
        lines.push(`    { let next = rol(a, 5u) + ${f} + e + ${k} + w${j}; e = d; d = c; c = rol(b, 30u); b = a; a = next; }`);
    }
    lines.push('    return array<u32, 5>(stateIn[0]+a, stateIn[1]+b, stateIn[2]+c, stateIn[3]+d, stateIn[4]+e);', '}');
    return lines.join('\n');
}
const compressionStart = WGSL.indexOf('fn sha1_compress(');
const compressionEnd = WGSL.indexOf('\n}\n', compressionStart) + 3;
const SHA1_SCALAR_WGSL = WGSL.slice(0, compressionStart) + generateSHA1Unrolled() + WGSL.slice(compressionEnd);
const SCALAR_WGSL = SHA1_SCALAR_WGSL.replaceAll('sha1_compress(', 'sha1_unrolled(');
const WORKGROUP_SIZES = [1, 32, 64, 128, 256, 512];
const GROUP_WGSL = SCALAR_WGSL
    .replace('@compute @workgroup_size(1)',
        'override WORKGROUP_SIZE: u32 = 32u;\n@compute @workgroup_size(WORKGROUP_SIZE)')
    .replace('    input = inputs[id.x];',
        '    if (id.x >= arrayLength(&inputs)) { return; }\n    input = inputs[id.x];');

const INPUT_SIZE = 160;
const OUTPUT_SIZE = 64;
const MAX_BATCH = 4096;
const out = document.querySelector('#out');
const status = document.querySelector('#status');
const buttons = document.querySelectorAll('button:not(#stop), select');
let stopRequested = false;
document.querySelector('#stop').addEventListener('click', () => { stopRequested = true; });

async function initWebGPU() {
    if (!navigator.gpu) throw new Error('WebGPU недоступен. Откройте страницу через HTTPS или localhost в браузере с поддержкой WebGPU.');
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) throw new Error('WebGPU adapter не найден');
    const groupLimit = Math.min(512, adapter.limits.maxComputeInvocationsPerWorkgroup, adapter.limits.maxComputeWorkgroupSizeX);
    const device = await adapter.requestDevice({ requiredLimits: {
        maxComputeInvocationsPerWorkgroup: groupLimit,
        maxComputeWorkgroupSizeX: groupLimit,
    } });
    try {
        const bindGroupLayout = device.createBindGroupLayout({ entries: [
            { binding: 0, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'read-only-storage' } },
            { binding: 1, visibility: GPUShaderStage.COMPUTE, buffer: { type: 'storage' } },
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
        await compile(WGSL, [['baseline', 'main']]);
        await compile(GROUP_WGSL, WORKGROUP_SIZES.filter(size => size <= groupLimit).map(size =>
            [`scalar${size}`, 'main', { WORKGROUP_SIZE: size }]));
        const workgroupSizes = WORKGROUP_SIZES.filter(size => size <= groupLimit);
        const inputBuffer = device.createBuffer({ size: INPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        const outputBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
        const readBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
        const bindGroup = device.createBindGroup({
            layout: bindGroupLayout,
            entries: [
                { binding: 0, resource: { buffer: inputBuffer } },
                { binding: 1, resource: { buffer: outputBuffer } },
            ],
        });
        return { device, pipelines, inputBuffer, outputBuffer, readBuffer, bindGroup, workgroupSizes };
    } catch (error) {
        device.destroy();
        throw error;
    }
}

function fromHex(text, length, name) {
    const value = text.replace(/\s/g, '');
    if (!/^[0-9a-f]+$/i.test(value) || value.length !== length * 2) {
        throw new Error(`${name}: требуется ${length * 2} hex-символов (${length} байт)`);
    }
    return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
}

function packInput(pmk, keyData) {
    const message = new Uint8Array(128);
    message.set(new TextEncoder().encode('Pairwise key expansion'));
    // Byte 22 is the zero separator; byte 99 is the counter, initially zero.
    message.set(keyData, 23);
    message[100] = 0x80;
    new DataView(message.buffer).setUint32(124, (64 + 100) * 8, false);
    const data = new Uint32Array(INPUT_SIZE / 4);
    const keyView = new DataView(pmk.buffer, pmk.byteOffset, pmk.byteLength);
    const messageView = new DataView(message.buffer);
    for (let i = 0; i < 8; i++) data[i] = keyView.getUint32(i * 4, false);
    for (let i = 0; i < 32; i++) data[8+i] = messageView.getUint32(i * 4, false);
    return data;
}

function readInput() {
    return packInput(fromHex(document.querySelector('#pmk').value, 32, 'PMK'),
        fromHex(document.querySelector('#key-data').value, 76, 'keyData'));
}
// Synthetic vector shared with the WebGL2 page; independently computed with Python hmac.
const vector = {
    pmk: Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(''),
    keyData: Array.from({ length: 76 }, (_, i) => i.toString(16).padStart(2, '0')).join(''),
    ptk: 'e4498e7375804649bee63f3e89639568e2e43cea122829e4caf9a0d903a7c1ed4a7a2be58646bd0a7530f5b3ccce0e6652e88b8747478cf5785260c8c3e7dd2a',
};
document.querySelector('#pmk').value = vector.pmk;
document.querySelector('#key-data').value = vector.keyData;

// One invocation per input record; a batch is submitted in one dispatch.
async function calculateBatch(gpu, data, variant = 'scalar', workgroupSize = 32) {
    const count = data.length / (INPUT_SIZE / 4);
    if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH) {
        throw new Error(`Размер batch должен быть от 1 до ${MAX_BATCH}`);
    }
    if (variant !== 'baseline' && variant !== 'scalar') throw new Error('Неизвестная реализация PTK');
    if (variant === 'baseline') workgroupSize = 1;
    if (!gpu.workgroupSizes.includes(workgroupSize)) throw new Error('Этот размер workgroup недоступен');
    const { device, pipelines, inputBuffer, outputBuffer, readBuffer, bindGroup } = gpu;
    device.queue.writeBuffer(inputBuffer, 0, data);
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    const selectedPipeline = variant === 'baseline' ? pipelines.baseline : pipelines[`scalar${workgroupSize}`];
    const selectedBindGroup = variant === 'baseline' ? bindGroup : device.createBindGroup({
        layout: selectedPipeline.getBindGroupLayout(0),
        entries: [
            { binding: 0, resource: { buffer: inputBuffer, size: data.byteLength } },
            { binding: 1, resource: { buffer: outputBuffer } },
        ],
    });
    pass.setPipeline(selectedPipeline);
    pass.setBindGroup(0, selectedBindGroup);
    pass.dispatchWorkgroups(Math.ceil(count / workgroupSize));
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
        data[offset + 7] ^= i;
    }
    return data;
}
function median(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function compareWorkgroups(gpu, base) {
    const count = 4096;
    const sizes = gpu.workgroupSizes;
    const data = makeBatch(base, count);
    const samples = Object.fromEntries(sizes.map(size => [size, []]));
    let expected;
    out.textContent = 'PTK: batch=4096, прогрев каждого размера, 5 замеров с чередованием порядка.\n' +
        'Время включает upload, кодирование команд, вычисление и чтение. Все PTK сверяются с baseline.\n\n';
    for (const size of WORKGROUP_SIZES.filter(size => !sizes.includes(size))) {
        out.textContent += `workgroup=${size}: пропущен — превышает лимит адаптера.\n`;
    }
    const check = words => {
        if (!expected) expected = words;
        else if (words.some((word, i) => word !== expected[i])) throw new Error('PTK не совпали между реализациями');
        if (stopRequested) throw new Error('Остановлено пользователем');
    };
    status.textContent = 'Прогрев PTK baseline';
    check((await calculateBatch(gpu, data, 'baseline', 1)).words);
    for (const size of sizes) {
        if (stopRequested) throw new Error('Остановлено пользователем');
        status.textContent = `Прогрев PTK scalar, workgroup=${size}`;
        await new Promise(resolve => setTimeout(resolve, 0));
        check((await calculateBatch(gpu, data, 'scalar', size)).words);
    }
    const variants = [{ name: 'baseline, workgroup=1', size: 1, type: 'baseline' },
        ...sizes.map(size => ({ name: `scalar, workgroup=${size}`, size, type: 'scalar' }))];
    const results = Object.fromEntries(variants.map(v => [v.name, []]));
    for (let round = 0; round < 5; round++) {
        for (let j = 0; j < variants.length; j++) {
            if (stopRequested) throw new Error('Остановлено пользователем');
            const v = variants[(j + round) % variants.length];
            status.textContent = `${v.name}, замер ${round + 1}/5`;
            await new Promise(resolve => setTimeout(resolve, 0));
            const start = performance.now();
            const r = await calculateBatch(gpu, data, v.type, v.size);
            results[v.name].push(performance.now() - start);
            check(r.words);
        }
    }
    for (const v of variants) {
        const times = results[v.name], med = median(times);
        out.textContent += `${v.name}  dispatchWorkgroups=${Math.ceil(count / v.size)}\n` +
            `median=${med.toFixed(2)} ms  rate=${(count * 1000 / med).toFixed(2)} PTK/s  ` +
            `min=${Math.min(...times).toFixed(2)}  max=${Math.max(...times).toFixed(2)} ms\n` +
            `samples: ${times.map(t => t.toFixed(2)).join(', ')} ms\n\n`;
    }
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
            const variant = document.querySelector('#variant').value;
            const workgroupSize = variant === 'baseline' ? 1 : Number(document.querySelector('#workgroup').value);
            const base = mode === 'self-test' ? packInput(fromHex(vector.pmk, 32, 'PMK'), fromHex(vector.keyData, 76, 'keyData')) : readInput();
            if (mode === 'workgroups') {
                await compareWorkgroups(gpu, base);
            } else if (mode === 'benchmark') {
                out.textContent = `${variant === 'baseline' ? 'Baseline w[80]' : 'Scalar/unrolled'}, workgroup=${workgroupSize}\n` +
                    'Для каждого элемента меняется PMK; keyData из поля.\nВремя включает подготовку и загрузку данных, расчёт и чтение результата; без компиляции и выделения GPU-буферов.\n\n';
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
                    out.textContent += `batch=${String(count).padStart(4)}  time=${elapsed.toFixed(2)} ms  rate=${rate} PTK/s\n`;
                }
            } else {
                const result = await calculateBatch(gpu, base, variant, workgroupSize);
                if (deviceLost) return;
                if (stopRequested) throw new Error('Остановлено пользователем');
                const value = hex(result.words);
                if (mode === 'self-test' && value !== vector.ptk) throw new Error(`PTK не совпадает с тестовым вектором. Получено: ${value}`);
                out.textContent = `${variant === 'baseline' ? 'Baseline w[80]' : 'Scalar/unrolled'}, workgroup=${workgroupSize}\n\nPTK (64 байта):\n${value}\n\nGPU dispatch + readback:\n${result.time.toFixed(2)} ms`;
                if (mode === 'self-test') out.textContent += '\n\nТестовый вектор совпадает.';
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
    document.querySelector('#ptk-form').addEventListener('submit', event => {
        event.preventDefault();
        void run();
    });
    document.querySelector('#workgroups').addEventListener('click', () => { void run('workgroups'); });
    document.querySelector('#benchmark').addEventListener('click', () => { void run('benchmark'); });
    document.querySelector('#self-test').addEventListener('click', () => { void run('self-test'); });
    status.textContent = 'Готово.';
    setDisabled(false);
} catch (error) {
    showError(error);
}

})();
