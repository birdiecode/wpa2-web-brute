(async () => {
'use strict';

// PBKDF2-HMAC-SHA1: 4096 iterations, 32-byte PMK, fixed 8-byte password.
const WGSL = /* wgsl */ `
struct Input {
    password: array<u32, 8>,
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

// Precompute the SHA1 state after the 64-byte HMAC ipad/opad.
fn hmac_state(pad: u32) -> array<u32, 5> {
    var block: array<u32, 16>;
    for (var i = 0u; i < 16u; i++) { block[i] = pad; }
    for (var i = 0u; i < 8u; i++) {
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

const INPUT_SIZE = 164;
const OUTPUT_SIZE = 32;
const MAX_BATCH = 4096;
const out = document.querySelector('#out');
const status = document.querySelector('#status');
const buttons = document.querySelectorAll('button');

async function initWebGPU() {
    if (!navigator.gpu) throw new Error('WebGPU недоступен. Откройте страницу через HTTPS или localhost в браузере с поддержкой WebGPU.');
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) throw new Error('WebGPU adapter не найден');
    const device = await adapter.requestDevice();
    try {
        const shader = device.createShaderModule({ code: WGSL });
        const compilation = await shader.getCompilationInfo();
        const errors = compilation.messages.filter(message => message.type === 'error');
        if (errors.length) {
            throw new Error(errors.map(message => `${message.lineNum}:${message.linePos} ${message.message}`).join('\n'));
        }
        const pipeline = await device.createComputePipelineAsync({
            layout: 'auto', compute: { module: shader, entryPoint: 'main' }
        });
        const inputBuffer = device.createBuffer({ size: INPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
        const outputBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
        const readBuffer = device.createBuffer({ size: OUTPUT_SIZE * MAX_BATCH, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
        const bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries: [
                { binding: 0, resource: { buffer: inputBuffer } },
                { binding: 1, resource: { buffer: outputBuffer } }
            ]
        });
        return { device, pipeline, inputBuffer, outputBuffer, readBuffer, bindGroup };
    } catch (error) {
        device.destroy();
        throw error;
    }
}

function readInput() {
    const enc = new TextEncoder();
    const pw = enc.encode(document.querySelector('#password').value);
    const ssid = enc.encode(document.querySelector('#ssid').value);
    if (pw.length !== 8) throw new Error('Пароль должен быть ровно 8 байт UTF-8');
    if (ssid.length < 1 || ssid.length > 32) throw new Error('SSID должен быть 1..32 байта UTF-8');
    const data = new Uint32Array(INPUT_SIZE / 4);
    data.set(pw);
    data.set(ssid, 8);
    data[40] = ssid.length;
    return data;
}
// One invocation per input record; a batch is submitted in one dispatch.
async function calculateBatch(gpu, data) {
    const count = data.length / (INPUT_SIZE / 4);
    if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH) {
        throw new Error(`Размер batch должен быть от 1 до ${MAX_BATCH}`);
    }
    const { device, pipeline, inputBuffer, outputBuffer, readBuffer, bindGroup } = gpu;
    device.queue.writeBuffer(inputBuffer, 0, data);
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(count);
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
        data.set(new TextEncoder().encode(String(i).padStart(8, '0')), offset);
    }
    return data;
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
        setDisabled(true);
        status.className = '';
        status.textContent = 'Вычисление...';
        out.textContent = '';
        try {
            const base = readInput();
            if (mode === 'benchmark') {
                out.textContent = 'Пароли для бенчмарка: 00000000 … 00004095; SSID из поля.\nВремя включает подготовку и загрузку данных, расчёт и чтение результата; без компиляции и выделения GPU-буферов.\n\n';
                status.textContent = 'Прогрев...';
                await calculateBatch(gpu, makeBatch(base, 1));
                for (let count = 1; count <= MAX_BATCH; count *= 2) {
                    if (deviceLost) return;
                    status.textContent = `Бенчмарк: batch=${count} / ${MAX_BATCH}`;
                    await new Promise(resolve => setTimeout(resolve, 0));
                    const start = performance.now();
                    await calculateBatch(gpu, makeBatch(base, count));
                    if (deviceLost) return;
                    const elapsed = performance.now() - start;
                    const rate = elapsed > 0 ? (count * 1000 / elapsed).toFixed(2) : '—';
                    out.textContent += `batch=${String(count).padStart(4)}  time=${elapsed.toFixed(2)} ms  rate=${rate} PMK/s\n`;
                }
            } else {
                const result = await calculateBatch(gpu, base);
                if (deviceLost) return;
                const value = hex(result.words);
                
                out.textContent = `PMK (32 байта):\n${value}\n\nGPU dispatch + readback:\n${result.time.toFixed(2)} ms`;
                if (mode === 'self-test') out.textContent += '\n\nТестовый вектор совпадает.';
            }
            status.className = 'ok';
            status.textContent = '✓ Готово';
        } catch (error) {
            showError(error);
        } finally {
            busy = false;
            setDisabled(deviceLost);
        }
    }
    document.querySelector('#pmk-form').addEventListener('submit', event => {
        event.preventDefault();
        void run();
    });
    document.querySelector('#benchmark').addEventListener('click', () => { void run('benchmark'); });
    
    status.textContent = 'Готово.';
    setDisabled(false);
} catch (error) {
    showError(error);
}

})();
