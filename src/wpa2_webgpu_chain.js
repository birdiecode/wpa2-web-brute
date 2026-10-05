// Three ordered GPU passes, one submission, one final MIC readback.
(function () {
'use strict';
class WPA2WebGPU {
    static async create() {
        if (!navigator.gpu) throw new Error('WebGPU недоступен; используйте HTTPS или localhost');
        const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
        if (!adapter) throw new Error('WebGPU adapter не найден');
        const device = await adapter.requestDevice();
        const chain = new WPA2WebGPU(device);
        try {
            const sources = [WebGPUPMK.shader, WebGPUPTK.shader, WebGPUMIC.ptkShader];
            for (let i = 0; i < sources.length; i++) {
                const module = device.createShaderModule({ code: sources[i] });
                const info = await module.getCompilationInfo();
                const errors = info.messages.filter(m => m.type === 'error');
                if (errors.length) throw new Error(errors.map(m => m.message).join('\n'));
                chain.pipelines.push(await device.createComputePipelineAsync({
                    layout: 'auto',
                    compute: { module, entryPoint: 'main', constants: { WORKGROUP_SIZE: chain.groups[i] } },
                }));
            }
            return chain;
        } catch (error) { chain.dispose(); throw error; }
    }
    constructor(device) {
        this.device = device;
        this.inputSize = WebGPUPMK.inputSize;
        this.groups = [32, 256, 256].map(n => Math.min(n,
            device.limits.maxComputeInvocationsPerWorkgroup, device.limits.maxComputeWorkgroupSizeX));
        this.maxBatch = Math.min(32768,
            Math.floor(device.limits.maxStorageBufferBindingSize / this.inputSize),
            Math.floor(device.limits.maxBufferSize / this.inputSize),
            device.limits.maxComputeWorkgroupsPerDimension * Math.min(...this.groups));
        this.pipelines = [];
        this.buffers = [];
        this.busy = false;
        this.disposed = false;
        this.lost = false;
        device.lost.then(() => { this.lost = true; });
        const storage = GPUBufferUsage.STORAGE;
        this.input = this.buffer(this.inputSize * this.maxBatch, storage | GPUBufferUsage.COPY_DST);
        // Intermediate keys cannot be mapped or copied to CPU: STORAGE usage only.
        this.pmk = this.buffer(32 * this.maxBatch, storage);
        this.ptk = this.buffer(64 * this.maxBatch, storage);
        this.mic = this.buffer(16 * this.maxBatch, storage | GPUBufferUsage.COPY_SRC);
        this.readback = this.buffer(16 * this.maxBatch, GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ);
        this.prf = this.buffer(128, storage | GPUBufferUsage.COPY_DST);
        this.params = this.buffer(16, GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST);
        this.message = null;
        this.messageCapacity = 0;
    }
    buffer(size, usage) {
        const buffer = this.device.createBuffer({ size, usage });
        this.buffers.push(buffer);
        return buffer;
    }
    async derive(passwords, ssid, keyData, message) {
        if (this.disposed || this.lost) throw new Error('Устройство WebGPU недоступно; перезагрузите страницу');
        if (this.busy) throw new Error('Дождитесь завершения текущего расчёта');
        if (!Array.isArray(passwords) || passwords.length < 1 || passwords.length > this.maxBatch)
            throw new Error(`Batch должен быть от 1 до ${this.maxBatch}`);
        const enc = new TextEncoder();
        if (typeof ssid !== 'string') throw new TypeError('SSID должен быть строкой');
        const salt = enc.encode(ssid);
        if (salt.length < 1 || salt.length > 32) throw new Error('SSID должен быть 1–32 байта UTF-8');
        if (!(keyData instanceof Uint8Array) || keyData.length !== 76) throw new Error('keyData должен содержать 76 байт');
        if (!(message instanceof Uint8Array)) throw new TypeError('EAPOL должен быть Uint8Array');
        const count = passwords.length;
        const stride = this.inputSize / 4;
        const input = new Uint32Array(stride * count);
        passwords.forEach((password, i) => {
            if (typeof password !== 'string') throw new TypeError('Пароль должен быть строкой');
            const bytes = enc.encode(password);
            if (bytes.length < 8 || bytes.length > 63) throw new Error('Пароль должен содержать 8–63 байта UTF-8');
            input.set(bytes, i * stride);
            input.set(salt, i * stride + 64);
            input[i * stride + 96] = salt.length;
        });
        const prf = new Uint8Array(128);
        prf.set(enc.encode('Pairwise key expansion'));
        prf.set(keyData, 23);
        prf[100] = 0x80;
        new DataView(prf.buffer).setUint32(124, 164 * 8, false);
        const paddedSize = Math.ceil((message.length + 9) / 64) * 64;
        if (paddedSize > this.device.limits.maxStorageBufferBindingSize) throw new Error('EAPOL превышает лимит GPU buffer');
        const padded = new Uint8Array(paddedSize);
        padded.set(message);
        padded[message.length] = 0x80;
        const bits = (64 + message.length) * 8;
        const view = new DataView(padded.buffer);
        view.setUint32(paddedSize - 8, Math.floor(bits / 0x100000000), false);
        view.setUint32(paddedSize - 4, bits >>> 0, false);
        const words = bytes => {
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            return Uint32Array.from({ length: bytes.length / 4 }, (_, i) => view.getUint32(i * 4, false));
        };
        this.busy = true;
        try {
            if (paddedSize > this.messageCapacity) {
                if (this.message) {
                    this.message.destroy();
                    this.buffers.splice(this.buffers.indexOf(this.message), 1);
                }
                this.message = this.buffer(paddedSize, GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST);
                this.messageCapacity = paddedSize;
            }
            const queue = this.device.queue;
            queue.writeBuffer(this.input, 0, input);
            queue.writeBuffer(this.prf, 0, words(prf));
            queue.writeBuffer(this.message, 0, words(padded));
            queue.writeBuffer(this.params, 0, new Uint32Array([paddedSize / 64, 0, 0, 0]));
            const resources = [
                [[this.input, input.byteLength], [this.pmk, count * 32]],
                [[this.pmk, count * 32], [this.ptk, count * 64], [this.prf, 128]],
                [[this.ptk, count * 64], [this.message, paddedSize], [this.mic, count * 16], [this.params, 16]],
            ];
            const encoder = this.device.createCommandEncoder();
            for (let stage = 0; stage < 3; stage++) {
                const pipeline = this.pipelines[stage];
                const group = this.device.createBindGroup({
                    layout: pipeline.getBindGroupLayout(0),
                    entries: resources[stage].map(([buffer, size], binding) => ({
                        binding, resource: { buffer, size },
                    })),
                });
                // Separate passes order writes before the next stage reads the same storage.
                const pass = encoder.beginComputePass();
                pass.setPipeline(pipeline);
                pass.setBindGroup(0, group);
                pass.dispatchWorkgroups(Math.ceil(count / this.groups[stage]));
                pass.end();
            }
            encoder.copyBufferToBuffer(this.mic, 0, this.readback, 0, count * 16);
            queue.submit([encoder.finish()]);
            await this.readback.mapAsync(GPUMapMode.READ, 0, count * 16);
            let result;
            try { result = new Uint32Array(this.readback.getMappedRange(0, count * 16).slice(0)); }
            finally { this.readback.unmap(); }
            return { mics: Array.from({ length: count }, (_, i) => {
                const bytes = new Uint8Array(16), view = new DataView(bytes.buffer);
                for (let j = 0; j < 4; j++) view.setUint32(j * 4, result[i * 4 + j], false);
                return bytes;
            }) };
        } finally { this.busy = false; }
    }
    dispose() {
        if (this.disposed) return;
        this.disposed = true;
        for (const buffer of this.buffers) buffer.destroy();
        this.device.destroy();
    }
}
globalThis.WPA2WebGPU = WPA2WebGPU;
})();
