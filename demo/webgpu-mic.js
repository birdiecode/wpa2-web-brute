import { WebGPUMIC } from '../src/wpa2_webgpu_mic.js';

(() => {

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
