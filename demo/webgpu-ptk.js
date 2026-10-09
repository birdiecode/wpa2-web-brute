import { initWebGPU, packInput, calculateBatch, INPUT_SIZE, MAX_BATCH, WORKGROUP_SIZES } from '../src/wpa2_webgpu_ptk.js';

(async () => {
if (!document.querySelector('#ptk-form')) return;
const out = document.querySelector('#out');
const status = document.querySelector('#status');
const buttons = document.querySelectorAll('button:not(#stop), select');
let stopRequested = false;
document.querySelector('#stop').addEventListener('click', () => { stopRequested = true; });

function fromHex(text, length, name) {
    const value = text.replace(/\s/g, '');
    if (!/^[0-9a-f]+$/i.test(value) || value.length !== length * 2) {
        throw new Error(`${name}: требуется ${length * 2} hex-символов (${length} байт)`);
    }
    return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
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
if (document.querySelector('#ptk-form')) {
    document.querySelector('#pmk').value = vector.pmk;
    document.querySelector('#key-data').value = vector.keyData;
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
