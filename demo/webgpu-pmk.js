import { initWebGPU, packInput, calculateBatch, INPUT_SIZE, MAX_BATCH, WORKGROUP_SIZES, VARIANTS } from '../src/wpa2_webgpu_pmk.js';

(async () => {
if (!document.querySelector('#pmk-form')) return;
const out = document.querySelector('#out');
const status = document.querySelector('#status');
const buttons = document.querySelectorAll('button:not(#stop), select, input');
let stopRequested = false;
document.querySelector('#stop').addEventListener('click', () => { stopRequested = true; });

function readInput() { return packInput(document.querySelector('#password').value, document.querySelector('#ssid').value); }
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
