(function () {
'use strict';

const vector = {
    password: '12345678',
    ssid: 'Test_WiFi',
    keyData: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b',
    message: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
    mic: 'f955d7dba6bd85b2560cf3f9d8a501e8',
};
const $ = selector => document.querySelector(selector);
const out = $('#out');
const status = $('#status');
const controls = document.querySelectorAll('button:not(#stop), select');
let chain;
let chainPromise;
let busy = false;
let stopRequested = false;

$('#password').value = vector.password;
$('#ssid').value = vector.ssid;
$('#key-data').value = vector.keyData;
$('#message').value = vector.message;
$('#stop').addEventListener('click', () => { stopRequested = true; });

function fromHex(text, length, name) {
    const value = text.replace(/\s/g, '');
    if (!/^[0-9a-f]*$/i.test(value) || value.length % 2 !== 0) throw new Error(`${name}: требуется hex-строка с чётным числом символов`);
    if (length !== null && value.length !== length * 2) throw new Error(`${name}: требуется ${length} байт (${length * 2} hex-символов)`);
    return Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair, 16));
}
function hex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }

async function ensureChain() {
    if (chain) return chain;
    if (!chainPromise) {
        status.textContent = 'Компиляция трёх shader для одного GPUDevice…';
        chainPromise = WPA2WebGPU.create().then(value => {
            chain = value;
            return value;
        }).catch(error => { chainPromise = null; throw error; });
    }
    return chainPromise;
}

function readInputs(useVector = false) {
    const password = useVector ? vector.password : $('#password').value;
    const ssid = useVector ? vector.ssid : $('#ssid').value;
    const keyData = useVector ? fromHex(vector.keyData, 76, 'keyData') : fromHex($('#key-data').value, 76, 'keyData');
    let message = useVector ? fromHex(vector.message, null, 'EAPOL') : fromHex($('#message').value, null, 'EAPOL');
    if (!useVector && message.length < 4) throw new Error('Введите полный EAPOL frame (не менее 4 байт)');
    if (typeof password !== 'string' || typeof ssid !== 'string') throw new TypeError('Пароль и SSID должны быть строками');
    if (!useVector && $('#zero-mic').checked) {
        const offset = Number($('#mic-offset').value);
        if (!Number.isInteger(offset) || offset < 0 || offset + 16 > message.length) throw new Error('MIC field должен указывать на 16 байт внутри EAPOL');
        message = message.slice();
        message.fill(0, offset, offset + 16);
    }
    return { password, ssid, keyData, message };
}

async function derive(passwords, ssid, keyData, message, onStage = () => {}) {
    const gpu = await ensureChain();
    if (stopRequested) throw new Error('Остановлено пользователем');
    onStage('PMK → PTK → MIC на GPU…');
    return gpu.derive(passwords, ssid, keyData, message);
}

async function benchmarkLarge(input) {
    const gpu = await ensureChain();
    const repeats = Number($('#repeats').value);
    if (![5, 10].includes(repeats)) throw new Error('Выберите 5 или 10 прогонов');
    const sizes = [4096, 8192, 16384, 32768].filter(n => n <= gpu.maxBatch);
    if (!sizes.length) throw new Error('Лимиты GPU не позволяют batch 4096');
    const cases = sizes.map(count => ({
        count, passwords: Array.from({ length: count }, (_, i) => String(10000000 + i)),
        samples: [], expected: null,
    }));
    out.textContent = `Полная цепочка, ${repeats} прогонов после прогрева каждого batch.\n` +
        'Порядок batch чередуется. Время: упаковка входов, upload, три dispatch и один readback MIC.\n' +
        'Создание паролей, компиляция и проверка результатов исключены. Все MIC сверяются с прогревом.\n\n';
    for (const n of [4096, 8192, 16384, 32768].filter(n => n > gpu.maxBatch))
        out.textContent += `batch=${n}: пропущен, лимит GPU ${gpu.maxBatch}\n`;
    for (const item of cases) {
        if (stopRequested) throw new Error('Остановлено пользователем');
        status.textContent = `Прогрев batch=${item.count}`;
        await new Promise(resolve => setTimeout(resolve, 0));
        item.expected = (await derive(item.passwords, input.ssid, input.keyData, input.message)).mics;
    }
    for (let round = 0; round < repeats; round++) {
        for (let j = 0; j < cases.length; j++) {
            if (stopRequested) throw new Error('Остановлено пользователем');
            const item = cases[(j + round) % cases.length];
            status.textContent = `batch=${item.count}, прогон ${round + 1}/${repeats}`;
            await new Promise(resolve => setTimeout(resolve, 0));
            const start = performance.now();
            const result = await derive(item.passwords, input.ssid, input.keyData, input.message);
            const elapsed = performance.now() - start;
            if (result.mics.length !== item.expected.length ||
                result.mics.some((mic, i) => mic.some((byte, k) => byte !== item.expected[i][k])))
                throw new Error(`MIC не совпали с прогревом при batch=${item.count}`);
            item.samples.push(elapsed);
            out.textContent += `batch=${item.count}  прогон=${round + 1}  ${elapsed.toFixed(2)} ms\n`;
        }
    }
    out.textContent += '\nМедианы полной цепочки:\n';
    for (const item of cases) {
        const sorted = [...item.samples].sort((a, b) => a - b);
        const middle = Math.floor(sorted.length / 2);
        const median = sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
        out.textContent += `batch=${item.count}  median=${median.toFixed(2)} ms  rate=${(item.count * 1000 / median).toFixed(2)} цепочек/s  min=${sorted[0].toFixed(2)}  max=${sorted.at(-1).toFixed(2)} ms\n` +
            `samples: ${item.samples.map(n => n.toFixed(2)).join(', ')} ms\n\n`;
    }
}

function setBusy(value) {
    controls.forEach(control => { control.disabled = value; });
    $('#stop').disabled = !value;
}
async function run(mode) {
    if (busy) return;
    busy = true; stopRequested = false; setBusy(true);
    status.className = ''; out.textContent = '';
    try {
        const input = readInputs(mode === 'self-test');
        if (mode === 'large-benchmark') {
            await benchmarkLarge(input);
        } else if (mode === 'benchmark') {
            const password0 = '10000000';
            status.textContent = 'Прогрев полной цепочки…';
            await derive([password0], input.ssid, input.keyData, input.message);
            out.textContent = 'Одна цепочка на пароль; время включает подготовку, загрузку, три WebGPU dispatch и один readback итогового MIC. Компиляция shader исключена.\n\n';
            for (let count = 1; count <= 4096; count *= 2) {
                if (stopRequested) throw new Error('Остановлено пользователем');
                const passwords = Array.from({ length: count }, (_, i) => String(10000000 + i));
                status.textContent = `Полная цепочка: batch=${count} / 4096`;
                await new Promise(resolve => setTimeout(resolve, 0));
                const start = performance.now();
                await derive(passwords, input.ssid, input.keyData, input.message);
                const elapsed = performance.now() - start;
                out.textContent += `batch=${String(count).padStart(4)}  time=${elapsed.toFixed(2)} ms  rate=${(count * 1000 / elapsed).toFixed(2)} цепочек/s\n`;
            }
        } else {
            const initStart = performance.now();
            await ensureChain();
            const initTime = performance.now() - initStart;
            const start = performance.now();
            const result = await derive([input.password], input.ssid, input.keyData, input.message,
                text => { status.textContent = text; });
            const mic = hex(result.mics[0]);
            out.textContent = `MIC (16 байт):\n${mic}\n\n` +
                `Полная цепочка: ${(performance.now() - start).toFixed(2)} ms (shader init: ${initTime.toFixed(2)} ms, отдельно)`;
            if (mode === 'self-test') {
                out.textContent = `Ожидаемый MIC:\n${vector.mic}\n\n` + out.textContent;
                if (mic !== vector.mic) throw new Error(`Тестовый MIC не совпал: получено ${mic}`);
                out.textContent += '\n\nПолная цепочка PMK → PTK → MIC совпадает с тестовым вектором.';
            }
        }
        status.className = 'ok'; status.textContent = '✓ Готово';
    } catch (error) {
        console.error(error); status.className = 'error'; status.textContent = `Ошибка: ${error.message}`;
    } finally { busy = false; setBusy(false); }
}

$('#wpa2-form').addEventListener('submit', event => { event.preventDefault(); void run('single'); });
$('#self-test').addEventListener('click', () => void run('self-test'));
$('#large-benchmark').addEventListener('click', () => void run('large-benchmark'));
$('#benchmark').addEventListener('click', () => void run('benchmark'));
window.addEventListener('pagehide', () => {
    if (!chain) return;
    chain.dispose(); chain = null; chainPromise = null;
});
})();
