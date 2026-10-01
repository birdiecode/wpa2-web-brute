(function () {
'use strict';

const vector = {
    password: '12345678',
    ssid: 'Test_WiFi',
    keyData: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b',
    message: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
    pmk: 'e4a5c4c71b86171f29c19bd0ed6ef0217a32f402ace8066ec5dab52456843c37',
    ptk: '53a67a28658402b0d50a1c121ba5462a22575f50fc02d10f6041bf2dd5ea024dc01f27922387be818f29fca711598092f47677806a6f7517487d9e82117aa27d',
    mic: 'f955d7dba6bd85b2560cf3f9d8a501e8',
};
const $ = selector => document.querySelector(selector);
const out = $('#out');
const status = $('#status');
const controls = document.querySelectorAll('button:not(#stop)');
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
    if (chainPromise) return chainPromise;
    chainPromise = (async () => {
        const parts = [];
        try {
            status.textContent = 'Компиляция PMK shader…';
            const pmk = await WebGPUPMK.create(); parts.push(pmk);
            status.textContent = 'Компиляция PTK shader…';
            const ptk = await WebGPUPTK.create(); parts.push(ptk);
            status.textContent = 'Компиляция MIC shader…';
            const mic = await WebGPUMIC.create({ lite: true }); parts.push(mic);
            chain = { pmk, ptk, mic };
            return chain;
        } catch (error) {
            for (const part of parts) { try { part.dispose(); } catch (_) {} }
            chainPromise = null;
            throw error;
        }
    })();
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
    onStage('PBKDF2: генерация PMK…');
    const pmkResult = await gpu.pmk.calculate(passwords, ssid);
    if (stopRequested) throw new Error('Остановлено пользователем');
    onStage('PRF-512: генерация PTK…');
    const ptkResult = await gpu.ptk.calculate(pmkResult.pmks, keyData);
    if (stopRequested) throw new Error('Остановлено пользователем');
    onStage('HMAC-SHA1: расчёт MIC…');
    const kcks = ptkResult.ptks.map(ptk => ptk.slice(0, 16));
    const micResult = await gpu.mic.calculate(kcks, message, 'scalar', gpu.mic.defaultWorkgroupSize);
    return { pmks: pmkResult.pmks, ptks: ptkResult.ptks, mics: micResult.mics,
        stageTimes: [pmkResult.time, ptkResult.time, micResult.time] };
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
        if (mode === 'benchmark') {
            const password0 = '10000000';
            status.textContent = 'Прогрев полной цепочки…';
            await derive([password0], input.ssid, input.keyData, input.message);
            out.textContent = 'Одна цепочка на пароль; время включает подготовку, загрузку, три WebGPU dispatch/readback. Компиляция shader исключена.\n\n';
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
            if (mode === 'self-test' && hex(result.pmks[0]) !== vector.pmk) throw new Error(`Тестовый PMK не совпал: ${hex(result.pmks[0])}`);
            if (mode === 'self-test' && hex(result.ptks[0]) !== vector.ptk) throw new Error(`Тестовый PTK не совпал: ${hex(result.ptks[0])}`);
            const mic = hex(result.mics[0]);
            out.textContent = `PMK (32 байта):\n${hex(result.pmks[0])}\n\nPTK (64 байта):\n${hex(result.ptks[0])}` +
                `\n\nMIC (16 байт):\n${mic}\n\nВремя этапов, ms — PMK ${result.stageTimes[0].toFixed(2)}, PTK ${result.stageTimes[1].toFixed(2)}, MIC ${result.stageTimes[2].toFixed(2)}\n` +
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
$('#benchmark').addEventListener('click', () => void run('benchmark'));
window.addEventListener('pagehide', () => {
    if (!chain) return;
    chain.pmk.dispose(); chain.ptk.dispose(); chain.mic.dispose(); chain = null;
});
})();
