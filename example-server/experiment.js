(() => {
'use strict';
const scriptBase = new URL('.', document.currentScript.src);
const style = document.createElement('style');
style.textContent = `
  body { max-width:960px; margin:36px auto; padding:0 20px; font:16px/1.5 system-ui; color:#18232e; }
  form,.fields { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; align-items:end; }
  label { display:grid; gap:5px; min-width:0; }
  input,select,button { box-sizing:border-box; width:100%; padding:10px; font:inherit; border:1px solid #aab5bf; border-radius:5px; }
  button { cursor:pointer; background:#175cd3; color:white; border-color:#175cd3; }
  button:disabled { opacity:.6; cursor:wait; }
  pre { padding:16px; background:#f1f4f7; border-radius:6px; white-space:pre-wrap; overflow-wrap:anywhere; max-height:450px; overflow:auto; }
  section { margin-top:36px; }
  .note { color:#52616f; font-size:14px; }
  .wide { grid-column:1/-1; }
`;
document.head.append(style);
const panel = document.createElement('div');
panel.innerHTML = `<section>
  <h2>Задание с сервера</h2>
  <div class="fields">
    <button id="mic-button" class="wide" type="button">Запустить</button>
    <button id="stop-button" class="wide" type="button" disabled>Остановить после текущего задания</button>
  </div>
  <h2>Найденные пароли</h2>
  <pre id="found-passwords" role="status">Проверка ещё не запускалась.</pre>
  <p id="job-status" class="note" role="status"></p>
  <h2>Результаты диапазонов</h2>
  <pre id="mic-result" role="status">Параметры задания загружаются с /api/job при запуске расчёта.</pre>
</section>`;
document.body.append(panel);
function loadLibrary(path) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = new URL(path, scriptBase).href;
    script.onload = resolve;
    script.onerror = () => reject(new Error(`Не удалось загрузить библиотеку: ${path}`));
    document.head.append(script);
  });
}

const $ = id => document.getElementById(id);
async function calculate(data, rankLibrary, cryptoLibrary) {
  const compiled = rankLibrary.compileMask(data.mask);
  if (!Array.isArray(data.intervals) || data.intervals.length < 1 || data.intervals.length > 4)
    throw new Error('Задание должно содержать от 1 до 4 диапазонов в intervals.');
  const ranges = data.intervals.map((range, i) => {
    if (!range || typeof range.start !== 'string' || typeof range.end !== 'string' ||
        !/^\d+$/.test(range.start) || !/^\d+$/.test(range.end))
      throw new Error(`Диапазон ${i}: start и end должны быть строками с целыми неотрицательными числами.`);
    const start = BigInt(range.start), end = BigInt(range.end), size = end - start;
    if (size < 1n || size > 32768n) throw new Error(`Диапазон ${i}: интервал должен содержать от 1 до 32768 кандидатов.`);
    if (start >= compiled.total) throw new Error(`Диапазон ${i}: начальный индекс выходит за пределы маски.`);
    if (end > compiled.total) throw new Error(`Диапазон ${i}: конец интервала выходит за пределы маски.`);
    return { start, end };
  });

  if (!data.ssid || new TextEncoder().encode(data.ssid).length > 32)
    throw new Error('SSID должен содержать от 1 до 32 байт UTF-8.');
  function hexBytes(value, requiredBytes, field) {
    const normalized = value.replace(/[\s:.-]/g,'');
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(normalized)) throw new Error(`${field}: некорректный hex.`);
    const bytes = Uint8Array.from(normalized.match(/../g) || [], x => parseInt(x, 16));
    if (requiredBytes !== null && bytes.length !== requiredBytes) throw new Error(`${field}: требуется ${requiredBytes} байт.`);
    return bytes;
  }
  const keyData=hexBytes(data.keyData,76,'keyData');
  const eapol=hexBytes(data.eapol,null,'EAPOL');
  if (eapol.length === 0) throw new Error('Укажите EAPOL frame в hex.');

  const reference = data.expectedMic.trim().toLowerCase();
  if (reference && !/^[0-9a-f]{32}$/.test(reference)) throw new Error('Ожидаемый MIC: требуется 16 байт hex.');

  const Backend = {
    webcrypto: cryptoLibrary.WPA2WebCrypto,
    webgl: cryptoLibrary.WPA2WebGL,
    webgpu: cryptoLibrary.WPA2WebGPU
  }[data.backend];
  if (!Backend) throw new Error('Неизвестный бэкенд.');
  let backend;
  try { backend = await Backend.create(); }
  catch (error) { throw Object.assign(new Error(error.message), { code: 'BACKEND_UNAVAILABLE' }); }
  try {
    const batches = [];
    let micMs = 0;
    for (const { start, end } of ranges) {
      const lines = [];
      for (let index = start; index < end; index++) lines.push(compiled.at(index));
      const micStarted = performance.now();
      const { mics } = await backend.derive(lines, data.ssid, keyData, eapol);
      const batchMs = performance.now() - micStarted;
      micMs += batchMs;
      const prefixes = new Uint8Array(mics.length * 6);
      mics.forEach((mic, offset) => prefixes.set(mic.subarray(0, 6), offset * 6));
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', prefixes));
      const hash = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
      const results = mics.map((mic, offset) => {
        const hex = Array.from(mic, byte => byte.toString(16).padStart(2, '0')).join('');
        return {
          index: (start + BigInt(offset)).toString(),
          password: lines[offset],
          mic: hex,
          matches: reference ? hex === reference : null
        };
      });
      batches.push({ start: start.toString(), end: end.toString(), results, micMs: batchMs, hash });
    }
    return { batches, micMs, backend: data.backend };
  } finally {
    backend.dispose();
  }
}
function runBackend(data) {
  // WebGL2 backend creates its canvas through document, which is unavailable in workers.
  if (data.backend === 'webgl' || typeof Worker === 'undefined') return calculate(data,window.RankLib,window.WPA2WebBrute);
  const rankUrl=new URL('./rank-lib-js/dist/rank-lib.js',scriptBase).href;
  const cryptoUrl=new URL('./wpa2-web-brute/dist/wpa2-web-brute.full.js',scriptBase).href;
  const source=`importScripts(${JSON.stringify(rankUrl)},${JSON.stringify(cryptoUrl)});
    const calculate=${calculate.toString()};
    onmessage=async({data})=>{try{postMessage({result:await calculate(data,self.RankLib,self.WPA2WebBrute)});}catch(error){postMessage({error:error.message,code:error.code});}};`;
  const url=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  return new Promise((resolve,reject)=>{
    let worker;
    const cleanup=()=>{worker?.terminate();URL.revokeObjectURL(url);};
    try { worker=new Worker(url);
      worker.onmessage=({data})=>{cleanup();data.error?reject(Object.assign(new Error(data.error), { code: data.code })):resolve(data.result);};
      worker.onerror=event=>{cleanup();reject(new Error(event.message||'Ошибка Worker. Откройте страницу через localhost.'));};
      worker.postMessage(data);
    } catch(error) {cleanup();reject(error);}
  });
}
async function run(data) {
  if (data.backend !== 'auto') return runBackend(data);
  const errors = [];
  for (const backend of ['webgpu', 'webgl', 'webcrypto']) {
    try { return await runBackend({ ...data, backend }); }
    catch (error) {
      if (error.code !== 'BACKEND_UNAVAILABLE') throw error;
      errors.push(`${backend}: ${error.message}`);
    }
  }
  throw new Error('Нет доступного бэкенда. ' + errors.join('; '));
}
let nextJob = null;
let currentRunId = null;
let running = false;
let stopRequested = false;
const foundPasswords = new Set();
function validateJob(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) throw new Error('Сервер вернул некорректное задание.');
  for (const field of ['mask', 'ssid', 'keyData', 'eapol']) {
    if (typeof job[field] !== 'string') throw new Error(`В задании отсутствует строковое поле ${field}.`);
  }
  if (!Array.isArray(job.intervals) || job.intervals.length > 4 || (!job.done && !job.waiting && job.intervals.length < 1))
    throw new Error('Задание должно содержать от 1 до 4 диапазонов.');
  return job;
}
async function processJob() {
  $('mic-result').textContent='Расчёт…';
  if (!foundPasswords.size) $('found-passwords').textContent='Проверка…';
  $('job-status').textContent='';
  try {
    let job = nextJob;
    if (!job) {
      const response = await fetch('/api/job', { cache: 'no-store' });
      if (!response.ok) throw new Error(`Не удалось получить задание: HTTP ${response.status}`);
      job = validateJob(await response.json());
    }
    if (job.runId !== currentRunId) {
      foundPasswords.clear();
      currentRunId = job.runId;
    }
    if (job.done) {
      for (const match of job.foundPasswords ?? [])
        foundPasswords.add(`Пароль ${JSON.stringify(match.password)} | Индекс ${match.index} | Диапазон ${match.range}`);
      $('mic-result').textContent=job.stopReason === 'password_found' ? 'Пароль найден. Обработка остановлена.' : 'Все диапазоны маски обработаны.';
      $('found-passwords').textContent=foundPasswords.size ? [...foundPasswords].join('\n') : 'Новых кандидатов для проверки нет.';
      $('job-status').textContent=job.stopReason === 'password_found' ? 'Выдача интервалов прекращена.' : 'Заданий больше нет.';
      return false;
    }
    if (job.waiting) {
      nextJob = null;
      $('job-status').textContent='Все диапазоны выданы. Ожидание результатов других вкладок…';
      await new Promise(resolve => setTimeout(resolve, 2000));
      return true;
    }
    if (job.expiresAt && job.expiresAt <= Date.now()) {
      nextJob = null;
      $('job-status').textContent='Резерв истёк. Получение нового задания…';
      return true;
    }
    const result = await run({ ...job, expectedMic: job.expectedMic ?? '', backend: 'auto' });
    const count = result.batches.reduce((sum, batch) => sum + batch.results.length, 0);
    const found = result.batches.flatMap((batch, i) => batch.results
      .filter(row => row.matches === true)
      .map(row => `Пароль ${JSON.stringify(row.password)} | Индекс ${row.index} | Диапазон ${i}`));
    found.forEach(match => foundPasswords.add(match));
    $('found-passwords').textContent = foundPasswords.size ? [...foundPasswords].join('\n')
      : job.expectedMic?.trim() ? 'Совпадений в проверенных диапазонах нет.' : 'Ожидаемый MIC не задан — поиск совпадений не выполнялся.';
    $('mic-result').textContent=`Бэкенд: ${{webgpu: 'WebGPU', webgl: 'WebGL2', webcrypto: 'WebCrypto'}[result.backend]}\nРасчёт ${count} MIC, диапазонов: ${result.batches.length} | ${result.micMs.toFixed(3)} мс (PMK → PTK → MIC)\n\n` + result.batches.map((batch, i) => {
      const heading = `Диапазон ${i}: [${batch.start}, ${batch.end}) | ${batch.results.length} MIC | ${batch.micMs.toFixed(3)} мс`;
      return heading + `\nSHA-256 (первые 6 байт каждого MIC): ${batch.hash}\n` + batch.results.map(row => {
        const status = row.matches === null ? '' : row.matches ? ' | СОВПАДЕНИЕ' : ' | Не совпадает';
        return `Индекс ${row.index} | Пароль ${JSON.stringify(row.password)} | MIC ${row.mic}${status}`;
      }).join('\n');
    }).join('\n\n');
    const passwords = result.batches.flatMap((batch, i) => batch.results
      .filter(row => row.matches === true)
      .map(row => ({ password: row.password, range: i, index: row.index })));
    const payload = {
      ...(job.jobId ? { jobId: job.jobId } : {}),
      intervals: result.batches.map(batch => ({ start: batch.start, end: batch.end, hash: batch.hash })),
      ...(passwords.length ? { passwords } : {})
    };
    $('job-status').textContent='Отправка результата…';
    try {
      const response = await fetch('/api/job', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload), cache: 'no-store'
      });
      if (response.status === 409) {
        nextJob = null;
        $('job-status').textContent='Задание уже принято или изменилось. Получение нового задания…';
        return true;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      nextJob = validateJob(await response.json());
      for (const match of nextJob.foundPasswords ?? [])
        foundPasswords.add(`Пароль ${JSON.stringify(match.password)} | Индекс ${match.index} | Диапазон ${match.range}`);
      if (foundPasswords.size) $('found-passwords').textContent=[...foundPasswords].join('\n');
      $('job-status').textContent=nextJob.stopReason === 'password_found' ? 'Пароль найден. Выдача интервалов остановлена.' : nextJob.done ? 'Результат отправлен. Все диапазоны маски обработаны.'
        : 'Результат отправлен. Следующее задание получено.';
      return !nextJob.done;
    } catch (error) {
      $('job-status').textContent='Ошибка отправки результата или получения следующего задания: ' + error.message;
      return false;
    }
  } catch (error) {
    $('mic-result').textContent='Ошибка: '+error.message;
    if (!foundPasswords.size) $('found-passwords').textContent='Проверка не завершена.';
    return false;
  }
}
async function startProcessing() {
  if (running) return;
  if (nextJob?.done) nextJob = null;
  running = true;
  stopRequested = false;
  $('mic-button').disabled = true;
  $('stop-button').disabled = false;
  try {
    while (!stopRequested) {
      const hasNext = await processJob();
      if (!hasNext) break;
      // Allow rendering and the stop button to run between jobs.
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    if (stopRequested && !$('job-status').textContent.startsWith('Ошибка') && !$('mic-result').textContent.startsWith('Ошибка'))
      $('job-status').textContent='Остановлено после текущего задания. Можно продолжить.';
  } finally {
    running = false;
    $('mic-button').disabled = false;
    $('mic-button').textContent = 'Продолжить';
    $('stop-button').disabled = true;
  }
}
$('mic-button').onclick = startProcessing;
$('stop-button').onclick = () => {
  stopRequested = true;
  $('stop-button').disabled = true;
  $('job-status').textContent = 'Остановка после завершения текущего задания…';
};
$('mic-button').disabled = true;
$('stop-button').disabled = true;
Promise.all([
  loadLibrary('./rank-lib-js/dist/rank-lib.js'),
  loadLibrary('./wpa2-web-brute/dist/wpa2-web-brute.full.js')
]).then(() => startProcessing()).catch(error => {
  $('mic-result').textContent = 'Ошибка: ' + error.message;
  $('job-status').textContent = 'Не удалось запустить обработку.';
});

})();
