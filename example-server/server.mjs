import http from 'node:http';
import { readFile, writeFile, rename, rm, copyFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { compileMask } from 'rank-lib-js';
import { initialize, expire, count, available, reserve, findAssignment, complete } from './intervals.mjs';

const jobFile = process.env.JOB_FILE ?? new URL('./job.json', import.meta.url);
const resultFile = process.env.RESULT_FILE ?? new URL('./result.json', import.meta.url);
const rankBundle = new URL('../dist/rank-lib.js', import.meta.resolve('rank-lib-js'));
if (!process.env.JOB_FILE) {
  try { await copyFile(new URL('./job.example.json', import.meta.url), jobFile, constants.COPYFILE_EXCL); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
}
let jobQueue = Promise.resolve();
const jobTimeoutMs = Number(process.env.JOB_TIMEOUT_MS ?? 60000);
if (!Number.isSafeInteger(jobTimeoutMs) || jobTimeoutMs <= 0) throw new Error('JOB_TIMEOUT_MS must be a positive integer');
function serialized(callback) {
  const operation = jobQueue.then(callback);
  jobQueue = operation.catch(() => {});
  return operation;
}

async function saveJob(job) {
  const tempFile = jobFile instanceof URL ? new URL('./job.json.tmp', jobFile) : `${jobFile}.tmp`;
  await writeFile(tempFile, JSON.stringify(job, null, 2) + '\n');
  await rename(tempFile, jobFile);
}

async function loadJob() {
  const job = JSON.parse(await readFile(jobFile, 'utf8'));
  const total = compileMask(job.mask).total;
  const now = Date.now();
  const migrated = initialize(job, total, now, jobTimeoutMs);
  const expired = expire(job.scheduler, now);
  job.done = Boolean(job.scheduler.foundPasswords?.length) || count(job.scheduler.completed) === total;
  if (migrated || expired) await saveJob(job);
  return { job, total };
}

function getWork() {
  return serialized(async () => {
    const { job, total } = await loadJob();
    const state = job.scheduler;
    const completed = count(state.completed), inProgress = count(state.reserved.flatMap(r => r.intervals));
    const issued = completed + inProgress;
    const percent = n => total ? Number(n * 10000n / total) / 100 : 100;
    return {
      mask: job.mask, total: total.toString(), completed: completed.toString(), issued: issued.toString(),
      inProgress: inProgress.toString(), remaining: (total - issued).toString(),
      completedPercent: percent(completed), issuedPercent: percent(issued),
      done: job.done, stopReason: state.foundPasswords?.length ? 'password_found' : job.done ? 'exhausted' : null,
      foundPasswords: state.foundPasswords ?? [],
      activeJobs: state.reserved.length, timeoutMs: jobTimeoutMs,
      intervals: { completed: state.completed, reserved: state.reserved.flatMap(r => r.intervals), available: available(state, total) },
      ranges: state.reserved.flatMap(assignment => assignment.intervals.map((interval, i) =>
        ({ ...interval, range: i, jobId: assignment.id, expiresAt: assignment.expiresAt })))
    };
  });
}

function getJob(result, issue = true) {
  return serialized(async () => {
    const { job, total } = await loadJob();
    const state = job.scheduler;
    if (result && !state.foundPasswords?.length) {
      const assignment = findAssignment(state, result);
      if (!assignment) throw Object.assign(new Error('Резерв истёк или задание уже завершено. Получите новое задание.'), { status: 409 });
      await writeFile(resultFile, JSON.stringify(result, null, 2) + '\n');
      complete(state, assignment);
      if (result.passwords?.length) {
        state.foundPasswords = result.passwords.map(match => ({
          ...match, interval: assignment.intervals[match.range], jobId: assignment.id, foundAt: new Date().toISOString()
        }));
        state.reserved = [];
      }
    }
    const assignment = issue ? reserve(state, total, Date.now(), jobTimeoutMs) : null;
    job.done = Boolean(state.foundPasswords?.length) || count(state.completed) === total;
    if (issue || result) await saveJob(job);
    const { scheduler, progress, ranges, ...parameters } = job;
    return { ...parameters, jobId: assignment?.id ?? null,
      intervals: assignment?.intervals ?? [],
      ranges: assignment?.intervals.map(i => ({ start: i.start, batchSize: (BigInt(i.end) - BigInt(i.start)).toString() })) ?? [],
      expiresAt: assignment?.expiresAt ?? null, timeoutMs: jobTimeoutMs,
      done: job.done, waiting: !assignment && !job.done,
      stopReason: state.foundPasswords?.length ? 'password_found' : job.done ? 'exhausted' : null,
      foundPasswords: state.foundPasswords ?? [] };
  });
}

function resetWork() {
  return serialized(async () => {
    const { job } = await loadJob();
    const state = job.scheduler;
    state.completed = [];
    state.reserved = [];
    delete state.foundPasswords;
    job.done = false;
    job.runId = randomUUID();
    let cursor = 0n;
    job.ranges = state.batchSizes.map(size => {
      const range = { start: cursor.toString(), batchSize: size };
      cursor += BigInt(size);
      return range;
    });
    await saveJob(job);
    await rm(resultFile, { force: true });
    return { ok: true, runId: job.runId };
  });
}

// Free abandoned reservations even when no clients are polling.
setInterval(() => serialized(loadJob).catch(error => console.error('Reservation cleanup:', error.message)),
  Math.min(1000, jobTimeoutMs)).unref();

const assets = new Map([
  ['/', ['experiment.html', 'text/html; charset=utf-8']],
  ['/experiment.html', ['experiment.html', 'text/html; charset=utf-8']],
  ['/experiment.js', ['experiment.js', 'text/javascript; charset=utf-8']],
  ['/admin', ['admin.html', 'text/html; charset=utf-8']],
  ['/admin/', ['admin.html', 'text/html; charset=utf-8']],
  ['/rank-lib-js/dist/rank-lib.js', [rankBundle, 'text/javascript; charset=utf-8']],
  ['/wpa2-web-brute/dist/wpa2-web-brute.full.js', ['../dist/wpa2-web-brute.full.js', 'text/javascript; charset=utf-8']],
]);

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const allowed = pathname === '/api/reset' ? ['POST'] : pathname === '/api/job' ? ['GET', 'HEAD', 'POST'] : ['GET', 'HEAD'];
  if (!allowed.includes(req.method)) {
    res.writeHead(405, { Allow: allowed.join(', ') }).end();
    return;
  }
  try {
    let body, contentType;
    if (pathname === '/api/job') {
      let result;
      if (req.method === 'POST') {
        if (req.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
          res.writeHead(415).end('Expected application/json'); return;
        }
        const chunks = [];
        let bytes = 0;
        for await (const chunk of req) {
          bytes += chunk.length;
          if (bytes > 65536) { res.writeHead(413).end('Result too large'); return; }
          chunks.push(chunk);
        }
        try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { res.writeHead(400).end('Invalid JSON'); return; }
        if (result && typeof result === 'object' && !result.intervals) result.intervals = result.ranges;
        if (!result || !Array.isArray(result.intervals) || result.intervals.length < 1 || result.intervals.length > 4 ||
            !result.intervals.every(range => range && typeof range.start === 'string' && typeof range.end === 'string' &&
              /^\d+$/.test(range.start) && /^\d+$/.test(range.end) &&
              BigInt(range.end) > BigInt(range.start) && /^[0-9a-f]{64}$/.test(range.hash)) ||
            (result.passwords !== undefined && (!Array.isArray(result.passwords) ||
              !result.passwords.every(match => match && typeof match.password === 'string' &&
                Number.isInteger(match.range) && match.range >= 0 && match.range < result.intervals.length &&
                typeof match.index === 'string' && /^\d+$/.test(match.index) &&
                BigInt(match.index) >= BigInt(result.intervals[match.range].start) &&
                BigInt(match.index) < BigInt(result.intervals[match.range].end))))) {
          res.writeHead(400).end('Expected range hashes and optional passwords'); return;
        }
      }
      body = JSON.stringify(await getJob(result, req.method !== 'HEAD'));
      contentType = 'application/json; charset=utf-8';
    } else if (pathname === '/api/reset') {
      body = JSON.stringify(await resetWork());
      contentType = 'application/json; charset=utf-8';
    } else if (pathname === '/api/work') {
      body = JSON.stringify(await getWork());
      contentType = 'application/json; charset=utf-8';
    } else {
      const asset = assets.get(pathname);
      if (!asset) { res.writeHead(404).end('Not found'); return; }
      body = await readFile(new URL(asset[0], import.meta.url));
      contentType = asset[1];
    }
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (error) {
    console.error(error);
    res.writeHead(error.status ?? 500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(req.method === 'HEAD' ? undefined : JSON.stringify({ error: error.status ? error.message : 'Ошибка загрузки данных сервера.' }));
  }
});

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '127.0.0.1';
server.listen(port, host, () => console.log(`http://${host}:${server.address().port}`));
