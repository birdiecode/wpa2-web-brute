import test from 'node:test';
import assert from 'node:assert/strict';
import { merge, count, gaps, initialize, reserve, expire, complete, findAssignment, available } from './intervals.mjs';

const interval = (start, end) => ({ start: String(start), end: String(end) });
const state = () => ({ completed: [], reserved: [], batchSizes: ['2', '2', '2', '2'] });

test('merge intervals and preserve exact indices beyond Number precision', () => {
  const start = 9007199254740993n;
  const merged = merge([interval(start + 2n, start + 5n), interval(start, start + 3n)]);
  assert.deepEqual(merged, [interval(start, start + 5n)]);
  assert.equal(count(merged), 5n);
  assert.deepEqual(gaps([interval(2, 4), interval(6, 10)], 12n), [interval(0, 2), interval(4, 6), interval(10, 12)]);
});

test('expired reservations are returned to the free intervals without losing completed work', () => {
  const s = state();
  const slow = reserve(s, 20n, 0, 100);
  const fast = reserve(s, 20n, 10, 100);
  assert.equal(slow.intervals[0].start, '0');
  assert.equal(fast.intervals[0].start, '8');
  complete(s, fast);
  assert.deepEqual(s.completed, [interval(8, 16)]);
  assert.equal(expire(s, 100), true);
  assert.equal(findAssignment(s, { jobId: slow.id, intervals: slow.intervals }), undefined);
  assert.deepEqual(available(s, 20n), [interval(0, 8), interval(16, 20)]);
  const retry = reserve(s, 20n, 100, 100);
  assert.notEqual(retry.id, slow.id);
  assert.deepEqual(retry.intervals, slow.intervals);
  complete(s, retry);
  const tail = reserve(s, 20n, 101, 100);
  complete(s, tail);
  assert.deepEqual(s.completed, [interval(0, 20)]);
  assert.equal(count(s.completed), 20n);
});

test('migration reconstructs holes from existing pending assignments', () => {
  const job = { mask:'x', ranges:[{ start:'16', batchSize:'2' }], progress:{ issued:'16' },
    scheduler:{ mask:'x', completed:'8', pending:[{ id:'slow', ranges:[{ start:'0', batchSize:'8' }] }] } };
  initialize(job, 20n, 100, 60);
  assert.deepEqual(job.scheduler.completed, [interval(8, 16)]);
  assert.equal(job.scheduler.reserved[0].expiresAt, 160);
  assert.equal(initialize(job, 20n, 120, 60), false);
  assert.equal(job.scheduler.reserved[0].expiresAt, 160);
});
