import { randomUUID } from 'node:crypto';

// Intervals are half-open; string indices preserve precision in JSON.
export function merge(intervals) {
  const sorted = intervals.map(({ start, end }) => ({ start: BigInt(start), end: BigInt(end) }))
    .filter(i => i.end > i.start).sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
  const result = [];
  for (const interval of sorted) {
    const last = result.at(-1);
    if (last && interval.start <= last.end) { if (interval.end > last.end) last.end = interval.end; }
    else result.push({ ...interval });
  }
  return result.map(i => ({ start: i.start.toString(), end: i.end.toString() }));
}

export const count = intervals => merge(intervals).reduce((n, i) => n + BigInt(i.end) - BigInt(i.start), 0n);

export function gaps(intervals, total) {
  const result = [];
  let cursor = 0n;
  for (const interval of merge(intervals)) {
    const start = BigInt(interval.start), end = BigInt(interval.end);
    if (start > cursor) result.push({ start: cursor.toString(), end: start.toString() });
    if (end > cursor) cursor = end;
  }
  if (cursor < total) result.push({ start: cursor.toString(), end: total.toString() });
  return result;
}

export function fromRanges(ranges, total) {
  return ranges.map(range => {
    const start = BigInt(range.start), end = start + BigInt(range.batchSize);
    return { start: start.toString(), end: (end < total ? end : total).toString() };
  });
}

export function initialize(job, total, now, timeout) {
  if (job.scheduler?.version === 2 && job.scheduler.mask === job.mask) return false;
  const old = job.scheduler?.mask === job.mask ? job.scheduler : null;
  const sizes = (job.ranges.length ? job.ranges : old?.pending?.[0]?.ranges ?? [])
    .map(r => r.batchSize);
  const batchSizes = sizes.length ? sizes : ['250', '250', '250', '250'];
  const reserved = (old?.pending ?? []).map(assignment => ({
    id: assignment.id, intervals: fromRanges(assignment.ranges, total), expiresAt: now + timeout
  }));
  const issued = old ? BigInt(job.progress.issued) : job.done ? total
    : job.ranges.reduce((min, r) => BigInt(r.start) < min ? BigInt(r.start) : min, total);
  const holes = gaps(reserved.flatMap(r => r.intervals), total);
  const completed = holes.map(i => ({ start: i.start, end: (BigInt(i.end) < issued ? BigInt(i.end) : issued).toString() }))
    .filter(i => BigInt(i.end) > BigInt(i.start));
  job.scheduler = { version: 2, mask: job.mask, batchSizes, completed: merge(completed), reserved };
  delete job.progress;
  return true;
}

export function expire(state, now) {
  const length = state.reserved.length;
  state.reserved = state.reserved.filter(r => r.expiresAt > now);
  return state.reserved.length !== length;
}

export const available = (state, total) => gaps([...state.completed, ...state.reserved.flatMap(r => r.intervals)], total);

export function reserve(state, total, now, timeout) {
  if (state.foundPasswords?.length) return null;
  const free = available(state, total), intervals = [];
  for (const size of state.batchSizes) {
    const first = free[0];
    if (!first) break;
    const start = BigInt(first.start), limit = BigInt(first.end);
    const end = start + BigInt(size) < limit ? start + BigInt(size) : limit;
    intervals.push({ start: start.toString(), end: end.toString() });
    if (end === limit) free.shift(); else first.start = end.toString();
  }
  if (!intervals.length) return null;
  const assignment = { id: randomUUID(), intervals, expiresAt: now + timeout };
  state.reserved.push(assignment);
  return assignment;
}

export function findAssignment(state, result) {
  const intervals = result.intervals ?? result.ranges;
  return state.reserved.find(assignment => (!result.jobId || assignment.id === result.jobId) &&
    assignment.intervals.length === intervals.length && assignment.intervals.every((i, n) =>
      i.start === intervals[n].start && i.end === intervals[n].end));
}

export function complete(state, assignment) {
  state.completed = merge([...state.completed, ...assignment.intervals]);
  state.reserved = state.reserved.filter(r => r.id !== assignment.id);
}
