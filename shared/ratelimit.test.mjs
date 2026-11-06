import { test } from 'node:test';
import assert from 'node:assert/strict';
import { peek, retryAfter, take } from './ratelimit.mjs';

/** In-memory stand-in for Netlify Blobs with etag-based conditional writes. */
function memoryStore() {
  const data = new Map();
  let version = 0;
  return {
    data,
    async getWithMetadata(key) {
      const e = data.get(key);
      return e ? { data: structuredClone(e.value), etag: e.etag } : null;
    },
    async setJSON(key, value, opts = {}) {
      const e = data.get(key);
      if (opts.onlyIfNew && e) return { modified: false };
      if (opts.onlyIfMatch && e?.etag !== opts.onlyIfMatch) return { modified: false };
      data.set(key, { value: structuredClone(value), etag: `"${++version}"` });
      return { modified: true };
    },
  };
}

const perMinute = (key, max) => ({ key, limits: [{ max, window: 60 }] });

test('allows up to the limit, then reports how long to wait', async () => {
  const store = memoryStore();
  const b = [perMinute('p', 3)];
  assert.equal((await take(store, b, 1000)).ok, true);
  assert.equal((await take(store, b, 1010)).ok, true);
  assert.equal((await take(store, b, 1020)).ok, true);
  const denied = await take(store, b, 1030);
  assert.equal(denied.ok, false);
  assert.equal(denied.retryAfter, 30); // oldest (1000) leaves the window at 1060
  assert.equal((await take(store, b, 1061)).ok, true); // sliding window
});

test('multiple limits on one bucket', () => {
  const limits = [{ max: 3, window: 60 }, { max: 5, window: 3600 }];
  assert.equal(retryAfter([0, 100, 200, 300, 400], limits, 500), 3600 - 500);
  assert.equal(retryAfter([0, 100, 200, 300], limits, 500), 0);
});

test('a full bucket blocks without recording in the others', async () => {
  const store = memoryStore();
  await take(store, [perMinute('global', 1)], 0);
  const r = await take(store, [perMinute('person', 5), perMinute('global', 1)], 1);
  assert.equal(r.ok, false);
  assert.equal(r.bucket.key, 'global');
  assert.equal(store.data.has('person'), false);
});

test('peek never records', async () => {
  const store = memoryStore();
  assert.equal((await peek(store, [perMinute('p', 1)], 0)).ok, true);
  assert.equal(store.data.size, 0);
});

test('concurrent takes cannot exceed the limit', async () => {
  const store = memoryStore();
  const results = await Promise.all(Array.from({ length: 20 }, () => take(store, [perMinute('p', 5)], 100)));
  assert.equal(results.filter((r) => r.ok).length, 5);
  assert.equal(store.data.get('p').value.length, 5);
});

test('old timestamps are pruned', async () => {
  const store = memoryStore();
  for (let t = 0; t < 10; t++) await take(store, [perMinute('p', 100)], t * 30);
  assert.ok(store.data.get('p').value.length <= 3);
});

test('works with stores that return no etag (netlify dev sandbox)', async () => {
  const store = memoryStore();
  const real = store.getWithMetadata;
  store.getWithMetadata = async (key) => {
    const e = await real(key);
    return e ? { data: e.data } : null; // no etag, like the local sandbox
  };
  const b = [perMinute('p', 2)];
  assert.equal((await take(store, b, 0)).ok, true);
  assert.equal((await take(store, b, 1)).ok, true);
  assert.equal((await take(store, b, 2)).ok, false);
});
