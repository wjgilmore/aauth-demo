// Sliding-window rate limiter on top of a key/value store with conditional writes
// (Netlify Blobs: getWithMetadata + setJSON with onlyIfMatch / onlyIfNew).
//
// Each bucket stores the timestamps (seconds) of recent events. A bucket can have
// several limits, e.g. 3 per minute and 15 per hour.

const MAX_ATTEMPTS = 6;

/** Seconds until the bucket would accept another event, or 0 if it would now. */
export function retryAfter(times, limits, t) {
  let wait = 0;
  for (const { max, window } of limits) {
    const recent = times.filter((x) => x > t - window).sort((a, b) => a - b);
    if (recent.length >= max) wait = Math.max(wait, recent[recent.length - max] + window - t);
  }
  return Math.max(0, Math.ceil(wait));
}

const longest = (limits) => Math.max(...limits.map((l) => l.window));

async function read(store, key) {
  const entry = await store.getWithMetadata(key, { type: 'json' });
  return { times: Array.isArray(entry?.data) ? entry.data : [], etag: entry?.etag, exists: Boolean(entry) };
}

/**
 * Check buckets without recording anything.
 * Returns { ok: true } or { ok: false, bucket, retryAfter }.
 */
export async function peek(store, buckets, t = Date.now() / 1000) {
  for (const b of buckets) {
    const { times } = await read(store, b.key);
    const wait = retryAfter(times, b.limits, t);
    if (wait > 0) return { ok: false, bucket: b, retryAfter: wait };
  }
  return { ok: true };
}

/**
 * Record one event in each bucket, unless any bucket is full. Uses conditional
 * writes so concurrent requests can't both take the last slot.
 * Returns { ok: true } or { ok: false, bucket, retryAfter }.
 */
export async function take(store, buckets, t = Date.now() / 1000) {
  const check = await peek(store, buckets, t);
  if (!check.ok) return check;

  for (const b of buckets) {
    for (let attempt = 0; ; attempt++) {
      const { times, etag, exists } = await read(store, b.key);
      const wait = retryAfter(times, b.limits, t);
      if (wait > 0) return { ok: false, bucket: b, retryAfter: wait };
      const next = [...times.filter((x) => x > t - longest(b.limits)), t];
      // Conditional write when the store gives us an etag. The local `netlify dev`
      // sandbox returns none for existing keys, so fall back to a plain write there.
      const opts = etag ? { onlyIfMatch: etag } : exists ? {} : { onlyIfNew: true };
      const { modified } = await store.setJSON(b.key, next, opts);
      if (modified) break;
      if (attempt >= MAX_ATTEMPTS) return { ok: false, bucket: b, retryAfter: 1 }; // heavy contention
    }
  }
  return { ok: true };
}
