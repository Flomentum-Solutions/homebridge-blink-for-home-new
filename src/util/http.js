const Bottleneck = require('bottleneck');

// 1 req/sec is conservative; bump to 2 if needed.
const limiter = new Bottleneck({ minTime: 1000, maxConcurrent: 1 });

async function limitedFetch(url, opts = {}) {
  return limiter.schedule(async () => {
    const res = await fetch(url, opts); // global fetch on Node 20+
    if (res.status === 429) {
      const ra = res.headers.get('retry-after');
      const waitMs = ra ? Number(ra) * 1000 : 1000;
      await new Promise(r => setTimeout(r, waitMs));
      return limitedFetch(url, opts);
    }
    return res;
  });
}

module.exports = { limitedFetch, limiter };