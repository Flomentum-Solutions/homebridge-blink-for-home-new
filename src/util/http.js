const Bottleneck = require('bottleneck');
const fetch = require('node-fetch'); // repo already depends on this; if not, swap for axios

// Blink gets cranky if you burst. 1 req/sec is conservative; bump to 2 if needed.
const limiter = new Bottleneck({ minTime: 1000, maxConcurrent: 1 });

async function limitedFetch(url, opts = {}) {
    return limiter.schedule(async () => {
        const res = await fetch(url, opts);
        if (res.status === 429) {
            // Honor Retry-After when present; otherwise back off 1s.
            const ra = res.headers.get('retry-after');
            const waitMs = ra ? parseInt(ra, 10) * 1000 : 1000;
            await new Promise(r => setTimeout(r, waitMs));
            return limitedFetch(url, opts);
        }
        return res;
    });
}

module.exports = { limitedFetch, limiter };