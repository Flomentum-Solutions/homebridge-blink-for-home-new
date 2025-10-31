const puppeteer = require('puppeteer');

async function captureBlinkLogin(authUrl) {
  const browser = await puppeteer.launch({
    headless: false,
    args: [
      '--disable-site-isolation-trials',   // may help capturing full headers
    ]
  });
  const page = await browser.newPage();

  // Listen for requests
  page.on('request', request => {
    console.log('► REQUEST:', request.method(), request.url());
    console.log('     headers:', request.headers());
    if (request.postData()) {
      console.log('     postData:', request.postData());
    }
    request.continue();   // continue without modification
  });

  // Listen for responses
  page.on('response', async response => {
    console.log('◄ RESPONSE:', response.status(), response.url());
    console.log('     headers:', response.headers());
    const ct = response.headers()['content-type'] || '';
    if (ct.includes('application/json')) {
      console.log('     body:', await response.json());
    } else if (ct.includes('text/') || ct.includes('application/html')) {
      console.log('     body snippet:', (await response.text()).slice(0, 200));
    }
  });

  // Enable request interception (to capture everything)
  await page.setRequestInterception(true);

  console.log('Opening login page:', authUrl);
  await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: 0 });

  // Let the user interact so you can see why email field is disabled
  console.log('⚠️ Please inspect the login page in the browser, then close browser to finish.');
  await browser.waitForTarget(() => false).catch(() => {});   // waits until user closes browser

  await browser.close();
}

const authUrl = process.argv[2];
if (!authUrl) {
  console.error('Usage: node capture-blink-oauth.js "<authUrl>"');
  process.exit(1);
}

captureBlinkLogin(authUrl).catch(err => {
  console.error('ERROR during capture:', err);
  process.exit(1);
});

// Run with: node capture-blink-oauth.js "THE_AUTH_URL_HERE"
// Example auth URL: https://api.oauth.blink.com/oauth/v2/signin?response_type=code&client_id=ios&redirect_uri=http%3A%2F%2F192.0.1.1%3A52888%2Fblink%2Foauth%2Fcallback&scope=client&state=b41a93a656ec78cf519e2f82ceef9848&code_challenge=QdGlfy1JHreCQsuflVmLRhZdxrZBrry5jXMGH3NKjno&code_challenge_method=S256&app-brand=blink&app-version=49.2&device-brand=Apple&device-model=iPhone18%2C1&device-os-version=26.1&dark-mode=default&entry_source=default&language=en