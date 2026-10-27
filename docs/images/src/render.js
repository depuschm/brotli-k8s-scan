// Render the HTML sources to PNG with Playwright's Chromium.
// Usage: node render.js <cache-dir>   (reads <name>.html, writes png/<name>.png)
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');

const dir = path.resolve(process.argv[2]);
// [name, device scale]: README images at 2x for sharp text; the social preview
// must be exactly 1280x640 pixels, so 1x.
const jobs = [['banner', 2], ['fingerprint', 2], ['scan-cluster', 2], ['same-version', 2], ['social-preview', 1]];

(async () => {
  fs.mkdirSync(path.join(dir, 'png'), { recursive: true });
  const browser = await chromium.launch();
  for (const [name, scale] of jobs) {
    const page = await browser.newPage({ deviceScaleFactor: scale, viewport: { width: 1400, height: 800 } });
    // the pages only use local files; block anything else
    await page.route(/^(?!file:)/, (route) => route.abort());
    await page.goto('file://' + path.join(dir, name + '.html'));
    await page.evaluate(() => document.fonts.ready);
    const el = await page.$('body > div');
    await el.screenshot({ path: path.join(dir, 'png', name + '.png') });
    const box = await el.boundingBox();
    console.log(`${name}: ${Math.round(box.width)}x${Math.round(box.height)} @${scale}x`);
    await page.close();
  }
  await browser.close();
})();
