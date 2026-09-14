const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { before, after, test } = require('node:test');
const { chromium, webkit } = require('playwright');

const site = resolve(__dirname, '..');
const temporary = mkdtempSync(join(tmpdir(), 'sdme-site-test-'));
const output = join(temporary, 'public');
const browsers = [];
let server;
let origin;

before(async () => {
  const { prepareSite } = await import('../scripts/content.mjs');
  prepareSite(site, temporary);
  writeFileSync(join(temporary, 'content/docs/outline-disabled.md'), '+++\ntitle = "No outline"\nweight = 100\ntemplate = "doc.html"\n[extra]\nshow_outline = false\n+++\n\n## A heading\n\nContent.\n');
  writeFileSync(join(temporary, 'content/docs/outline-nesting.md'), '+++\ntitle = "Nested headings"\nweight = 101\ntemplate = "doc.html"\n+++\n\n# One\n\n### Three\n\n###### Six\n\n## Two\n\n## Two\n\n## Code `example` & text\n');
  server = createServer((request, response) => {
    let path = new URL(request.url, 'http://localhost').pathname;
    if (path.endsWith('/')) path += 'index.html';
    const types = { css: 'text/css', js: 'text/javascript', html: 'text/html', svg: 'image/svg+xml' };
    try {
      response.setHeader('Content-Type', types[path.split('.').pop()] || 'application/octet-stream');
      response.end(readFileSync(join(output, path)));
    } catch {
      response.writeHead(404);
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  execFileSync(process.env.ZOLA_BIN || 'zola', ['--root', temporary, 'build', '--base-url', origin]);
  for (const engine of [chromium, webkit]) browsers.push({ name: engine.name(), browser: await engine.launch() });
});

after(async () => {
  await Promise.all(browsers.map(({ browser }) => browser.close()));
  if (server) await new Promise(resolve => server.close(resolve));
  rmSync(temporary, { recursive: true, force: true });
});

async function withPage(browser, options, run) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light', ...options });
  const errors = [];
  await context.route('https://api.github.com/**', route => route.abort());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  page.on('pageerror', error => errors.push(error.message));
  try {
    await run(page, context);
    assert.deepEqual(errors, [], 'No browser script errors when the release API fails');
  } finally {
    await context.close();
  }
}

async function assertNoOverflow(page) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Page stays within the viewport');
}

for (const engine of ['chromium', 'webkit']) {
  test(`${engine}: outline follows headings, anchors, scrolling, and desktop preference`, async () => {
    const { browser } = browsers.find(item => item.name === engine);
    await withPage(browser, {}, async page => {
      await page.goto(`${origin}/docs/architecture/`);
      assert.equal(await page.locator('.outline').evaluate(element => element.open), true);
      const headings = await page.locator('.document-content :is(h1,h2,h3,h4,h5,h6)[id]').evaluateAll(elements => elements.map(element => element.id));
      const targets = await page.locator('.outline-links a').evaluateAll(elements => elements.map(element => decodeURIComponent(element.hash.slice(1))));
      assert.deepEqual(targets, headings);
      const link = page.getByRole('navigation', { name: 'Headings on this page' }).getByRole('link', { name: '9. Networking', exact: true });
      await link.click();
      await page.waitForFunction(() => document.querySelector('.outline-links [aria-current]')?.textContent === '9. Networking');
      assert.equal(new URL(page.url()).hash, '#9-networking');
      assert.equal(await page.locator('[id="9-networking"]').evaluate(element => element.getBoundingClientRect().top >= document.querySelector('.site-header').getBoundingClientRect().bottom), true);
      await page.evaluate(() => { document.activeElement.blur(); window.scrollTo(0, document.documentElement.scrollHeight); });
      await page.waitForFunction(() => document.querySelector('.outline-links [aria-current]')?.hash === [...document.querySelectorAll('.outline-links a')].at(-1).hash);
      assert.equal(await page.locator('.outline-links [aria-current]').getAttribute('href'), `#${headings.at(-1)}`);
      await page.locator('.outline summary').click();
      await page.reload();
      assert.equal(await page.locator('.outline').evaluate(element => element.open), false);
      await page.locator('.outline summary').focus();
      await page.keyboard.press('Enter');
      assert.equal(await page.locator('.outline').evaluate(element => element.open), true);
      await assertNoOverflow(page);
    });
  });

  test(`${engine}: mobile outline keeps the article full width and closes after navigation`, async () => {
    const { browser } = browsers.find(item => item.name === engine);
    await withPage(browser, { viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true }, async page => {
      for (const width of [320, 390, 768, 900, 901, 1024]) {
        await page.setViewportSize({ width, height: 844 });
        for (const path of ['/docs/architecture/', '/docs/security/', '/tutorial/first-container/', '/']) {
          await page.goto(origin + path);
          await assertNoOverflow(page);
          if (path !== '/') {
            assert.equal(await page.locator('.outline').evaluate(element => element.open), width > 900);
            if (width <= 900) {
              const articleWidth = await page.locator('.document').evaluate(element => element.getBoundingClientRect().width);
              assert.ok(articleWidth >= Math.min(width - 48, 760), 'Outline does not consume article width');
            }
          }
        }
      }
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(`${origin}/tutorial/first-container/`);
      await page.locator('.outline summary').click();
      const outlineNav = page.getByRole('navigation', { name: 'Headings on this page' });
      await outlineNav.getByRole('link', { name: 'Naming your containers', exact: true }).click();
      await page.waitForFunction(() => location.hash === '#naming-your-containers');
      assert.equal(await page.locator('.outline').evaluate(element => element.open), false);
      const headingTop = await page.locator('#naming-your-containers').evaluate(element => element.getBoundingClientRect().top);
      const headerBottom = await page.locator('.site-header').evaluate(element => element.getBoundingClientRect().bottom);
      assert.ok(headingTop >= headerBottom && headingTop < headerBottom + 60, 'Target heading lands below the header');
      await page.reload();
      assert.equal(await page.locator('.outline').evaluate(element => element.open), false);
      await assertNoOverflow(page);
    });
  });

  test(`${engine}: nested headings, opt-out, no-heading pages, and no JavaScript`, async () => {
    const { browser } = browsers.find(item => item.name === engine);
    await withPage(browser, { javaScriptEnabled: false }, async page => {
      for (const path of ['/docs/ai-skill/', '/docs/outline-disabled/']) {
        await page.goto(origin + path);
        assert.equal(await page.locator('.page-outline').count(), 0);
      }
      await page.goto(`${origin}/docs/outline-nesting/`);
      assert.equal(await page.locator('.outline-links > ul > li > ul > li > ul a').textContent(), 'Six');
      const targets = await page.locator('.outline-links a').evaluateAll(elements => elements.map(element => decodeURIComponent(element.hash.slice(1))));
      assert.equal(new Set(targets).size, 6, 'Duplicate headings retain distinct anchors');
      for (const id of targets) assert.equal(await page.locator(`[id="${id}"]`).count(), 1);
      await page.locator('.outline-links a').last().click();
      assert.equal(new URL(page.url()).hash, `#${targets.at(-1)}`);
      await page.locator('.outline summary').click();
      assert.equal(await page.locator('.outline').evaluate(element => element.open), false);
      await page.goto(`${origin}/#downloads`);
      assert.equal(await page.locator('#fallback').isVisible(), true);
    });
  });

  test(`${engine}: theme preference and release fallback remain usable`, async () => {
    const { browser } = browsers.find(item => item.name === engine);
    await withPage(browser, {}, async page => {
      await page.goto(origin);
      await page.getByRole('button', { name: 'Switch to dark theme' }).click();
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
      await page.reload();
      assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
      assert.equal(await page.locator('#fallback').isVisible(), true);
      assert.equal(await page.locator('#fallback a').first().getAttribute('href'), 'https://github.com/fiorix/sdme/releases/latest');
      await page.goto(`${origin}/docs/ai-skill/`);
      assert.equal(await page.getByRole('button', { name: 'Copy code', exact: true }).count(), 2);
    });
  });

  test(`${engine}: shared Markdown links and GitHub alerts render on the website`, async () => {
    const { browser } = browsers.find(item => item.name === engine);
    await withPage(browser, {}, async page => {
      await page.goto(`${origin}/tutorial/first-container/`);
      assert.equal(await page.getByRole('link', { name: 'installation page', exact: true }).getAttribute('href'), `${origin}/#installation`);
      assert.equal(await page.locator('.markdown-alert-warning').count(), 2);
      assert.equal(await page.locator('.markdown-alert-tip').count(), 1);
      await page.getByRole('link', { name: 'Day-to-Day Management', exact: true }).click();
      assert.equal(new URL(page.url()).pathname, '/tutorial/management/');
      await page.goto(`${origin}/docs/security/`);
      await page.getByRole('link', { name: 'Architecture, Section 14', exact: true }).first().click();
      assert.equal(new URL(page.url()).pathname, '/docs/architecture/');
      assert.equal(new URL(page.url()).hash, '#14-security');
      await page.locator('[id="14-security"]').waitFor({ state: 'visible' });
      assert.equal(await page.locator('[id="14-security"]').isVisible(), true);
      const table = page.getByRole('table').filter({ hasText: 'Diff container against its base rootfs' });
      assert.equal(await table.getByRole('cell', { name: 'NAME', exact: true }).count(), 1);
    });
  });
}
