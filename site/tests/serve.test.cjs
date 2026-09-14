const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { test } = require('node:test');

test('live preview regenerates canonical Markdown and serves relative assets', { timeout: 20000 }, async t => {
  const root = resolve(__dirname, '../..');
  const temporary = mkdtempSync(join(tmpdir(), 'sdme-preview-'));
  for (const entry of ['docs', 'README.md', 'site/content', 'site/static', 'site/templates', 'site/scripts', 'site/config.toml', 'site/pages.json']) {
    cpSync(join(root, entry), join(temporary, entry), { recursive: true });
  }
  symlinkSync(join(root, 'site/node_modules'), join(temporary, 'site/node_modules'), 'dir');
  symlinkSync(join(root, 'test'), join(temporary, 'test'), 'dir');
  const reserve = createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));

  const child = spawn(process.execPath, [join(temporary, 'site/scripts/zola.mjs'), 'serve', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', data => { logs += data; });
  child.stderr.on('data', data => { logs += data; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGINT');
      await once(child, 'exit');
    }
    rmSync(temporary, { recursive: true, force: true });
  });

  const origin = `http://127.0.0.1:${port}`;
  async function waitForPage(text) {
    for (let attempt = 0; attempt < 100; attempt++) {
      assert.equal(child.exitCode, null, logs);
      const response = await fetch(origin + '/docs/ai-skill/').catch(() => null);
      if (response?.ok) {
        const html = await response.text();
        if (html.includes(text)) return html;
      }
      await delay(100);
    }
    assert.fail(`Preview did not render ${text}\n${logs}`);
  }

  await waitForPage('Embedded AI agent skill');
  const source = join(temporary, 'docs/ai-skill.md');
  writeFileSync(join(temporary, 'docs/preview.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
  writeFileSync(source, readFileSync(source, 'utf8') + '\n## Live preview update\n\n![Preview](preview.svg)\n');
  const html = await waitForPage('Live preview update');
  const assetUrl = html.match(/<img src="([^"]+)"/)[1];
  const response = await fetch(new URL(assetUrl, origin));
  assert.equal(response.status, 200, assetUrl + '\n' + logs);
  assert.match(await response.text(), /<svg/);
  const generated = readFileSync(join(temporary, 'site/.zola/content/docs/ai-skill.md'), 'utf8');
  assert.match(generated, /\[Preview\]\(\.\.\/\.\.\/docs-assets\/preview.svg\)/);
});
