const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { dirname, join, resolve } = require('node:path');
const { before, test } = require('node:test');

let prepareSite;
let rewriteLinks;
before(async () => ({ prepareSite, rewriteLinks } = await import('../scripts/content.mjs')));

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'sdme-markdown-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const directory of ['docs/tutorial', 'site/content', 'site/static', 'site/templates']) mkdirSync(join(root, directory), { recursive: true });
  writeFileSync(join(root, 'README.md'), '# sdme\n\n## Installation\n');
  writeFileSync(join(root, 'docs/README.md'), '# Documentation\n');
  writeFileSync(join(root, 'docs/architecture.md'), '# Architecture\n\n## Storage\n');
  writeFileSync(join(root, 'docs/tutorial/start.md'), '# Start\n\n[Architecture](../architecture.md#storage)\n\n[Install](../../README.md#installation)\n');
  writeFileSync(join(root, 'site/config.toml'), 'base_url = "https://sdme.io"\n');
  const pages = {
    'docs/architecture.md': { source: 'docs/architecture.md', weight: 1, template: 'doc.html' },
    'tutorial/start.md': { source: 'docs/tutorial/start.md', weight: 1, extra: { show_outline: false } },
  };
  writeFileSync(join(root, 'site/pages.json'), JSON.stringify(pages));
  return { root, site: join(root, 'site'), output: join(root, 'site/.zola'), pages };
}

test('rewrite inline, image, and reference destinations without touching code or formatting', () => {
  const source = [
    '[**nested** label](../doc.md#heading "Title")',
    '![image](<image%20name.svg>)',
    '[reference][id]',
    '',
    '[id]: ../doc.md#other',
    '',
    '`[inline example](example.md)`',
    '',
    '```md',
    '[fenced example](example.md)',
    '```',
    '',
    '    [indented example](example.md)',
    '',
    '> [!TIP]',
    '> Keep this alert.',
    '',
    '[escaped](file\\(name\\).md)',
  ].join('\n');
  const destinations = [];
  const output = rewriteLinks(source, destination => { destinations.push(destination); return `@/${destination}`; });
  assert.deepEqual(destinations, ['../doc.md#heading', 'image%20name.svg', '../doc.md#other', 'file(name).md']);
  assert.equal(output, source.replace('(../doc.md#heading', '(@/../doc.md#heading').replace('<image%20name.svg>', '<@/image%20name.svg>').replace('[id]: ../doc.md', '[id]: @/../doc.md').replace('file\\(name\\).md', '@/file(name).md'));
});

test('generate metadata and website links from canonical Markdown', t => {
  const { root, site, output } = fixture(t);
  const original = readFileSync(join(root, 'docs/tutorial/start.md'), 'utf8');
  prepareSite(site, output);
  const generated = readFileSync(join(output, 'content/tutorial/start.md'), 'utf8');
  assert.match(generated, /title = "Start"/);
  assert.match(generated, /show_outline = false/);
  assert.match(generated, /\[Architecture\]\(@\/docs\/architecture.md#storage\)/);
  assert.match(generated, /\[Install\]\(@\/_index.md#installation\)/);
  assert.doesNotMatch(generated, /^# Start$/m);
  assert.equal(readFileSync(join(root, 'docs/tutorial/start.md'), 'utf8'), original);
});

test('copy local assets and link repository files to GitHub', t => {
  const { root, site, output } = fixture(t);
  writeFileSync(join(root, 'docs/diagram.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
  writeFileSync(join(root, 'example.sh'), 'true\n');
  writeFileSync(join(root, 'docs/architecture.md'), '# Architecture\n\n![Diagram](diagram.svg)\n\n[Script](../example.sh)\n');
  prepareSite(site, output);
  const generated = readFileSync(join(output, 'content/docs/architecture.md'), 'utf8');
  assert.match(generated, /!\[Diagram\]\(\.\.\/\.\.\/docs-assets\/diagram.svg\)/);
  assert.match(generated, /https:\/\/github.com\/fiorix\/sdme\/blob\/main\/example.sh/);
  assert.equal(readFileSync(join(output, 'static/docs-assets/diagram.svg'), 'utf8'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
});

test('reject missing links before changing the generated site', t => {
  const { root, site, output } = fixture(t);
  prepareSite(site, output);
  const original = readFileSync(join(output, 'content/docs/architecture.md'), 'utf8');
  writeFileSync(join(root, 'docs/architecture.md'), '# Architecture\n\n[Missing](missing.md)\n');
  assert.throws(() => prepareSite(site, output), /missing relative link missing.md/);
  assert.equal(readFileSync(join(output, 'content/docs/architecture.md'), 'utf8'), original);
});

test('reject unregistered sources and remove pages deleted from the manifest', t => {
  const { root, site, output, pages } = fixture(t);
  prepareSite(site, output);
  delete pages['tutorial/start.md'];
  writeFileSync(join(site, 'pages.json'), JSON.stringify(pages));
  assert.throws(() => prepareSite(site, output), /Register docs\/tutorial\/start.md/);
  rmSync(join(root, 'docs/tutorial/start.md'));
  prepareSite(site, output);
  assert.equal(existsSync(join(output, 'content/tutorial/start.md')), false);
});

test('canonical docs contain plain Markdown and valid relative file targets', () => {
  const site = resolve(__dirname, '..');
  const root = resolve(site, '..');
  const pages = JSON.parse(readFileSync(join(site, 'pages.json'), 'utf8'));
  for (const { source } of Object.values(pages)) {
    const markdown = readFileSync(join(root, source), 'utf8');
    assert.match(markdown, /^# .+\n/);
    assert.doesNotMatch(markdown, /\{%|\]\(@\//);
    assert.doesNotMatch(markdown, /^> \[!\w+\] .+/m, 'Alert markers stay on their own line');
  }
  const output = mkdtempSync(join(tmpdir(), 'sdme-canonical-'));
  try { prepareSite(site, output); }
  finally { rmSync(output, { recursive: true, force: true }); }
});

test('canonical heading links resolve using GitHub anchor names', async () => {
  const { default: GithubSlugger } = await import('github-slugger');
  const { micromark, parse, postprocess, preprocess } = await import('micromark');
  const { decodeString } = await import('micromark-util-decode-string');
  const root = resolve(__dirname, '../..');
  const pages = JSON.parse(readFileSync(join(root, 'site/pages.json'), 'utf8'));
  const ids = new Map();
  function headings(source) {
    if (ids.has(source)) return ids.get(source);
    const markdown = readFileSync(source, 'utf8');
    const events = postprocess(parse().document().write(preprocess()(markdown, undefined, true)));
    const slugger = new GithubSlugger();
    const result = new Set();
    for (const [event, token] of events) {
      if (event !== 'enter' || !['atxHeading', 'setextHeading'].includes(token.type)) continue;
      const html = micromark(markdown.slice(token.start.offset, token.end.offset));
      result.add(slugger.slug(decodeString(html.replace(/<[^>]*>/g, '').trim())));
    }
    ids.set(source, result);
    return result;
  }
  for (const source of ['docs/README.md', ...Object.values(pages).map(page => page.source)]) {
    const absolute = join(root, source);
    rewriteLinks(readFileSync(absolute, 'utf8'), destination => {
      if (/^(?:[a-z][a-z\d+.-]*:|\/)/i.test(destination) || !destination.includes('#')) return null;
      const [path, fragment] = destination.split('#');
      const target = path ? resolve(dirname(absolute), decodeURIComponent(path)) : absolute;
      if (target.endsWith('.md') && fragment) {
        assert.ok(headings(target).has(decodeURIComponent(fragment)), `${source}: GitHub heading is missing for ${destination}`);
      }
      return null;
    });
  }
});
