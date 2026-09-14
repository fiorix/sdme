import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { parse, postprocess, preprocess } from 'micromark';
import { decodeString } from 'micromark-util-decode-string';

const repository = 'https://github.com/fiorix/sdme';

function encodePath(path) {
  return path.split(sep).map(part => encodeURIComponent(part).replace(/[()]/g, character => '%' + character.charCodeAt(0).toString(16))).join('/');
}

// Token offsets let the build change destinations without reformatting Markdown or code.
export function rewriteLinks(markdown, rewrite) {
  const events = postprocess(parse().document().write(preprocess()(markdown, undefined, true)));
  const replacements = [];
  for (const [event, token] of events) {
    if (event !== 'enter' || !['resourceDestinationString', 'definitionDestinationString'].includes(token.type)) continue;
    const destination = markdown.slice(token.start.offset, token.end.offset);
    const replacement = rewrite(decodeString(destination));
    if (replacement !== null) replacements.push({ start: token.start.offset, end: token.end.offset, replacement });
  }
  for (const { start, end, replacement } of replacements.reverse()) {
    markdown = markdown.slice(0, start) + replacement + markdown.slice(end);
  }
  return markdown;
}

function files(directory) {
  return readdirSync(directory, { recursive: true, withFileTypes: true })
    .filter(entry => entry.isFile())
    .map(entry => join(entry.parentPath, entry.name));
}

function inside(root, path) {
  const result = relative(root, path);
  return result !== '..' && !result.startsWith('..' + sep) && !isAbsolute(result);
}

// The output is disposable; canonical Markdown and site templates are only read.
export function prepareSite(site, output) {
  const root = dirname(site);
  const docs = join(root, 'docs');
  const pages = JSON.parse(readFileSync(join(site, 'pages.json'), 'utf8'));
  const generated = new Map();
  const routes = new Map([
    [join(root, 'README.md'), '_index.md'],
    [join(docs, 'README.md'), 'docs/_index.md'],
  ]);
  for (const [target, page] of Object.entries(pages)) {
    const source = resolve(root, page.source);
    if (!inside(docs, source) || !inside(join(output, 'content'), resolve(output, 'content', target))) {
      throw new Error(`Page paths must stay inside docs and generated content: ${target}`);
    }
    if (routes.has(source)) throw new Error(`Duplicate Markdown source: ${page.source}`);
    routes.set(source, target);
  }

  for (const source of files(docs)) {
    if (extname(source) === '.md') {
      if (!routes.has(source)) throw new Error(`Register ${relative(root, source)} in site/pages.json`);
    } else {
      const target = 'docs-assets/' + relative(docs, source).split(sep).join('/');
      routes.set(source, target);
      generated.set('static/' + target, readFileSync(source));
    }
  }

  function linkFor(source, destination) {
    if (/^(?:[a-z][a-z\d+.-]*:|\/|#)/i.test(destination)) return null;
    const match = destination.match(/^([^?#]*)(.*)$/);
    const target = resolve(dirname(source), decodeURIComponent(match[1]));
    if (!inside(root, target) || !existsSync(target)) {
      throw new Error(`${relative(root, source)}: missing relative link ${destination}`);
    }
    if (routes.has(target)) {
      if (extname(target) !== '.md') {
        const pageDirectory = routes.get(source).replace(/(?:_index)?\.md$/, '');
        return encodePath(posix.relative(pageDirectory, routes.get(target))) + match[2];
      }
      return '@/' + encodePath(routes.get(target)) + match[2];
    }
    const kind = statSync(target).isDirectory() ? 'tree' : 'blob';
    return `${repository}/${kind}/main/${encodePath(relative(root, target))}${match[2]}`;
  }

  for (const source of files(docs).filter(source => extname(source) === '.md')) {
    const markdown = readFileSync(source, 'utf8');
    if (!/^# .+\n/.test(markdown)) throw new Error(`${relative(root, source)} must start with a Markdown title`);
    const body = rewriteLinks(markdown, destination => linkFor(source, destination));
    const target = routes.get(source);
    if (source === join(docs, 'README.md')) continue;
    const { source: sourcePath, ...metadata } = pages[target];
    const title = markdown.slice(2, markdown.indexOf('\n')).trim();
    const extra = { ...metadata.extra, source: sourcePath };
    delete metadata.extra;
    const front = Object.entries({ title, ...metadata }).map(([key, value]) => `${key} = ${JSON.stringify(value)}`);
    front.push('[extra]', ...Object.entries(extra).map(([key, value]) => `${key} = ${JSON.stringify(value)}`));
    generated.set('content/' + target, Buffer.from(`+++\n${front.join('\n')}\n+++\n${body.slice(body.indexOf('\n') + 1)}`));
  }

  generated.set('config.toml', readFileSync(join(site, 'config.toml')));
  for (const directory of ['content', 'static', 'templates']) {
    for (const source of files(join(site, directory))) {
      const target = relative(site, source).split(sep).join('/');
      if (generated.has(target)) throw new Error(`Generated page collides with site source: ${target}`);
      generated.set(target, readFileSync(source));
    }
  }

  mkdirSync(output, { recursive: true });
  for (const file of files(output)) {
    if (!generated.has(relative(output, file).split(sep).join('/'))) rmSync(file);
  }
  for (const [target, content] of generated) {
    const path = join(output, target);
    if (existsSync(path) && readFileSync(path).equals(content)) continue;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
}
