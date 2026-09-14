import { watch } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareSite } from './content.mjs';

const site = dirname(dirname(fileURLToPath(import.meta.url)));
const output = join(site, '.zola');
const [command = 'build', ...args] = process.argv.slice(2);
if (!['build', 'check', 'serve'].includes(command)) throw new Error('Expected build, check, or serve');
prepareSite(site, output);

const watchers = [];
let pending;
if (command === 'serve') {
  function rebuild() {
    clearTimeout(pending);
    pending = setTimeout(() => {
      try { prepareSite(site, output); }
      catch (error) { console.error(error.message); }
    }, 100);
  }
  watchers.push(watch(join(dirname(site), 'docs'), { recursive: true }, rebuild));
  for (const directory of ['content', 'static', 'templates']) {
    watchers.push(watch(join(site, directory), { recursive: true }, rebuild));
  }
  watchers.push(watch(site, (_, path) => {
    if (path === 'config.toml' || path === 'pages.json') rebuild();
  }));
}

const zolaArgs = ['--root', output, command];
if (command !== 'check') zolaArgs.push('--output-dir', join(site, 'public'), '--force');
const child = spawn(process.env.ZOLA_BIN || 'zola', [...zolaArgs, ...args], { stdio: 'inherit' });
function cleanup() {
  clearTimeout(pending);
  watchers.forEach(watcher => watcher.close());
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { cleanup(); child.kill(signal); });
child.on('error', error => { cleanup(); console.error(error.message); process.exitCode = 1; });
child.on('exit', (code, signal) => { cleanup(); process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
