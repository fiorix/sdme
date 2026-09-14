# Website

The website uses Zola 0.22.1 and Node.js 22 or newer. Run `npm ci` from this directory, then `npm run serve` for a local preview, `npm run build` to generate `public/`, or `npm run check` to check internal links. Set `ZOLA_BIN` if Zola is outside your `PATH`.

## Shared Markdown

Edit documentation in [`../docs/`](../docs/README.md). These are ordinary Markdown files with a leading `# Title`, relative links such as `[Security](security.md)`, fenced code blocks, and GitHub alerts. They render directly on GitHub. Use relative `.md` links for other pages, including heading fragments; link repository files relative to the current document too.

`pages.json` maps website content paths to the canonical Markdown source and records descriptions, ordering, templates, and optional page settings. Register new pages there. Existing documentation URLs remain under `/docs/` and tutorials under `/tutorial/`.

The build copies site files into the ignored `.zola/` directory, adds Zola front matter, and rewrites Markdown link destinations there. Links to published documents become website links; links to other repository files point to GitHub, and documentation assets are published under `/docs-assets/`. The parser preserves code examples and source formatting. Build checks reject missing relative targets and unregistered Markdown pages. Generated files are never edited or committed.

`npm run serve` watches the canonical Markdown, metadata, and site templates and assets, then lets Zola rebuild the preview. GitHub Pages runs the same build and deploys when either `docs/` or `site/` changes.

## Page outlines

Documentation and tutorial pages automatically show an outline generated from their Markdown headings, including nested headings. Pages without headings have no outline. On desktop, the outline stays beside the article and highlights the current heading as you scroll. On screens up to 900px wide, it becomes a collapsed control above the article; selecting a heading closes it. Heading links and the collapse control also work without JavaScript.

Set `show_outline = false` under `[extra]` in `config.toml` to disable outlines site-wide. Override the default for an individual page in its `pages.json` entry:

```json
"extra": { "show_outline": false }
```

## Verification

Run `npx playwright install chromium webkit`, then `npm test`. Tests cover Markdown adaptation and build an isolated copy of the site to check heading navigation, desktop and mobile layouts, theme switching, release fallbacks, and operation without JavaScript in Chromium and WebKit.
