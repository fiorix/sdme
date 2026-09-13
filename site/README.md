# Website

The website is built with Zola. Run `zola serve` from this directory for a local preview, or `zola build` to generate `public/`. Deployment uses Zola 0.22.1.

## Page outlines

Documentation and tutorial pages automatically show an outline generated from their Markdown headings, including nested headings. Pages without headings have no outline. On desktop, the outline stays beside the article and highlights the current heading as you scroll. On screens up to 900px wide, it becomes a collapsed control above the article; selecting a heading closes it. Heading links and the collapse control also work without JavaScript.

Set `show_outline = false` under `[extra]` in `config.toml` to disable outlines site-wide. Override the default for an individual page in its front matter:

```toml
[extra]
show_outline = false
```

## Verification

Run `npm ci`, then `npx playwright install chromium webkit`, and `npm test`. The tests build an isolated copy of the site and check heading navigation, desktop and mobile layouts, theme switching, release fallbacks, and operation without JavaScript in Chromium and WebKit. Set `ZOLA_BIN` if Zola is outside your `PATH`.
