# InSpectre marketing website

Static marketing site for **www.inspectre.cc**. Pure HTML/CSS/JS — no build step,
no server, no dependencies. Upload the contents of this folder to any static host.

## Pages
- `index.html` — landing page (what InSpectre is + key features)
- `downloads.html` — Docker / VM / Raspberry Pi download options
- `docs.html` — install & usage guide (summary; links to the full Wiki)
- `help.html` — redirects to the GitHub issues tracker

## Assets
- `assets/style.css` — phantom dark theme (matrix green on black), responsive
- `assets/main.js` — mobile nav, copy-to-clipboard, reveal-on-scroll
- `assets/logo.svg` — ghost/scan-line wordmark logo (also used as favicon)

## Placeholders to update before going live
- **Screenshots** — drop real images in `assets/` and replace the
  `.shot-placeholder` / `.split-media` blocks (search for "screenshot").
- **Docker Hub** — the downloads page links to
  `https://hub.docker.com/u/thefunkygibbon`; update if the namespace/image differs.
- **VM & Raspberry Pi images** — currently marked "Coming soon"; wire up the
  real download URLs once the hosting location is decided.

## Local preview
```bash
cd website
python3 -m http.server 8080
# open http://localhost:8080
```
