# InSpectre marketing website

Static marketing site for **www.inspectre.cc**. Pure HTML/CSS/JS — no build step,
no server, no dependencies. Upload the contents of this folder to any static host.

The design is a **TUI / terminal-app aesthetic**: a tmux-style status bar, terminal
windows, a `man`-page command reference, box-drawn ASCII panels and a matrix-green
palette on black. All four pages share `assets/style.css` and `assets/main.js`.

## Pages
- `index.html` — landing page (what InSpectre is + key capabilities)
- `downloads.html` — Docker / VM / Raspberry Pi download options
- `docs.html` — install & usage guide (summary; links to the full Wiki)
- `plugins.html` — plugin developer guide (summary of `plugin.md`)
- `help.html` — support links + mailto contact form

## Assets
- `assets/style.css` — terminal theme (matrix green on black), responsive
- `assets/main.js` — mobile nav, copy-to-clipboard, status-bar clock, reveal-on-scroll, footer year
- `assets/ghost-logo.svg` — ghost wordmark logo
- `assets/favicon.svg` — favicon

## Keeping content accurate
The copy is kept in sync with the actual application. When features change, update:
- **Container count** — the stack is **4 containers**: `frontend`, `backend` (web),
  `probe`, and `db` (PostgreSQL). See `docker-compose.yml`.
- **Network tools count** — `docs.html` and `index.html` cite the tool count; the tools
  live in `backend/main.py` (`/tools/*` endpoints).
- **Notification channels** — channel types are defined in `backend/main.py`.
- **Plugin reference** — `plugins.html` summarises `plugin.md`; keep the built-in
  plugin table and capability list in step with `backend/plugins/builtin/`.

## Placeholders to update before going live
- **Screenshots** — the landing page uses ASCII panels instead of screenshots; drop real
  images into `assets/` if you want to swap them in.
- **Docker Hub** — the downloads page links to `https://hub.docker.com/u/thefunkygibbon`;
  update if the namespace/image differs.
- **VM & Raspberry Pi images** — currently marked "coming soon"; wire up the real
  download URLs once the hosting location is decided.

## Local preview
```bash
cd website
python3 -m http.server 8080
# open http://localhost:8080
```
