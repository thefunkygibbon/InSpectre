# InSpectre Plugin Examples

This folder contains ready-to-adapt example plugins and an annotated template.
Plugins in InSpectre are **declarative manifests** (JSON or YAML) — there is no
plugin code to write or compile. The InSpectre engine reads the manifest and
performs the HTTP / file / SNMP calls for you, then maps the responses into the
device inventory and event system.

For the complete API reference, see [`../../plugin.md`](../../plugin.md).

## Files

| File | What it shows |
|---|---|
| [`TEMPLATE.yaml`](TEMPLATE.yaml) | Fully annotated skeleton with every field explained inline. The best starting point. |
| [`hello-world.json`](hello-world.json) | Minimal **discovery** plugin: polls a JSON API for a DHCP lease list and feeds devices into the inventory. API-key-header auth. |
| [`example-firewall.json`](example-firewall.json) | **Blocking** plugin for a token-authenticated firewall. Shows a `login → action` dependency chain, bearer-token `session_extract`, and the required `block_client` / `unblock_client` actions. |

## How to use one

1. Copy a file (e.g. `TEMPLATE.yaml`) and rename it. Set a unique lowercase `id`.
2. Edit the `config_schema`, `endpoints`, and `actions` to match your device's API.
3. In InSpectre go to **Settings → Plugins → Upload Plugin** and select your file
   (both `.json` and `.yaml`/`.yml` are accepted).
4. Open the plugin, fill in the config fields, and click **Test Connection**.
5. Toggle **Enabled**. Polling plugins begin on the next cycle; blocking plugins
   become selectable under **Settings → Security Responses → Blocking Method**.

## Validate before uploading (optional)

A manifest is validated on upload, but you can sanity-check the JSON/YAML locally:

```bash
python3 -c "import json,sys; json.load(open(sys.argv[1])); print('JSON OK')" hello-world.json
python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1])); print('YAML OK')" TEMPLATE.yaml
```

## Tips

- Mark secret fields as `type: password` — they are encrypted at rest.
- Add a `test_connection` action so the **Test Connection** button works.
- For APIs that always return HTTP 200 and signal failures in the body, use
  `endpoints.error_check` (see the guide) so failures surface correctly.
- Set `min_inspectre_version` to the version you developed against.
