## Purpose

This file gives guidance to AI coding agents working on the `homebridge-blink-for-home-new` repository so they can be productive immediately. Keep advice concrete and codebase-specific.

## Quick start (what humans normally run)

- Install deps: `npm install`
- Run tests and linting: `npm test` (runs `jest` then `eslint`)
- Link plugin for local Homebridge development: `npm run watch` (runs `npm link` after a no-op build)
- CLI entrypoint: `bin/blink` (calls `src/blink-cli`)

Notes: Node engines required are ^20 || ^22 || ^24 (see `package.json`). Homebridge-compatible versions are declared under `engines`.

## Big-picture architecture (short)

- Blink API client: `src/blink-api.js` — encapsulates HTTP calls to Blink (token management, refresh, region shards, retries, caching).
- Blink domain model: `src/blink.js` — Blink, BlinkCamera, BlinkNetwork classes manage polling, thumbnails, motion, and command orchestration.
- Homebridge integration: `src/homebridge/*.js` (entry: `src/index.js`, platform: `src/homebridge/index.js`) — registers the Homebridge platform, wires HAP logger, and creates accessories using device-level helpers.
- UI integration: `homebridge-ui/server.js` — implements the Plugin UI server (extends `@homebridge/plugin-ui-utils`).
- CLI: `bin/blink` → `src/blink-cli` provides a CLI wrapper for developer utilities.

Data flow summary:
- On startup Homebridge calls the platform entry (`src/index.js`) which registers `HomebridgeBlink` (in `src/homebridge/index.js`).
- `HomebridgeBlink.setupBlink()` builds a `BlinkHAP`/`Blink` instance (client + domain), authenticates (token or PIN 2FA), then calls `Blink.refreshData()` to fetch networks/cameras.
- Blink classes poll Blink APIs (thumbnail, status, media) and expose convenience methods used by accessory code to update HAP characteristics.

## Key patterns & conventions (project-specific)

- Token / credentials sources: credentials can come from `config.json` (Homebridge UI) or environment variables: `BLINK_EMAIL`, `BLINK_PASSWORD`, `BLINK_PIN`, `BLINK_CLIENT_UUID`. The Blink client also reads an ini file via `inifile.js` when present.
- OAuth cache: Homebridge plugin persists an OAuth bundle to `api.user.storagePath()` as `blink-oauth.json` (see `src/homebridge/index.js` and Blink._persistOAuthBundle()).
- Polling and throttle: Blink enforces internal cooldowns and caching in `src/blink-api.js` and `src/blink.js`. Avoid adding un-throttled loops — reuse existing Blink methods like `refreshData`, `refreshCameraThumbnail`.
- Locking for commands: use Blink._lock or Blink._command(...) pattern to avoid concurrent update races (see `Blink._lock`, `Blink._command`, `_commandWait`).
- Binary assets: placeholder images used by cameras are loaded synchronously from `src/` (e.g. `privacy.png`, `disabled.png`) — tests and code expect these files to be present.

## Tests, linting, and developer workflows

- Run unit tests: `npm test` (runs `jest` and the linter). Test files are alongside sources: `src/*.test.js` and `src/homebridge/*.test.js`.
- Linting: ESLint with Google style; rules are in `package.json` under `eslintConfig` (4-space indent, Stroustrup brace style). Keep line length <= 125.
- Local plugin development: `npm run watch` will `npm link` the package. To test with Homebridge locally, install Homebridge in dev or globally and run Homebridge in debug mode (e.g. `homebridge -D` or via `npx homebridge -D`). The repo has `homebridge` as a devDependency — tests can run with the version in `node_modules`.

## Integration points & external dependencies

- Blink REST endpoints (the client targets `rest-<region>.immedia-semi.com` and `rest-prod.immedia-semi.com`). `src/blink-api.js` contains the list of endpoints used and logic for shard discovery (`/api/v1/account/tier_info`).
- Homebridge HAP: plugin registers as a platform and uses `homebridge.hap` to build UUIDs and HAP types. See `src/index.js` and `src/homebridge/index.js`.
- UI: `@homebridge/plugin-ui-utils` is used by `homebridge-ui/server.js`.

## What to reference in code reviews / changes

- Authentication & expiry: all token logic lives in `src/blink-api.js` (`login`, `refreshGrant`, `useOAuthBundle`, `getOAuthBundle`). When changing auth behavior, update `Blink._persistOAuthBundle` and `HomebridgeBlink.setupBlink()` use of `api.user.storagePath()`.
- Polling & resource usage: `src/blink.js` controls polling intervals (constants at top) and caching; if you change intervals, update constants and tests accordingly.
- Accessory wiring: `src/homebridge/index.js` expects devices to provide `createAccessory(api, cachedAccessories)` and to expose `canonicalID` values used when registering/unregistering accessories.

## Examples (copyable snippets / places to inspect)

- Authenticate and fetch homescreen: `Blink.authenticate()` → `Blink.refreshData()` (see `src/homebridge/index.js:setupBlink`).
- Refresh a camera thumbnail safely: `blink.refreshCameraThumbnail(networkID, cameraID, force)` (see `src/blink.js`).
- Call Blink REST: `new BlinkAPI().get('/networks')` (see `src/blink-api.js`) — note the client will try to login automatically if needed.

## Gotchas & cautionary notes

- 2FA: Blink may require email/phone PIN verification. `blink-api` resends/validates PINs; code paths will throw with descriptive messages — tests may need to mock `BlinkAPI.login` or use token bundles.
- Rate limiting & retries: Blink endpoints can return 429 or 5xx — the client has retry logic. Avoid adding duplicate retry loops around `BlinkAPI` calls unless you also update caching/lock logic.
- Tests may rely on binary files and small fixtures in `src/` (privacy/disabled images). Preserve these files when refactoring.

## If you need more info

- I merged what I found from `README.md`, `package.json`, and the key sources under `src/`.
- If something is missing (CI scripts, build step, or a canonical accessory factory), tell me which area to expand and I will update this doc.

---
Please review and tell me if you'd like more details about any of the following: accessory creation, token caching format, local Homebridge run steps, or tests to add for a specific module.
