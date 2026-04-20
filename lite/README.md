# gproxy-lite

A single-binary, personal-use Claude proxy using **OAuth** (the same auth
method the official Claude Code CLI uses). Forked down from [gproxy] with
everything non-essential removed.

## What it does

- Exposes `/v1/messages`, `/v1/messages/count_tokens`, `/v1/models` and
  forwards to `api.anthropic.com` using your OAuth access token.
- Refreshes the access token automatically before expiry.
- Injects the required `You are Claude Code, …` identity into `system` so
  OAuth requests aren't rejected (toggle via config).
- Logs every request (model, tokens, status, latency) to SQLite.
- Serves a single read-only status page at `/` for a quick glance.

## What it does NOT do

No web admin, no user system, no multi-provider routing, no OpenAI-style
protocol translation — by design.

## Quickstart

```bash
cd lite

# 1. Configure
cp gproxy.example.toml gproxy.toml
$EDITOR gproxy.toml          # set a client_key

# 2. Log in via OAuth (opens browser, paste the code back)
cargo run --release -- login

# 3. Run the proxy
cargo run --release
```

Then point your client at `http://127.0.0.1:8787` with the `client_key`
you set as the API key. Status page: `http://127.0.0.1:8787/`.

## Config

See `gproxy.example.toml`. The two fields that matter:

- `server.client_key` — the key your client sends to the proxy.
- `upstream.tokens_file` — where OAuth tokens are stored (created by `login`).

## OAuth login flow

`gproxy-lite login` prints a URL. Open it, sign in to Claude, and after
authorization the browser lands on `https://platform.claude.com/oauth/code/callback`
with a `?code=…&state=…` in the URL. Copy the code (or paste the whole URL)
back into the terminal. Tokens land in `./data/tokens.json`.

## Client setup examples

**Claude Code CLI**

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
export ANTHROPIC_AUTH_TOKEN=sk-lite-change-me   # whatever you set in config
claude
```

**Cherry Studio / Chatbox**: set API Base to `http://127.0.0.1:8787`,
API Key to your `client_key`.

[gproxy]: https://github.com/LeenHawk/gproxy
