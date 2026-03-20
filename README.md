# vlpo-worker-rs

## Required Settings

Set these before local testing or deployment:

- `UUID`: access identifier
- `WS_PATH`: expected WebSocket path

Optional fallback settings:

- `PROXYIP`: fallback relay host or `host:port`
- `SOCKS5`: SOCKS5 relay in `socks5://user:pass@host:port` form
- `HTTP_PROXY`: HTTP CONNECT relay in `http://user:pass@host:port` form

If `PROXYIP` is set without an explicit port, the destination port is reused.

## Local Development

Create `.dev.vars`:

```env
UUID=xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx
WS_PATH=/your-private-path
# optional
# PROXYIP=1.2.3.4
# SOCKS5=socks5://user:pass@host:port
# HTTP_PROXY=http://user:pass@host:port
```

Run locally:

```bash
wrangler dev
```

## Deployment

```bash
wrangler secret put UUID
wrangler secret put WS_PATH
# optional
wrangler secret put PROXYIP
wrangler secret put SOCKS5
wrangler secret put HTTP_PROXY
```

Deploy:

```bash
wrangler deploy
```