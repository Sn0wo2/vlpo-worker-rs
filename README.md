# vlpo-worker-rs

## Required Secrets

- `UUID`
- `WS_PATH`

## Optional Secrets

- `PROXYIP`
- `SOCKS5`
- `HTTP_PROXY`
- `DNS_UPSTREAM`
- `KEY`
- `PASSWORD`

`PROXYIP` keeps the destination port when you only provide a host or IP.

## DNS Upstream

`DNS_UPSTREAM` accepts one or more entries, separated by commas.

Examples:

```env
DNS_UPSTREAM=https://dns.google/dns-query
DNS_UPSTREAM=https://dns.google/dns-query,https://dns.quad9.net/dns-query
DNS_UPSTREAM=tls://8.8.8.8,tls://9.9.9.9
DNS_UPSTREAM=8.8.8.8:53,9.9.9.9:53
```

Supported formats:

- `https://host/dns-query` for DoH
- `tls://host:853` for DoT
- `host:53` for TCP DNS

Default DNS upstream:

```env
DNS_UPSTREAM=https://dns.google/dns-query
```

## Local Development

Create `.dev.vars`:

```env
UUID=xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx
WS_PATH=/your-private-path
# optional
# PROXYIP=1.2.3.4
# SOCKS5=socks5://user:pass@host:port
# HTTP_PROXY=http://user:pass@host:port
# DNS_UPSTREAM=https://dns.google/dns-query,https://dns.quad9.net/dns-query
```

Run:

```bash
wrangler dev
```

## Deployment

Set secrets:

```bash
wrangler secret put UUID
wrangler secret put WS_PATH
wrangler secret put DNS_UPSTREAM
wrangler secret put PROXYIP
wrangler secret put SOCKS5
wrangler secret put HTTP_PROXY
```

Deploy:

```bash
wrangler deploy
```
