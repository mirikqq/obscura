## Stealth mode

```bash
obscura fetch https://example.com --stealth
obscura serve --stealth
obscura scrape url1 url2 --stealth
obscura mcp --stealth
```

`--stealth` is a global flag, so it works before or after the subcommand and applies to `fetch`, `serve`, `scrape`, and `mcp`. In a `scrape` run each worker inherits it.

What `--stealth` changes:

- Uses the wreq HTTP client with browser-matching TLS fingerprints (ClientHello, ALPN, cipher order).
- Selects one validated browser identity and drives every surface from it: the TLS stack, the User-Agent, `navigator`, `screen`, the window chain, the audio sample rate and the timezone all come from the same profile, so they cannot contradict each other. The profile is rejected at startup if they do.
- Aligns that identity to the address the traffic actually leaves from, when a proxy is configured.
- Leaves the tracker blocklist off, so the request pattern matches an ordinary browser. Opt in with `OBSCURA_BLOCK_TRACKERS=1` when privacy or bandwidth matters more (see [Environment variables](Environment-variables.md)).
- Bundles webpki roots instead of relying on the system store.

Requires a build that includes the stealth feature. Use a `-stealth` archive
with rendering or a `-no-render-stealth` archive without it. To build the
rendering variant yourself:

```bash
cargo build --release -p obscura-cli --bins --features render,stealth
```

Omit rendering with `cargo build --release -p obscura-cli --bins --no-default-features --features stealth`.

## What stealth handles

- Basic bot detection that checks TLS fingerprint or User-Agent.
- Sites that rely on third-party analytics being reachable.

## What stealth does not handle

- Cloudflare interactive challenges.
- Datadome and Akamai bot manager active challenges.
- CAPTCHAs.
- IP-based rate limiting (use proxies).

## Proxies

HTTP proxy:

```bash
obscura fetch https://example.com --proxy http://proxy.example.com:8080
obscura serve --proxy http://proxy.example.com:8080
```

With auth:

```bash
obscura fetch https://example.com --proxy http://user:pass@proxy.example.com:8080
```

SOCKS5:

```bash
obscura fetch https://example.com --proxy socks5://proxy.example.com:1080
```

## Custom User-Agent

```bash
obscura fetch https://example.com --user-agent "Mozilla/5.0 (...) ..."
obscura serve --user-agent "Mozilla/5.0 (...) ..."
```

Default UA matches a recent Chrome on the build platform.

## Browser profile, timezone, and geolocation

With `--stealth`, the identity is one `StealthProfile` (crate `obscura-stealth`) covering the UA, `navigator`, `screen`, the window chain, client hints, the audio sample rate, the locale and the TLS stack. It is validated before use: a profile whose user agent, platform and handshake disagree is rejected rather than shipped, because the contradiction is what a site checks.

A single stable identity is used by default -- one address cycling through identities is itself a signal -- so anything else is opt-in:

```bash
OBSCURA_STEALTH_PROFILE=chrome_148_macos obscura serve   # pin a named preset
OBSCURA_STEALTH_PROFILE_FILE=my.yaml obscura serve       # load one from disk
OBSCURA_STEALTH_SEED=42 obscura serve                    # sample one, reproducibly
OBSCURA_STEALTH_SAMPLE=1 obscura serve                   # sample a fresh one
```

Sampled identities are drawn from a Bayesian network of observed fingerprints
(the Apify/BrowserForge dataset, via `veilus-fingerprint`), so the field
*combinations* are ones that occur in the wild rather than ones that merely
look plausible individually. Every sample still goes through the same
validation, and its TLS stack is selected from the captured stacks rather than
generated.

Without `--stealth`, the older `OBSCURA_PROFILE` / `OBSCURA_ROTATE_PROFILE` pool
still applies.

**WebGL:** `canvas.getContext('webgl')` returns `null`, so a page cannot read a
renderer string at all. The profile carries a full GPU catalog entry (renderer,
vendor, extension list, `getParameter` values) for when a WebGL surface exists,
but nothing reads it today.

### Timezone and geolocation from the exit IP

The timezone is set at ICU's default, so `Date` (the local getters, the
`Date(y, m, d)` constructor, `getTimezoneOffset`, `toString`) and
`Intl.DateTimeFormat` all read one zone and stay consistent, DST included. It
follows the profile, and `OBSCURA_TIMEZONE` overrides it:

```bash
OBSCURA_TIMEZONE=America/New_York obscura serve
```

When a proxy is configured, the identity is aligned to the address the traffic
actually leaves from, the way Camoufox does it: the exit IP is resolved against
a local MaxMind GeoLite2-City database, and its timezone and coordinates drive
the clock and `navigator.geolocation`. An exit in Stockholm reporting
`Europe/Paris` is the cheapest contradiction a risk engine can check, and it is
checked on nearly every request.

You supply the database. Obscura does not download one on its own initiative --
MaxMind needs a licence key, and pulling a binary database from a third-party
redistribution is a supply-chain choice that belongs to whoever runs the engine.
Point it at one you already have, or name a source to fetch from; a fetched copy
is cached under the per-user cache directory and refreshed every 30 days. With
neither set, the alignment falls back to the HTTP geolocation providers.

No lookup of any kind is made without a proxy:

```bash
OBSCURA_GEOIP_MMDB=/path/GeoLite2-City.mmdb   # use a database you already have
OBSCURA_GEOIP_URL=https://...                 # source to fetch it from (opt in)
OBSCURA_NO_GEOIP=1                            # skip the database, use HTTP providers
OBSCURA_NO_EGRESS=1                           # skip the alignment entirely
OBSCURA_ALIGN_EGRESS=1                        # align even without a proxy
OBSCURA_MATCH_LANG=1                          # also take the country's language
```

The language deliberately does *not* follow the address by default: English
reads as ordinary from anywhere, and a localised challenge page is unreadable
to whoever is driving the run.

`navigator.geolocation` coordinates can still be set directly, and should match
the timezone and proxy region:

```bash
OBSCURA_GEOLOCATION="40.7128,-74.0060" obscura serve
```

See [Environment variables](Environment-variables.md) for the full list.

## Combine

```bash
obscura serve \
  --stealth \
  --proxy http://user:pass@proxy.example.com:8080 \
  --user-agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ..."
```
