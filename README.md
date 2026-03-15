# cf-email-domain-decoy

A cryptic, minimal decoy landing page for **email-only domains** — built entirely on Cloudflare Workers (free tier).

If you own a domain purely for email (e.g., with ProtonMail, SimpleLogin, Fastmail), visitors to your domain currently see a Cloudflare error page or nothing at all. This Worker replaces that with a beautifully designed, intentionally cryptic page that reveals **zero information** about you — while silently fingerprinting every visitor and scoring them as human or bot.

```
┌──────────────────────────────────────────┐
│                                          │
│            ◇ Moroccan Pattern ◇          │
│          (CSS-only geometric art)        │
│                                          │
│        curiosity is noted.               │
│               ▮                          │
│                                          │
└──────────────────────────────────────────┘
```

## Why?

You have an email-only domain. Someone emails you and thinks *"let me check if they have a website"*. Or a bot scans your domain looking for vulnerabilities.

**Without this Worker:** They see a Cloudflare error page, which leaks that you have no origin server.

**With this Worker:** They see a dark, polished, intentionally cryptic page with a Moroccan geometric pattern and the message *"curiosity is noted."* — followed by a blinking cursor. No links. No names. No contact info. No JavaScript. Nothing to click. An aesthetic dead end.

Meanwhile, every request is silently fingerprinted and scored.

## Features

- **Zero JavaScript** — pure HTML + CSS. The blinking cursor uses CSS `@keyframes`
- **Zero external resources** — no fonts, no images, no CDNs, no tracking pixels
- **Zero PII exposure** — no names, no emails, no metadata, no tech stack clues
- **Bot fingerprinting** — scores every visitor 0-100 based on 15+ signals
- **ISP classification** — identifies residential, hosting, mobile, education, corporate visitors
- **Datacenter ASN detection** — flags 25 known datacenter providers (AWS, GCP, Azure, etc.)
- **Structured logging** — `console.log()` JSON per request, viewable via `wrangler tail` or Cloudflare dashboard (no KV needed)
- **Hardened security headers** — CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Every path returns the same page** — `/admin`, `/secret`, `/.env` all serve identical content with HTTP 200. Zero information about site structure
- **`/favicon.ico` returns 204** — prevents browser errors without leaking anything
- **Compatible with Cloudflare managed robots.txt** — route exclusion lets Cloudflare handle AI crawler directives natively

## Bot Scoring Signals

The Worker scores visitors based on:

| Signal | Score | Meaning |
|---|---|---|
| No User-Agent | +40 | Almost certainly a bot |
| Old TLS (1.0/1.1) | +30 | Outdated client, likely automated |
| Hosting/datacenter ISP | +25 | Not a human browsing from home |
| Known datacenter ASN | +20 | AWS, GCP, Azure, Hetzner, etc. |
| Fake browser UA (claims Chrome but missing `sec-ch-ua`) | +20 | Spoofed User-Agent |
| HTTP/1.0 | +20 | Ancient protocol |
| Few headers (<5) | +20 | Minimal request, likely scripted |
| No Accept-Language | +15 | Real browsers always send this |
| Short User-Agent (<20 chars) | +15 | Unusual for real browsers |
| Missing Sec-Fetch headers | +5 each | Modern browsers include these |
| Simple Accept-Language | +8 | No locale preferences |
| Residential ISP | -10 | Likely a real human |
| Mobile ISP | -5 | Likely a real human |

## Structured Log Output

Every non-static request is logged as JSON via `console.log()`:

```json
{
  "t": "2026-03-15T19:45:00.000Z",
  "p": "/admin",
  "m": "GET",
  "s": 85,
  "r": ["no-ua", "hosting-isp", "datacenter-asn", "few-headers"],
  "isp": "hosting",
  "asn": 14061,
  "org": "DigitalOcean, LLC",
  "co": "DE",
  "ci": "Frankfurt",
  "colo": "FRA",
  "tls": "TLSv1.3",
  "proto": "HTTP/2",
  "hc": 4,
  "ua": ""
}
```

View logs in real-time with:
```bash
wrangler tail my-domain-decoy
```

Or check **Workers > Logs** in the Cloudflare dashboard.

## Setup

### Prerequisites

- A domain managed by Cloudflare (free plan works)
- The domain is used for email only (no web hosting)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed (optional — you can also deploy via the Cloudflare API)

### Step 1: DNS Record

Create a proxied A record pointing to a dummy IP:

| Type | Name | Content | Proxy |
|---|---|---|---|
| A | `yourdomain.com` | `192.0.2.1` | Proxied (orange cloud) |

`192.0.2.1` is an [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation address — it goes nowhere. The proxied flag is required so Cloudflare intercepts the traffic and your Worker can handle it.

### Step 2: Deploy the Worker

**Option A: Wrangler CLI**

```bash
# Clone this repo
git clone https://github.com/yourusername/cf-email-domain-decoy.git
cd cf-email-domain-decoy

# Deploy
wrangler deploy
```

**Option B: Cloudflare Dashboard**

1. Go to **Workers & Pages** > **Create Worker**
2. Name it (e.g., `my-domain-decoy`)
3. Paste the contents of `worker.js`
4. Click **Deploy**

### Step 3: Worker Routes

Create two routes on your zone:

| Route | Worker |
|---|---|
| `yourdomain.com/robots.txt` | **None** (allows Cloudflare managed robots.txt to serve) |
| `yourdomain.com/*` | Your deployed Worker |

The `/robots.txt` exclusion is important — it lets Cloudflare's [managed robots.txt](https://developers.cloudflare.com/bots/additional-configurations/managed-robots-txt/) handle AI crawler directives and Content Signals natively.

### Step 4: Recommended Cloudflare Settings

These are optional but recommended for maximum security on an email-only domain:

| Setting | Value | Why |
|---|---|---|
| SSL/TLS | Full (strict) | Validates origin certificate |
| Min TLS Version | 1.2 | Blocks outdated clients |
| Always Use HTTPS | On | Redirects HTTP to HTTPS |
| HSTS | Enabled, 1 year, include subdomains, preload | Forces HTTPS |
| Security Level | High | More aggressive challenge rate |
| AI Bots Protection | Block | Blocks AI crawlers at the edge |
| Bot Fight Mode | On | Challenges automated traffic |
| Managed robots.txt | On | AI crawler directives + Content Signals |

## Architecture

```
Visitor → Cloudflare Edge
  ├─ Firewall Rules → Block/Challenge known bad actors
  ├─ Bot Fight Mode → Challenge automated traffic
  ├─ AI Labyrinth → Trap non-compliant AI crawlers
  ├─ Managed robots.txt → AI crawler directives
  ├─ /robots.txt → Served by Cloudflare (not the Worker)
  └─ All other paths → Worker
       ├─ Fingerprint request (TLS, headers, ASN, ISP)
       ├─ Calculate bot score (0-100)
       ├─ console.log() structured JSON
       ├─ /favicon.ico → 204 No Content
       └─ Everything else → Decoy page
```

## Cost

**Free.** Everything runs within Cloudflare's free tier:

| Resource | Usage | Free Limit |
|---|---|---|
| Worker requests | Variable | 100,000/day |
| Worker CPU time | <1ms per request | 10ms/request |
| KV | Not used | N/A |
| External calls | None | N/A |

## Customization

### Change the message

Find this line in `worker.js` and replace the text:

```html
<div class="msg">curiosity is noted.</div>
```

Some alternatives:
- `you were not expected.`
- `there is nothing here for you.`
- `this domain is not abandoned.`
- `▮` (just the cursor, no message)

### Change the visual style

The geometric pattern is pure CSS in the `DECOY_HTML` constant. Adjust the colors (`#1a1a1a`, `#151515`, `#0a0a0a`) or the `background-size` to change the pattern density.

### Disable bot fingerprinting

If you just want the static page without logging, remove the `fingerprintRequest()`, `calculateBotScore()`, and `console.log()` sections. The Worker then becomes a simple HTML responder.

## What This Is NOT

- **Not a WAF** — it doesn't block anything. Your Cloudflare firewall rules do that.
- **Not email security** — email goes directly to your mail provider via MX records, bypassing Cloudflare entirely. Your SPF, DKIM, and DMARC records handle email security.
- **Not a honeypot that captures credentials** — there are no forms, no inputs, no login pages. It's purely observational.

## Complementary Tools

For a complete email-only domain security setup:

- [Cloudflare DMARC Management](https://developers.cloudflare.com/dmarc-management/) — free DMARC reporting
- [Cloudflare AI Crawl Control](https://developers.cloudflare.com/ai-crawl-control/) — monitor and block AI crawlers
- [Cloudflare AI Labyrinth](https://developers.cloudflare.com/bots/additional-configurations/ai-labyrinth/) — trap non-compliant crawlers in an endless maze

## License

MIT
