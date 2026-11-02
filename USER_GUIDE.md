# User Guide — Domain Threat Investigation Platform

This guide explains how to use the platform, how evidence is collected for each investigation, what each piece of evidence means, and how to interpret the analyst reports — with real-world examples throughout.

---

## Table of Contents

1. [What This Platform Does](#1-what-this-platform-does)
2. [Submitting an Investigation](#2-submitting-an-investigation)
3. [Understanding the Investigation Pipeline](#3-understanding-the-investigation-pipeline)
4. [How Evidence Is Collected — With Examples](#4-how-evidence-is-collected--with-examples)
   - [DNS Records](#41-dns-records)
   - [HTTP / Web Content](#42-http--web-content)
   - [TLS Certificate](#43-tls-certificate)
   - [WHOIS Registration](#44-whois-registration)
   - [ASN & Hosting](#45-asn--hosting)
   - [Threat Intelligence (Intel)](#46-threat-intelligence-intel)
   - [VirusTotal](#47-virustotal)
   - [Threat Feeds](#48-threat-feeds)
   - [Email Security](#49-email-security)
   - [Domain Similarity (Typosquatting)](#410-domain-similarity-typosquatting)
   - [Visual Comparison (Screenshot)](#411-visual-comparison-screenshot)
   - [Redirect Analysis](#412-redirect-analysis)
   - [JavaScript Sandbox](#413-javascript-sandbox)
   - [Infrastructure Pivot](#414-infrastructure-pivot)
5. [Investigative Signals — What They Mean](#5-investigative-signals--what-they-mean)
6. [Reading the Report](#6-reading-the-report)
   - [Executive Summary Tab](#61-executive-summary-tab)
   - [Technical Evidence Tab](#62-technical-evidence-tab)
   - [Findings Tab](#63-findings-tab)
   - [Indicators Tab](#64-indicators-tab)
   - [Signals & Gaps Tab](#65-signals--gaps-tab)
   - [Infrastructure Tab](#66-infrastructure-tab)
7. [Classification — What Each Level Means](#7-classification--what-each-level-means)
8. [Batch Investigations](#8-batch-investigations)
9. [Domain Watchlist](#9-domain-watchlist)
10. [IP Lookup Tool](#10-ip-lookup-tool)
11. [Dashboard & Analytics](#11-dashboard--analytics)
12. [Exporting Reports](#12-exporting-reports)
13. [Common Investigation Scenarios](#13-common-investigation-scenarios)
14. [Tips for Analysts](#14-tips-for-analysts)

---

## 1. What This Platform Does

The platform automates domain threat investigations. Instead of manually querying DNS, WHOIS, VirusTotal, crt.sh, and AbuseIPDB — then trying to correlate the results — you submit a domain and the platform:

1. Runs **10+ evidence collectors in parallel** (DNS, HTTP, TLS, WHOIS, ASN, threat feeds, etc.)
2. Computes **investigative signals** — structured clues about anomalies
3. Sends everything to **Claude AI**, which applies a strict 5-step analytical methodology
4. Returns a **classified report** (benign / suspicious / malicious / inconclusive) with:
   - Risk score (0-100)
   - Analyst findings mapped to MITRE ATT&CK techniques
   - Indicators of Compromise (IOCs)
   - Specific SOC actions

The entire process typically completes in 60-90 seconds.

---

## 2. Submitting an Investigation

### Basic Investigation

Navigate to the home page and enter a domain:

```
Domain: paypa1-secure.com
```

Click **Investigate**. The platform immediately begins collecting evidence.

### Advanced Options

Expand the advanced options panel to enable additional analysis:

| Option | Description | When to Use |
|---|---|---|
| **Client Domain** | Your organization's legitimate domain (e.g., `paypal.com`) | When you suspect the investigated domain is impersonating your brand |
| **Specific URL** | A full URL to screenshot instead of the domain root | When phishing content is at a specific path |
| **Reference Image** | Upload a screenshot of your legitimate site | When you want visual comparison but the client site is internal/behind auth |
| **Investigation Notes** | Free-text context for the AI analyst | SOC ticket notes, user reports, incident context |
| **SOC Ticket Notes** | Structured notes from your ticketing system | Attach ticket summary for the analyst |
| **Additional Context** | Any other relevant information | Previous findings, related incidents |

**Example — brand impersonation investigation:**

```
Domain:         paypa1-secure.com
Client Domain:  paypal.com
Notes:          User reported receiving phishing email with this link.
                Sender claimed to be PayPal support. Email originated from
                IP 198.51.100.45 which is outside PayPal's known infrastructure.
```

With `client_domain` set, the platform additionally:
- Computes a **domain similarity score** (typosquatting analysis)
- Captures **screenshots of both domains** and compares them visually
- Includes a side-by-side visual comparison in the report

---

## 3. Understanding the Investigation Pipeline

After submission, a real-time progress timeline shows each stage:

```
[✓] DNS           — 1.2s   Resolved A/MX/NS/TXT records
[✓] HTTP          — 2.8s   Fetched page, detected login form
[✓] TLS           — 0.9s   Certificate details extracted
[✓] WHOIS         — 3.1s   Registration info retrieved
[✓] ASN           — 1.4s   Hosting provider identified
[✓] Intel         — 4.2s   crt.sh + blocklists checked
[✓] VirusTotal    — 2.3s   5 vendors flagged as malicious
[✓] Threat Feeds  — 1.8s   AbuseIPDB: score 87
[⟳] AI Analyst    — ...    Analyzing 200+ evidence fields
```

Each tick marks a collector completing. If a collector fails (timeout, API key missing), it shows ✗ and the analyst is informed of the data gap — it doesn't stop the investigation.

---

## 4. How Evidence Is Collected — With Examples

### 4.1 DNS Records

**What it collects:** All DNS record types for the domain using three public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9).

**Why it matters:** DNS is the authoritative record of what servers a domain uses. Mismatches, missing records, and unusual configurations are meaningful signals.

**Example — legitimate domain:**
```json
{
  "a":    ["93.184.216.34"],
  "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
  "mx":   [{"host": "mail.example.com", "priority": 10}],
  "ns":   ["a.iana-servers.net", "b.iana-servers.net"],
  "txt":  ["v=spf1 -all"],
  "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
  "spf":   "v=spf1 -all"
}
```

**Example — suspicious domain:**
```json
{
  "a":    ["198.51.100.5"],
  "ns":   ["ns1.somebulkhost.net", "ns2.somebulkhost.net"],
  "txt":  [],
  "dmarc": null,
  "spf":   null,
  "mx":   []
}
```

What's notable: no MX (doesn't receive email), no SPF or DMARC (can be spoofed as a sender), nameservers point to bulk hosting infrastructure.

---

### 4.2 HTTP / Web Content

**What it collects:** Makes an HTTPS request (falls back to HTTP) and analyzes the response.

**Captures:**
- Redirect chain (every hop, status code, server header)
- Page title
- Whether a login/password form is present
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Server technology fingerprint
- Brand impersonation phrases in the page body
- Phishing kit code patterns
- External resources (JavaScript, images, fonts from other domains)
- Favicon hash (MurmurHash3)

**Example — phishing page:**
```json
{
  "reachable": true,
  "status_code": 200,
  "final_url": "https://paypa1-secure.com/login",
  "page_title": "PayPal - Log in to your account",
  "has_login_form": true,
  "redirect_chain": [
    {"url": "http://paypa1-secure.com", "status_code": 301},
    {"url": "https://paypa1-secure.com/login", "status_code": 200}
  ],
  "security_headers": {
    "Strict-Transport-Security": null,
    "Content-Security-Policy": null,
    "X-Frame-Options": null
  },
  "brand_indicators": [
    "log in to your account",
    "verify your account"
  ],
  "phishing_indicators": [
    "atob() call — Base64 decoding",
    "eval() call — potential JS obfuscation"
  ],
  "server": "nginx/1.14.0",
  "external_resources": [
    "cdn.paypal-static.com",
    "c.paypalobjects.com"
  ]
}
```

**What this tells us:** The page title impersonates PayPal, contains a login form, uses obfuscation techniques (`eval`, `atob`), and has no security headers. External resources pull from PayPal's legitimate CDN to make the page look authentic.

---

### 4.3 TLS Certificate

**What it collects:** Performs a TLS handshake on port 443 and extracts the full certificate.

**Captures:**
- Issuer (Certificate Authority name, organization)
- Subject (what domain the cert is for)
- Subject Alternative Names (all domains the cert covers)
- Validity period (not_before / not_after) and days remaining
- SHA-256 fingerprint
- Whether it is self-signed
- Whether it uses a wildcard (`*.domain.com`)
- Chain length

**Example — Let's Encrypt on a fresh phishing domain:**
```json
{
  "issuer_cn": "R10",
  "issuer_org": "Let's Encrypt",
  "subject_cn": "paypa1-secure.com",
  "sans": ["paypa1-secure.com", "www.paypa1-secure.com"],
  "not_before": "2026-02-20T00:00:00",
  "not_after":  "2026-05-21T00:00:00",
  "valid_days_remaining": 85,
  "sha256_fingerprint": "3A:9F:...",
  "is_self_signed": false,
  "is_wildcard": false,
  "chain_length": 2
}
```

**What this tells us:** The certificate is brand new (issued 5 days ago), uses a free CA (Let's Encrypt — used by legitimate and malicious sites equally). Free CAs are **not** a malicious indicator on their own, but the recency combined with a brand-new domain reinforces the infrastructure_age signal.

---

### 4.4 WHOIS Registration

**What it collects:** Queries the WHOIS database for domain registration information.

**Captures:**
- Registrar name
- Creation, expiration, and updated dates
- Domain age in days (computed)
- Whether privacy protection is active
- Registrant organization, country, email (when not redacted)

**Example — newly registered domain with privacy:**
```json
{
  "registrar": "Namecheap, Inc.",
  "creation_date": "2026-02-18T00:00:00",
  "expiration_date": "2027-02-18T00:00:00",
  "domain_age_days": 7,
  "privacy_protected": true,
  "registrant_org": null,
  "registrant_country": null,
  "registrant_email": "proxy@privacy.namecheap.com",
  "name_servers": ["ns1.somebulkhost.net", "ns2.somebulkhost.net"]
}
```

**What this tells us:** The domain is 7 days old (very young), privacy-protected (registrant hidden), registered at Namecheap (common for both legitimate and malicious domains), and expires in 1 year. Young domain age alone is not proof of malice — many legitimate sites are new — but combined with other signals it reinforces a suspicious pattern.

---

### 4.5 ASN & Hosting

**What it collects:** Resolves the domain's IP address, then queries ip-api.com for geolocation and hosting information.

**Captures:**
- ASN number and organization (e.g., `AS16509 Amazon.com`)
- Country, city
- ISP name
- Reverse DNS hostname
- Whether the host is a CDN (Cloudflare, Akamai, Fastly, CloudFront, Azure CDN)
- Hosting provider detection (AWS, GCP, Azure, DigitalOcean, Hetzner, etc.)

**Example — cheap VPS hosting:**
```json
{
  "ip": "198.51.100.5",
  "asn": "AS47583",
  "asn_org": "Hostinger International Limited",
  "country": "Netherlands",
  "city": "Amsterdam",
  "isp": "Hostinger International Limited",
  "reverse_dns": null,
  "is_cdn": false,
  "is_cloud": false,
  "hosting_provider": "Hostinger"
}
```

**Example — Cloudflare-protected legitimate domain:**
```json
{
  "ip": "104.21.45.67",
  "asn": "AS13335",
  "asn_org": "Cloudflare, Inc.",
  "country": "United States",
  "is_cdn": true,
  "is_cloud": false,
  "hosting_provider": "Cloudflare"
}
```

**What this tells us:** CDN hosting (Cloudflare, Akamai) is neutral — both legitimate businesses and phishing sites use it. Cheap VPS providers (Hostinger, Contabo, OVH) with no reverse DNS are worth noting but not definitive.

---

### 4.6 Threat Intelligence (Intel)

**What it collects:** Queries certificate transparency logs and DNS-based blocklists.

**Sources:**
- **crt.sh** — Certificate Transparency: all certificates ever issued for the domain
- **SURBL, Spamhaus DBL, URIBL** — DNS-based URL reputation blocklists
- **abuse.ch URLhaus** — Malware distribution URL database

**Example — clean domain:**
```json
{
  "related_certs": [
    {
      "serial_number": "04:AB:...",
      "name_value": "*.mycompany.com\nmycompany.com",
      "issuer_name": "DigiCert TLS RSA SHA256 2020 CA1",
      "not_before": "2024-01-15",
      "not_after": "2025-01-15"
    }
  ],
  "discovered_subdomains": ["www", "api", "mail", "blog"],
  "blocklist_hits": [],
  "urlhaus_urls": []
}
```

**Example — domain on blocklist:**
```json
{
  "related_certs": [
    {
      "serial_number": "07:FF:...",
      "issuer_name": "R10",
      "not_before": "2026-02-18",
      "not_after": "2026-05-19"
    }
  ],
  "discovered_subdomains": [],
  "blocklist_hits": ["surbl.org", "spamhaus-dbl"],
  "urlhaus_urls": [
    {
      "url": "https://paypa1-secure.com/steal.php",
      "threat": "phishing",
      "date_added": "2026-02-19"
    }
  ]
}
```

**What this tells us:** URLhaus listing with `steal.php` path is a strong malicious indicator. Blocklist hits from SURBL and Spamhaus DBL confirm the domain has been flagged by reputation systems. This, combined with the HTTP and WHOIS evidence, establishes a clear pattern.

---

### 4.7 VirusTotal

**What it collects:** Queries the VirusTotal API for vendor analysis results on the domain.

**Requires:** `VIRUSTOTAL_API_KEY` in `.env`

**Captures:**
- How many vendors flagged it as malicious, suspicious, harmless, or undetected
- Which specific vendors flagged it and their verdict
- Domain categories (content categorization)
- Popularity rank data

**Example — malicious domain:**
```json
{
  "malicious": 8,
  "suspicious": 2,
  "harmless": 52,
  "undetected": 12,
  "vendor_results": {
    "Fortinet": "Phishing",
    "Kaspersky": "HEUR:Trojan.Script.Phisher",
    "ESET": "Phishing",
    "Avast": "Phishing",
    "BitDefender": "Phishing",
    "Google Safebrowsing": "Phishing"
  },
  "categories": {
    "Forcepoint ThreatSeeker": "phishing and other frauds"
  },
  "last_analysis_date": "2026-02-24T12:00:00"
}
```

**Note for analysts:** VT results are treated as **signals, not conclusions**. A domain can have 0 VT detections and still be malicious (new, not yet caught). Conversely, a domain can have old VT flags for content that has since changed. The analyst AI applies the 90-day recency rule — findings older than 90 days carry reduced weight.

---

### 4.8 Threat Feeds

**What it collects:** Enriches the domain's resolved IP against multiple threat feeds.

**Sources:**
- **AbuseIPDB** — IP abuse confidence score (0-100) based on community reports
- **PhishTank** — Known verified phishing URL database
- **ThreatFox (abuse.ch)** — Malware C2 and IOC database
- **OpenPhish** — Community phishing feed

**Example — high-abuse IP:**
```json
{
  "abuseipdb": {
    "ip": "198.51.100.5",
    "abuse_confidence_score": 87,
    "total_reports": 142,
    "last_reported_at": "2026-02-24T08:15:00Z",
    "isp": "Hostinger International Limited",
    "usage_type": "Data Center/Web Hosting/Transit",
    "categories": [14, 21],
    "country_code": "NL"
  },
  "phishtank": {
    "in_database": true,
    "verified": true,
    "target_brand": "PayPal",
    "verified_at": "2026-02-20T10:30:00Z"
  },
  "threatfox_matches": [],
  "openphish_listed": true,
  "feeds_checked": ["abuseipdb", "phishtank", "threatfox", "openphish"],
  "feeds_skipped": []
}
```

**AbuseIPDB categories (common ones):**

| Code | Meaning |
|---|---|
| 14 | Port Scan |
| 18 | Brute Force |
| 21 | Web App Attack |
| 10 | SQL Injection |
| 7  | Data Breach/Leak |
| 20 | DDoS |

**What this tells us:** A score of 87 with 142 reports, a PhishTank verified match targeting PayPal, and OpenPhish listing together constitute overwhelming external confirmation of malicious intent.

---

### 4.9 Email Security

**What it collects:** Analyzes the domain's email authentication configuration.

**Why it matters for phishing:** Attackers often use domains with weak email security to send spoofed emails. A domain that can spoof email combined with other phishing indicators is a stronger pattern.

**Checks performed:**
- DMARC record (policy: `none` / `quarantine` / `reject`, percentage, alignment)
- SPF record (all qualifier: `-all` strict / `~all` softfail / `+all` permissive / `?all` neutral)
- DKIM selector probing (10 common selectors tested: `default`, `google`, `selector1`, `mail`, `dkim`, etc.)
- MX record blocklist check
- Computed `spoofability_score` and `email_security_score`

**Example — domain with no email security:**
```json
{
  "spf_record": null,
  "dmarc_record": null,
  "dkim_selectors_found": [],
  "mx_records": [],
  "spoofability_score": "high",
  "email_security_score": 5,
  "dmarc_policy": null,
  "spf_all_qualifier": null
}
```

**Example — well-configured domain:**
```json
{
  "spf_record": "v=spf1 include:_spf.google.com -all",
  "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@company.com; pct=100",
  "dkim_selectors_found": ["google", "selector1"],
  "spoofability_score": "low",
  "email_security_score": 92,
  "dmarc_policy": "reject",
  "spf_all_qualifier": "-all"
}
```

**Interpreting spoofability:**

| Level | Meaning |
|---|---|
| `low` | Domain is well-protected against email spoofing |
| `medium` | Partial protection — spoofed mail may sometimes be delivered |
| `high` | No meaningful protection — attackers can send email appearing to come from this domain |

**Important:** Weak email security alone is **not** a malicious indicator. Many legitimate domains have poor email hygiene. But combined with brand impersonation evidence, it strengthens a phishing hypothesis because phishers benefit from spoofable sender domains.

---

### 4.10 Domain Similarity (Typosquatting)

**What it collects:** Algorithmic comparison between the investigated domain and your client domain (only when `client_domain` is provided).

**Techniques detected:**

| Technique | Example | Description |
|---|---|---|
| **Character omission** | `paypa.com` | Missing letter `l` from `paypal.com` |
| **Character insertion** | `paypaall.com` | Extra `a` inserted |
| **Character transposition** | `paypla.com` | Letters `a` and `l` swapped |
| **Character replacement** | `payp4l.com` | Digit `4` replaces `a` |
| **TLD swap** | `paypal.net` | Different top-level domain |
| **Hyphenation** | `pay-pal.com` | Hyphen added |
| **Subdomain impersonation** | `paypal.evil.com` | Legitimate name as subdomain |
| **Combosquatting** | `paypal-secure.com` | Legitimate name + keyword |

**Homoglyph detection** — visually confusable characters:
- Latin `o` ↔ Cyrillic `о` (looks identical)
- Latin `a` ↔ Cyrillic `а`
- `rn` ↔ `m` (in certain fonts)
- `1` ↔ `l` ↔ `I`
- `0` ↔ `O`

**Example output:**
```json
{
  "client_domain": "paypal.com",
  "investigated_domain": "paypa1-secure.com",
  "levenshtein_distance": 7,
  "overall_similarity_score": 73,
  "detected_techniques": ["character_replacement", "combosquatting"],
  "homoglyph_matches": [],
  "is_typosquat": true
}
```

**Score interpretation:**

| Score | Interpretation |
|---|---|
| 0-30 | Low similarity — probably unrelated domain |
| 31-60 | Moderate similarity — investigate alongside other signals |
| 61-80 | High similarity — significant impersonation indicator |
| 81-100 | Very high similarity — strong typosquatting evidence |

**Note:** Domain similarity is **computed evidence** (algorithmic, not subjective). Unlike a human eyeballing a domain name, these are measurable metrics. The AI analyst treats them accordingly — but still requires other signals to classify as malicious.

---

### 4.11 Visual Comparison (Screenshot)

**What it collects:** Screenshots of both the investigated domain and your client domain, then computes image similarity.

**Process:**
1. Playwright (headless Chromium, 1280×800) captures a screenshot of the investigated domain
2. Playwright captures a screenshot of the client domain (or loads your uploaded reference image)
3. Perceptual hash (aHash + dHash) computed for both screenshots
4. Colour histogram similarity (Pearson correlation) computed
5. Weighted composite score: `60% perceptual hash + 40% histogram`

**Example output:**
```json
{
  "client_domain": "paypal.com",
  "investigated_capture_error": null,
  "client_capture_error": null,
  "phash_similarity": 0.87,
  "histogram_similarity": 0.79,
  "overall_visual_similarity": 0.84,
  "is_visual_clone": true,
  "is_partial_clone": false,
  "reference_image_used": false
}
```

**Classification thresholds:**

| Threshold | Classification | Meaning |
|---|---|---|
| ≥ 0.80 | `is_visual_clone = true` | Page appears nearly identical to client site |
| 0.50–0.79 | `is_partial_clone = true` | Significant visual similarities |
| < 0.50 | Distinct | Pages look different |

**Example — visual clone detected:**

> Investigated domain screenshot shows the same PayPal blue header, logo placement, and login form layout as the genuine paypal.com. Visual similarity: 84%. This constitutes strong evidence of page cloning.

**Note:** A visual clone finding alone is not sufficient for "malicious" classification. It must be combined with other indicators (domain similarity, login form, young domain) to pass the attacker necessity test.

---

### 4.12 Redirect Analysis

**What it collects:** Probes the domain with three different User-Agents to detect cloaking or evasion.

**User-Agents tested:**
1. Desktop Chrome browser
2. Googlebot
3. Mobile Chrome (Android)

**What true cloaking looks like:**
```json
{
  "cloaking_detected": true,
  "browser_final_url": "https://paypa1-secure.com/login",
  "googlebot_final_url": "https://www.google.com",
  "mobile_final_url": "https://paypa1-secure.com/login",
  "max_chain_length": 2,
  "evasion_techniques": ["ua_cloaking"]
}
```

This shows the domain serves a phishing page to browsers but redirects bots to Google — a classic evasion technique to avoid automated detection.

**What NOT to treat as suspicious:**

Content hash differences between User-Agents are **completely normal** for legitimate sites. A news website will serve different HTML to Googlebot (no ads, cleaner markup) than to mobile browsers (responsive layout). This is standard web development practice and is **not flagged as cloaking**.

---

### 4.13 JavaScript Sandbox

**What it collects:** Runs the domain in a Playwright browser with network interception enabled to observe JavaScript behavior.

**Captures:**
- All network requests (total count, external domain count)
- POST endpoint analysis — URL, parameters, and whether it looks like a credential form
- Browser fingerprinting API calls (canvas, WebGL, AudioContext)
- Tracking pixels (1×1 images)
- WebSocket connections
- Data exfiltration indicators

**Example — credential harvesting:**
```json
{
  "total_requests": 43,
  "external_requests": 12,
  "post_endpoints": [
    {
      "url": "https://harvest-data.xyz/collect.php",
      "method": "POST",
      "is_credential_form": true,
      "parameters": ["email", "password", "session_token"]
    }
  ],
  "fingerprinting_apis": ["canvas", "navigator.userAgent"],
  "tracking_pixels": ["https://fb.com/tr?..."],
  "websocket_connections": []
}
```

**The critical finding here:** The page POSTs login credentials to `harvest-data.xyz` — a completely different domain from the investigated site. This is the **only strong malicious indicator** from JS analysis. Everything else (fingerprinting APIs, tracking pixels, WebSocket connections) is standard on legitimate commercial websites.

---

### 4.14 Infrastructure Pivot

**What it collects:** Discovers other domains sharing the same infrastructure.

**Sources:**
- **HackerTarget** reverse IP lookup (free API): lists all domains hosted on the same IP
- Internal database: groups domains sharing nameservers (NS clustering)
- Internal database: finds domains with same registrar + registrant organization

**Example:**
```json
{
  "reverse_ip": [
    {
      "ip": "198.51.100.5",
      "domains": ["paypa1-secure.com", "amaz0n-login.net", "netf1ix-account.com", "..."],
      "total_domains": 47
    }
  ],
  "ns_clusters": [],
  "registrant_pivots": [],
  "total_related_domains": 47,
  "shared_hosting_detected": true
}
```

**What this tells us:** 47 domains on the same IP, many with similar impersonation patterns (`amaz0n-login.net`, `netf1ix-account.com`). This is consistent with a single threat actor running a phishing campaign from one host. This is pivotable intelligence — you can submit each co-hosted domain for investigation.

---

## 5. Investigative Signals — What They Mean

Signals are **pre-computed clues** surfaced before the AI analyst runs. They are listed in the **Signals & Gaps** tab of every report.

| Signal | Severity | What It Means |
|---|---|---|
| `sig_very_young_domain` | High | Domain < 7 days old — registered this week |
| `sig_young_domain` | Medium | Domain < 30 days old |
| `sig_whois_privacy` | Info | WHOIS registration hidden behind privacy proxy |
| `sig_self_signed` | Medium | TLS certificate not issued by a public CA |
| `sig_free_cert` | Info | Uses Let's Encrypt or ZeroSSL (used by everyone) |
| `sig_login_form` | Info | Page contains a password input field |
| `sig_phishing_indicators` | High | `eval()`, `atob()`, Telegram Bot API detected in page source |
| `sig_brand_impersonation` | Medium | "Verify your account", "Account suspended" found in page |
| `sig_no_dmarc` | Low | Domain can be spoofed in email sender |
| `sig_spf_permissive` | High | Any server can send email as this domain (`+all`) |
| `sig_mx_blocklisted` | High | Mail server is on a blocklist |
| `sig_blocklist_hit` | High | Domain in SURBL, Spamhaus, or URIBL |
| `sig_urlhaus_listed` | Critical | Domain is distributing malware (URLhaus confirmed) |
| `sig_vt_malicious` | High | VirusTotal vendors flagged this domain |
| `sig_abuseipdb_high` | High | IP abuse score ≥75 |
| `sig_phishtank_match` | Critical | Verified phishing URL in PhishTank database |
| `sig_typosquatting_detected` | High | Matches client domain via typosquatting techniques |
| `sig_visual_clone` | Critical | Screenshots show ≥80% visual similarity to client domain |
| `sig_cert_burst` | Medium | 5+ certificates issued in 7 days (rapid cert rotation) |

**Key insight:** No single signal determines classification. The AI analyst weighs all signals together and applies the attacker necessity test. A login form + young domain + high AbuseIPDB score + visual clone is a very different situation than just a login form on a young domain.

---

## 6. Reading the Report

### 6.1 Executive Summary Tab

The first tab gives you the headline findings:

- **Classification badge** — benign / suspicious / malicious / inconclusive (color-coded)
- **Risk score** — 0-100 (≥75 = malicious, 50-74 = suspicious, 25-49 = benign with concerns, <25 = clean)
- **Confidence** — low / medium / high
- **Primary reasoning** — one-paragraph core analytical argument
- **Legitimate explanation** — best-case scenario for all evidence
- **Malicious explanation** — most likely attack scenario for all evidence
- **Recommended SOC action** — monitor / investigate / block / hunt

**Example executive summary (malicious case):**

> **Classification: MALICIOUS** | **Confidence: HIGH** | **Risk Score: 91**
>
> *Primary reasoning:* The investigated domain paypa1-secure.com exhibits a convergent pattern of indicators that require an attacker-controlled explanation. The domain is 7 days old, registered with privacy protection, and resolves to an IP hosting 47 similar impersonation domains. The page visually clones PayPal's login interface (84% similarity) and contains JavaScript that exfiltrates credentials via POST to harvest-data.xyz. PhishTank confirms this as a verified phishing URL targeting PayPal, issued 5 days after domain registration. No legitimate service would combine all these characteristics.
>
> **Recommended action: BLOCK**

---

### 6.2 Technical Evidence Tab

Shows the raw collector output in structured panels. Each collector's results are displayed with:

- Key findings highlighted
- Data presented in readable tables
- Error or data gap noted where collection failed

Sections in this tab:
- DNS records table
- HTTP response details (redirect chain, headers, detected content)
- TLS certificate viewer
- WHOIS registration details
- Hosting & ASN details
- Intel findings (crt.sh, blocklists)
- VirusTotal vendor results
- Threat feeds (AbuseIPDB gauge, PhishTank results)
- Email security analysis
- Domain similarity chart (if client_domain provided)
- Screenshot comparison (side-by-side, if visual comparison ran)
- Redirect analysis results
- JavaScript sandbox findings
- Infrastructure pivot (co-hosted domains)
- Certificate timeline

---

### 6.3 Findings Tab

Analyst-generated findings, each with:

- **Severity badge** — info / low / medium / high / critical
- **Description** — detailed explanation with evidence references
- **MITRE ATT&CK technique** — mapped technique ID and name
- **Evidence references** — specific field paths in the evidence object

**Example findings for the phishing scenario:**

| Severity | Finding | ATT&CK |
|---|---|---|
| Critical | Visual clone of PayPal login interface detected (84% similarity) | T1036.005 — Masquerading: Match Legitimate Name |
| Critical | Credential exfiltration via POST to external domain harvest-data.xyz | T1056.003 — Input Capture: Web Portal Capture |
| High | Domain registered 7 days ago — consistent with phishing campaign infrastructure | T1583.001 — Acquire Infrastructure: Domains |
| High | JavaScript obfuscation via eval() and atob() encoding | T1608.005 — Stage Capabilities: Link Target |
| High | PhishTank verified phishing URL targeting PayPal | T1566.002 — Phishing: Spearphishing Link |
| Medium | No email security (DMARC/SPF absent) — domain can spoof emails | T1598 — Phishing for Information |

The MITRE ATT&CK tab within Findings shows a visual coverage map across all 14 tactics, highlighting which techniques are present.

---

### 6.4 Indicators Tab

Extracted IOCs ready for use in SIEM/SOAR/blocklist tools:

| Type | Value | Context | Confidence |
|---|---|---|---|
| domain | paypa1-secure.com | Phishing domain impersonating PayPal | High |
| ip | 198.51.100.5 | Hosting IP — 47 co-hosted phishing domains | High |
| url | https://paypa1-secure.com/login | Phishing landing page | High |
| url | https://harvest-data.xyz/collect.php | Credential exfiltration endpoint | High |
| domain | harvest-data.xyz | Credential collection backend | High |

---

### 6.5 Signals & Gaps Tab

Lists all pre-computed signals (what triggered investigation flags) and data gaps (what couldn't be collected).

**Data gap example:**
```
Field:  whois.registrant_email
Reason: WHOIS privacy protection redacts registrant contact details
Impact: Cannot attribute domain registration to a known threat actor or
        correlate with other domains registered by the same person
```

Data gaps are important — they tell you what additional investigation steps might yield results (e.g., a subpoena to the registrar, passive DNS correlation).

---

### 6.6 Infrastructure Tab

Shows the infrastructure context:

- **Pivot points** — IP addresses, nameservers, ASN, registrar, certificate SANs that can be used to find related infrastructure
- **Co-hosted domains** — full list of domains on the same IP (searchable, with copy-all)
- **Related investigations** — other domains already investigated that share infrastructure with this one

This tab is most valuable for **campaign attribution** — if multiple phishing domains share the same IP and nameservers, they are likely operated by the same threat actor.

---

## 7. Classification — What Each Level Means

| Classification | Risk Score Range | SOC Action | Meaning |
|---|---|---|---|
| **Malicious** | 75-100 | Block / Hunt | Evidence requires an attacker-controlled explanation. Credential harvesting, verified phishing, C2 infrastructure. |
| **Suspicious** | 40-74 | Investigate | Unusual behavior present but a legitimate explanation isn't ruled out. Warrants deeper investigation. |
| **Benign** | 0-39 | Monitor | All evidence explained by legitimate service operation. May still warrant periodic re-checking. |
| **Inconclusive** | — | Investigate | Insufficient evidence to distinguish legitimate from malicious. Specific data gaps are listed. |

**The attacker necessity test:** The AI will not classify a domain as malicious unless the evidence can *only* be explained by an attacker-controlled system. If a misconfiguration or unusual-but-valid setup explains the behavior, the domain is classified as suspicious at most.

---

## 8. Batch Investigations

Use batch mode to investigate multiple domains at once — useful for:
- Processing a list of domains from a threat feed
- Investigating all lookalike domains discovered during a brand monitoring sweep
- Re-investigating a set of previously inconclusive domains

**How to submit a batch:**
1. Go to **Batches** in the navigation
2. Click **New Batch**
3. Upload a `.txt` or `.csv` file (one domain per line for TXT; first column for CSV)
4. Enter a batch name and optional description
5. Submit — all domains begin investigating in parallel (rate-limited by your Celery worker concurrency)

**Campaign Detection:**

After all investigations complete, click **Detect Campaigns** on the batch page. The platform clusters investigations that share:
- Same IP address
- Same nameservers
- Same ASN
- Same registrar
- Same TLS certificate SANs

Domains in the same cluster were likely registered and operated by the same threat actor. This is useful for attributing phishing campaigns and blocking entire infrastructure.

---

## 9. Domain Watchlist

Monitor domains over time. When a domain status changes (benign → suspicious, or a new VT detection appears), the watchlist flags it.

**Use cases:**
- Monitor registered lookalike domains of your brand before attackers weaponize them
- Keep tabs on a suspicious domain you're not yet ready to block
- Watch competitor infrastructure for changes

**How to add:**
1. Go to **Watchlist**
2. Enter a domain
3. Set monitoring frequency (hourly by default)

The Celery Beat scheduler runs `watchlist_check()` every hour and re-investigates each monitored domain. Classification changes are highlighted in the watchlist view.

---

## 10. IP Lookup Tool

Standalone IP reputation lookup tool — for when you have an IP address from a log, firewall alert, or phishing email header and want quick context.

**Navigate to:** IP Lookup in the header navigation.

**What it checks:**
- **AbuseIPDB** — abuse confidence score (0-100), total reports, recent report details, abuse categories
- **ThreatFox** — malware and C2 IOC matches

**Score interpretation:**
| Score | Verdict |
|---|---|
| 0-24 | Low risk — likely clean |
| 25-49 | Low-medium risk — monitor |
| 50-74 | Medium-high risk — investigate |
| 75-100 | High risk — likely malicious, consider blocking |

**History:** Every lookup is saved to history. Click any past result to reload it without re-querying the API.

---

## 11. Dashboard & Analytics

The **Dashboard** page shows platform-wide statistics:

- **Total investigations** count with breakdown by classification
- **Classification pie chart** — proportion of benign/suspicious/malicious/inconclusive
- **Risk score histogram** — distribution of risk scores across all investigations
- **Investigation timeline** — volume of investigations over time
- **Top registrars** — which registrars your malicious domains tend to use
- **Top hosting providers** — which providers host the most flagged domains
- **Recent malicious** — latest investigations classified as malicious

This view is useful for identifying trends: if a specific registrar or hosting provider appears repeatedly in malicious classifications, it may indicate a specific threat actor or campaign.

---

## 12. Exporting Reports

Each investigation can be exported in three formats:

| Format | Best For |
|---|---|
| **PDF** | Executive briefings, management reporting, incident documentation |
| **Markdown** | Integration with wikis, Confluence, ticketing systems |
| **JSON** | SIEM/SOAR ingestion, automated pipeline processing, custom tooling |

**How to export:** From the investigation detail page, click the **Export** button and select your format.

The PDF includes all sections: cover page with classification badge and risk score, full technical evidence, findings with ATT&CK mappings, IOC table, and recommended actions. It uses the WeasyPrint rendering engine for professional A4 formatting.

---

## 13. Common Investigation Scenarios

### Scenario A: Phishing Email Link

**Situation:** User reports receiving an email with a link to `paypa1-secure-verify.com`.

**Steps:**
1. Submit `paypa1-secure-verify.com` with client domain `paypal.com`
2. Enable visual comparison (upload a screenshot of your PayPal login page if needed)
3. Add investigation notes: "User reported via help desk ticket #4821. Email sender: support@paypa1-secure-verify.com"
4. Wait 60-90 seconds for analysis

**What to look for:**
- Domain similarity score >60 → typosquatting confirmed
- Visual clone detected → page cloning confirmed
- Login form present + credential harvesting POST → active phishing
- AbuseIPDB score >75 → IP is known-bad

**Expected outcome:** malicious classification with block recommendation.

---

### Scenario B: Suspicious Domain from Threat Feed

**Situation:** Threat intelligence feed flags `cdn-analytics-tracker.net` as potentially malicious.

**Steps:**
1. Submit `cdn-analytics-tracker.net` without a client domain
2. No visual comparison needed (no impersonation suspected)
3. Let the platform collect evidence

**What to look for:**
- Is it resolving? (ASN, HTTP evidence)
- VT detections? (Intel, VirusTotal)
- URLhaus hits? (malware distribution?)
- Hosting on known-bad IP? (AbuseIPDB)
- What does the page actually serve? (HTTP evidence — page title, content)

**Possible outcomes:**
- If it's hosting malware: malicious (URLhaus + VT detections)
- If it's a legitimate CDN: benign
- If it's recently registered with no content: inconclusive (insufficient data)

---

### Scenario C: Brand Monitoring — New Lookalike Domain

**Situation:** Your brand monitoring tool detected `my-company-secure.com` was just registered (your company is `mycompany.com`).

**Steps:**
1. Submit `my-company-secure.com` with client domain `mycompany.com`
2. Note: domain may have no content yet (just registered)
3. Add to watchlist after initial investigation

**What to look for:**
- Domain similarity score (combosquatting pattern?)
- WHOIS age (how new?)
- Is it serving content? If not → inconclusive but add to watchlist
- Cert issued? (Early cert issuance = attacker preparing)
- Any VT/blocklist hits?

**Expected outcome:** Likely inconclusive (new, no content yet) or suspicious (similarity score + very young domain). Add to watchlist to catch when it goes live.

---

### Scenario D: Bulk Lookalike Investigation

**Situation:** After discovering a phishing campaign, you have a list of 50 related domains from threat intelligence.

**Steps:**
1. Create a text file with all 50 domains (one per line)
2. Go to Batches → New Batch
3. Upload the file, name the batch "Campaign-2026-02-24"
4. Submit
5. Monitor progress — results appear as each investigation concludes
6. Once all done, click "Detect Campaigns" to cluster by shared infrastructure

**Expected output:** Investigation results for all 50 domains, with clustering showing which domains share infrastructure (likely 2-3 distinct clusters corresponding to different hosting setups used by the same actor or related actors).

---

## 14. Tips for Analysts

**On classification confidence:**
- `high confidence malicious` = you can act immediately (block, hunt, report to registrar)
- `medium confidence malicious` = strong case but one or two gaps; consider blocking with monitoring
- `low confidence` = incomplete evidence; follow the `data_needed` list before acting

**On inconclusive results:**
- Check the Signals & Gaps tab for the specific `data_needed` list
- Common data needs: "HTTP response from /login path" (site may gate content), "WHOIS registration email" (redacted by privacy), "Full VT scan" (new domain not yet analyzed)
- Re-investigate after 24-48 hours if the domain had no content

**On legitimate explanations:**
- Before blocking, read the "Legitimate explanation" field in the Executive Summary
- The AI always considers the best-case scenario; if the legitimate explanation is convincing, it may warrant human review before blocking

**On data gaps:**
- A missing data gap reduces confidence but does not make a domain malicious
- If VT data is missing (no API key), note that in your documentation — it weakens your evidence base
- VirusTotal and AbuseIPDB API keys are strongly recommended for production use

**On watchlist monitoring:**
- Add newly registered high-similarity domains immediately — even if inconclusive
- A domain that is clean today may weaponize in 48 hours
- Set up watchlist alerts to notify your SOC team when classification changes

**On batch processing:**
- Use the campaign clustering feature — it's the most efficient way to identify shared infrastructure
- Domains sharing nameservers but on different IPs are often from the same registrant who uses different hosting providers to evade IP-based blocks

**On enrichment:**
- After an investigation concludes, use the **Enrich** button to add new information
- This is useful when you receive additional context after the initial investigation (e.g., sandbox report from a separate tool, OSINT findings, registrar abuse response)
- Enrichment re-runs the AI analyst with the new context appended
