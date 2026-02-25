# Application Demo Guide
## Domain Threat Investigation Platform

This guide walks through every page of the application in demo order, with talking points, what to click, and what to highlight for each screen. Designed for a 20-30 minute live walkthrough.

---

## Recommended Demo Flow

```
1.  Home / Investigation Submission  ──── "Let's start an investigation"
2.  Investigation in Progress        ──── "Watch it run in real time"
3.  Report — Executive Summary       ──── "Here's the verdict"
4.  Report — Technical Evidence      ──── "Here's everything we found"
5.  Report — Findings & ATT&CK       ──── "Here's what the attacker did"
6.  Report — Indicators              ──── "Here are the IOCs"
7.  Report — Signals & Gaps          ──── "Here's what flagged it"
8.  Report — Infrastructure          ──── "Here's the full infrastructure"
9.  Dashboard                        ──── "Here's the big picture"
10. All Cases                        ──── "Here's the case history"
11. Bulk Analysis                    ──── "Here's how we scale"
12. Watchlist                        ──── "Here's how we monitor"
13. IP Lookup                        ──── "One more tool — IP reputation"
```

**Tip:** Pre-run a phishing domain investigation before the demo so you have a completed malicious result ready. Suggested demo domain: any known-bad domain from PhishTank, or use a historical one from your investigation history.

---

## Page 1 — Home / Investigation Submission

**URL:** `http://localhost:3000/`

### What's On Screen

- Large centered domain input field with monospace font
- **"+ Add context"** toggle (expands investigation notes textarea)
- **"+ Compare against client domain"** toggle (expands brand protection options)
- Blue **Investigate** button
- **Recent Investigations** panel below — last 10 investigations with classification badge, risk score, state, and date

### What To Demo

**Step 1 — Basic submission:**
> "The core workflow is simple. You paste a domain and click Investigate. The platform immediately dispatches 10+ collectors in parallel."

Type: `paypa1-secure.com`
Click **Investigate**.

**Step 2 — Show the advanced options (before submitting if doing a brand comparison demo):**

Click **"+ Compare against client domain"** to expand:

> "If we're investigating a potential impersonation, we tell the platform what our legitimate domain is. It will then compute a typosquatting score *and* take screenshots of both sites and compare them visually."

Fields that appear:
- **Client Domain** — `paypal.com` (the legitimate site being impersonated)
- **Specific URL to investigate** — optional, for phishing pages deep in a path
- **Client URL to compare** — optional, specific page on your legitimate site
- **Upload reference screenshot** — for internal portals not accessible from the internet

Click **"+ Add context"** to expand:

> "You can attach any context from your SOC ticket — user reports, email headers, anything. The AI analyst receives this as supplementary data, clearly labelled as human-provided input."

Fields:
- **Investigation notes** — free-text context for the analyst

### Talking Points

- "No login required, no complex form — one domain and you have an investigation."
- "The recent investigations list lets you jump back to any previous case instantly."
- "Classification badges are color-coded: red = malicious, amber = suspicious, green = benign."

---

## Page 2 — Investigation In Progress (Real-Time)

**URL:** `http://localhost:3000/investigations/{id}` (auto-redirected after submission)

### What's On Screen

The investigation detail page loads with a **Progress Timeline** showing 8 collectors running:

```
  DNS          ✓  1.2s
  HTTP         ✓  2.8s
  TLS          ✓  0.9s
  WHOIS        ✓  3.1s
  ASN          ✓  1.4s
  Intel        ✓  4.2s
  VirusTotal   ✓  2.3s
  Threat Feeds ✓  1.8s
  AI Analyst   ⟳  analyzing...
```

Each collector shows its name, a spinner while running, a green checkmark when done, and elapsed time. Below the timeline, a faint "Analyzing evidence..." message while Claude processes.

### What To Demo

Watch each collector tick from running to complete in real time. Point out:

> "These 8 collectors run in parallel — DNS, HTTP, TLS, WHOIS, geolocation, certificate transparency, VirusTotal, and threat feeds. They're all executing simultaneously via Celery workers."

> "Once they all finish — usually in 30 to 60 seconds — the aggregated evidence goes to Claude. The AI runs a structured 5-step methodology: baseline plausibility, anomaly identification, attacker necessity test, hypothesis comparison, and classification."

> "The page polls every 5 seconds, so you see it update automatically — no refresh needed."

### Talking Points

- "If a collector fails or times out, it doesn't stop the investigation. The analyst receives a data gap note instead."
- "The entire pipeline typically completes in 60-90 seconds for a standard investigation."
- "This is where the value is — what used to take an analyst 30 minutes of manual lookups happens automatically."

---

## Page 3 — Report: Executive Summary Tab

**URL:** `http://localhost:3000/investigations/{id}` → **Executive Summary** tab (default)

### What's On Screen

After the investigation concludes, the tab bar appears with 7 tabs. The Executive Summary shows:

**Header area:**
- Domain name in monospace (`paypa1-secure.com`)
- Large **classification badge** — color-coded pill (red MALICIOUS / amber SUSPICIOUS / green BENIGN / grey INCONCLUSIVE)
- **Risk score** — large number like `91` next to the badge
- Confidence level: `HIGH / MEDIUM / LOW`
- Recommended action: `BLOCK / HUNT / INVESTIGATE / MONITOR`

**Body:**
- **Primary Reasoning** — one-paragraph core analytical argument from Claude
- **Legitimate Explanation** — best-case benign scenario Claude considered
- **Malicious Explanation** — attack scenario that fits the evidence
- **Key Evidence** — bullet list of the evidence fields that drove the classification
- **Contradicting Evidence** — any evidence that weakens the case (intellectual honesty)
- **Recommended Steps** — specific, actionable SOC tasks
- **Export** button (PDF / Markdown / JSON)

### What To Demo

Point to the classification badge:
> "This is the verdict. The AI applied its attacker necessity test — would an attacker-controlled system be *required* to explain this behavior? In this case: yes."

Point to the risk score:
> "91 out of 100. We use a consistent scale: 75+ is malicious, 40-74 is suspicious, under 40 is benign."

Read the Primary Reasoning aloud or paraphrase:
> "This is Claude's core argument. Notice it references specific evidence fields — this isn't a black box. Every claim maps to a measured data point."

Point to Legitimate Explanation:
> "This is important — the platform *always* argues the legitimate side too. It considers whether a misconfigured but benign site could explain the same evidence. Only if the legitimate explanation requires too many assumptions does it classify as malicious."

Point to Recommended Steps:
> "These are the actual SOC actions — not just 'block it.' It specifies what to block, what to hunt for, which teams to notify."

### Talking Points

- "This is the executive view — classification, confidence, reasoning, action. Everything a SOC lead or manager needs without reading the technical detail."
- "The 'contradicting evidence' field shows the platform's intellectual honesty — it doesn't just confirm suspicions."

---

## Page 4 — Report: Technical Evidence Tab

**URL:** Same page → **Technical Evidence** tab

### What's On Screen

Structured panels for each collector, displayed as dark cards:

| Panel | Key content shown |
|---|---|
| **DNS** | A records, MX, NS, TXT, DMARC, SPF in a clean table |
| **HTTP** | Redirect chain (hop by hop), page title, login form detected badge, security headers table (green/red), server fingerprint, brand indicators found |
| **TLS Certificate** | Issuer, validity dates, days remaining, SANs list, fingerprint |
| **WHOIS** | Registrar, creation date, domain age in days, privacy status, registrant info |
| **ASN & Hosting** | IP, ASN, organization, country, city, CDN detection badges |
| **Intel** | crt.sh certificate list, blocklist hits (red badges), URLhaus hits |
| **VirusTotal** | Malicious/suspicious/harmless vendor counts, per-vendor table with verdicts |
| **Threat Feeds** | AbuseIPDB score gauge (SVG arc), PhishTank match, ThreatFox IOCs, OpenPhish status |
| **Email Security** | DMARC policy, SPF qualifier, DKIM selectors, spoofability score |
| **Domain Similarity** | Similarity score, detected techniques (combosquatting, character replacement, etc.), Levenshtein distance |
| **Visual Comparison** | Side-by-side screenshots, similarity percentage, "VISUAL CLONE" badge |
| **Redirect Analysis** | Per-UA redirect chains, cloaking status |
| **JavaScript Sandbox** | POST endpoints, credential harvesting flag, fingerprinting APIs, tracking pixels |
| **Infrastructure Pivot** | Co-hosted domain count, first few domains listed |
| **Certificate Timeline** | Timeline of all certificates ever issued for this domain |

### What To Demo

**Threat Feeds panel — AbuseIPDB gauge:**
> "The AbuseIPDB gauge shows an abuse confidence score of 87 out of 100 — this IP has been reported 142 times for web application attacks and credential theft."

**Visual Comparison panel:**
> "This is the visual clone evidence. The platform captured a screenshot of both the phishing site and the real PayPal login page, then ran a perceptual hash comparison. 84% similarity — it's a near-perfect clone."

**Intel panel:**
> "crt.sh shows this certificate was issued 5 days ago — the same day the domain was registered. And here's the URLhaus hit — the platform found this exact domain actively distributing phishing pages."

**HTTP panel:**
> "The HTTP collector detected a login form, brand phrases like 'verify your account', and JavaScript patterns consistent with phishing kits — specifically `atob()` for base64 decoding and an `eval()` call, which are classic obfuscation techniques."

### Talking Points

- "This is everything a manual analyst would spend 30 minutes gathering, displayed in one place."
- "The color coding is consistent — red means bad, green means OK, grey means neutral."
- "All of this feeds into the AI's analysis. Nothing is hidden — you can inspect every piece of evidence."

---

## Page 5 — Report: Findings Tab

**URL:** Same page → **Findings** tab

### What's On Screen

**Findings list** — each finding is a card with:
- **Severity badge** — color-coded: CRITICAL (dark red) / HIGH (red) / MEDIUM (amber) / LOW (blue) / INFO (grey)
- **Title** — short descriptive name
- **Description** — detailed explanation with evidence field references
- **MITRE ATT&CK technique** — technique ID + name (e.g., `T1036.005 — Masquerading: Match Legitimate Name`)

Below the findings list:

**MITRE ATT&CK Coverage map** — visual grid of all 14 ATT&CK tactics (Reconnaissance, Resource Development, Initial Access, Execution, etc.) with techniques from this investigation highlighted in the relevant columns.

### What To Demo

Scroll through findings:
> "Each finding is a discrete, attributed observation. Not just 'this looks bad' — specific technical observations with severity and context."

Point to an ATT&CK technique badge:
> "Every finding maps to a MITRE ATT&CK technique. T1056.003 — Web Portal Capture — means the attacker cloned a login portal to steal credentials. T1583.001 — Acquire Infrastructure — means they registered a new domain for this campaign."

Point to the ATT&CK coverage grid:
> "The coverage map shows which tactics are present in this attack. This investigation has Resource Development, Initial Access, and Credential Access represented — a classic phishing kill chain."

### Talking Points

- "ATT&CK mapping turns raw investigation results into incident response context. Your SOC team knows exactly which playbooks apply."
- "CRITICAL findings are things you act on immediately. HIGH are your next priority."
- "The coverage grid is useful for threat hunting — it tells you what other behaviors to look for in your logs."

---

## Page 6 — Report: Indicators & Pivots Tab

**URL:** Same page → **Indicators & Pivots** tab

### What's On Screen

A table of IOCs (Indicators of Compromise):

| Type | Value | Context | Confidence |
|---|---|---|---|
| domain | paypa1-secure.com | Phishing domain | HIGH |
| ip | 198.51.100.5 | Hosting IP | HIGH |
| url | https://paypa1-secure.com/login | Phishing landing page | HIGH |
| url | https://harvest-data.xyz/collect.php | Credential exfiltration endpoint | HIGH |
| domain | harvest-data.xyz | Credential collection backend | HIGH |

Each row has a **Copy** button. There's also a **Copy All** button to export all IOCs at once.

Type badges are color-coded (domain = purple, ip = blue, url = orange, hash = green, email = teal).

### What To Demo

Click **Copy All**:
> "One click and all IOCs are on your clipboard, ready to paste into your SIEM, EDR, or threat intel platform."

Point to the exfiltration endpoint URL:
> "This is the credential harvesting endpoint — `harvest-data.xyz/collect.php`. This is the actual server receiving the stolen passwords. This is a high-value IOC for threat hunting."

### Talking Points

- "IOCs are automatically extracted from the analyst report — no manual parsing."
- "The confidence level matters: HIGH means the analyst has strong evidence this is malicious. LOW means it's a pivot candidate but not yet confirmed."
- "These IOCs can be pivoted — submit `harvest-data.xyz` for its own investigation to understand the attacker's backend infrastructure."

---

## Page 7 — Report: Signals & Gaps Tab

**URL:** Same page → **Signals & Gaps** tab

### What's On Screen

**Signals section** — list of pre-computed investigative clues:

Each signal card shows:
- **Severity badge**
- **Category** (infrastructure_age / certificate / content / email_security / similarity / etc.)
- **Description** — plain-English explanation
- **Evidence references** — field paths like `whois.domain_age_days`

Example signals visible:
```
[HIGH]     sig_very_young_domain       Domain is 7 days old — registered this week
           evidence: whois.domain_age_days

[CRITICAL] sig_phishtank_match         Verified phishing URL in PhishTank database
           evidence: threat_feeds.phishtank

[HIGH]     sig_phishing_indicators     eval() call, atob() call detected in page source
           evidence: http.phishing_indicators

[CRITICAL] sig_visual_clone            Screenshots show 84% visual similarity to client domain
           evidence: visual_comparison.overall_visual_similarity

[HIGH]     sig_typosquatting_detected  Combosquatting + character replacement vs paypal.com
           evidence: domain_similarity.detected_techniques

[HIGH]     sig_abuseipdb_high          IP abuse confidence score: 87
           evidence: threat_feeds.abuseipdb.abuse_confidence_score
```

**Data Gaps section** — what couldn't be collected:

```
[MEDIUM] whois.registrant_email
         Reason: WHOIS privacy protection redacts registrant info
         Impact: Cannot attribute registration to known threat actor

[LOW]    vt.passive_dns
         Reason: Domain too new for passive DNS records
         Impact: Cannot see historical IP associations
```

### What To Demo

Point to the signals list:
> "These signals are computed automatically before the AI analyst sees anything. They're structured clues — not conclusions. The analyst then validates each one against technical plausibility."

Point to a data gap:
> "Data gaps tell you what the investigation *couldn't* find and why that matters. If we subpoena the registrar for the registrant email, we might link this to other phishing campaigns from the same actor."

### Talking Points

- "Signals are inputs to the analysis, not outputs. The AI doesn't just rubber-stamp every signal — it checks if a legitimate explanation could produce the same behavior."
- "The data gaps section is an action list for deeper investigation. Each gap tells you exactly what to collect next."

---

## Page 8 — Report: Infrastructure Tab

**URL:** Same page → **Infrastructure** tab

### What's On Screen

**Pivot Points** — infrastructure artifacts from this investigation that can be used to find related domains:
- IP address(es) with copy button
- Nameservers with copy button
- ASN number
- Registrar name
- TLS certificate SANs
- Certificate fingerprint

**Related Investigations** — other domains already investigated by the platform that share infrastructure with this one (same IP, same NS, same ASN, etc.)

**Reverse IP Lookup** — full list of co-hosted domains:
- Summary card: "47 domains share IP 198.51.100.5"
- Preview of first 10-15 domains
- **"View all 47 →"** button

Clicking **"View all 47 →"** opens a modal:
- IP address header
- Search bar (live filter)
- Scrollable domain list with per-domain copy button
- **Copy all** button at the top
- Domain count in footer

**NS Clustering** and **Registrant Pivot** sections (if data available)

### What To Demo

Point to the IP in Pivot Points:
> "198.51.100.5 — this is the pivot point. Every artifact here is something you can use to find more infrastructure."

Click **"View all 47 →"**:
> "47 domains on the same IP. Watch — I'll search for 'payp' in the filter..."

Type `payp` in the modal search:
> "Three results: paypa1-secure.com, paypallogin.xyz, paypal-verification.net. Same threat actor, different campaigns, same VPS."

Click **Copy all**:
> "Copy all 47 domains — paste them into your SIEM as a bulk block list, or submit them as a batch investigation."

### Talking Points

- "This is where single-domain investigation turns into campaign attribution."
- "One phishing domain pulled is good. Identifying all 47 variants on the same server is a lot better."
- "The Related Investigations panel is particularly useful in active incident response — if your team has already investigated some of these domains, the results are linked here."

---

## Page 9 — Dashboard

**URL:** `http://localhost:3000/dashboard`

### What's On Screen

**Stat cards (top row):**
- Total investigations (e.g., `247`)
- Malicious count with red highlight
- Suspicious count with amber highlight
- Concluded count

**Charts (middle section):**
- **Classification pie chart** — proportion of benign / suspicious / malicious / inconclusive (color-coded)
- **Risk score histogram** — distribution of risk scores across all investigations (bar chart, x-axis = score ranges 0-10, 10-20, ... 90-100)
- **Investigation timeline** — stacked area chart, x-axis = dates, y-axis = count, stacked by classification color

**Bottom charts:**
- **Top registrars** — horizontal bar chart, which registrars appear most in malicious/suspicious investigations
- **Top hosting providers** — same format for hosting companies
- **Recent malicious** — table of the latest malicious-classified domains with risk score, date, and click-to-open

### What To Demo

Point to the pie chart:
> "At a glance — out of 247 investigations, 18% came back malicious, 31% suspicious, 44% benign, 7% inconclusive. This is your threat landscape in this environment."

Point to the risk histogram:
> "Most investigations cluster at the low end — that's expected, most domains are clean. The spike at 80-100 is your high-confidence malicious findings."

Point to the timeline chart:
> "You can see investigation volume over time, with each classification stacked. If you see a sudden spike in malicious findings on a specific date, that's a campaign."

Point to the top registrars chart:
> "Namecheap and Hostinger show up heavily in malicious results. That's actionable — it tells you which registrars your threat actors prefer."

Point to Recent Malicious:
> "Quick access to the latest high-risk domains. Click any row to jump directly to that investigation."

### Talking Points

- "This is the command view — your SOC manager or CISO can get the full threat landscape in 10 seconds."
- "Registrar and hosting trends help you build predictive models — if a domain just registered at Namecheap with Hostinger hosting, raise your baseline suspicion."

---

## Page 10 — All Cases

**URL:** `http://localhost:3000/investigations`

### What's On Screen

- **Search bar** — live filter by domain name
- **State filter** buttons — All / Pending / Gathering / Analyzing / Concluded / Failed
- **Investigation table** with columns:
  - Domain (monospace, clickable)
  - Classification badge (color-coded)
  - Risk score
  - State badge
  - Created date
- Pagination controls at the bottom

### What To Demo

Type in the search bar:
> "You can search across all investigations by domain name. Useful for 'has anyone already investigated this domain?'"

Click the **Malicious** state filter (or use classification filter if available):
> "Filter to just malicious findings. This is your active threat list."

Click a row to open the investigation:
> "Every row is clickable — opens straight to the Executive Summary."

### Talking Points

- "This is your case log. Everything the team has investigated, searchable and filterable."
- "State filters help you find investigations still in progress versus ones that have concluded."

---

## Page 11 — Bulk Analysis

**URL:** `http://localhost:3000/batches`

### What's On Screen

**Upload form (top):**
- File drop zone — accepts `.txt` or `.csv` (one domain per line)
- **Batch name** input
- **Description** input
- **Client domain** input (optional — applies typosquatting comparison to all domains in batch)
- **Upload & Investigate** button

**Recent Batches list (below):**
- Batch name
- Total domains / completed count
- Progress bar
- Status badge (running / completed / failed)
- Click to open batch detail

### What To Demo

Show the upload form:
> "You can drop a .txt or .csv file with up to hundreds of domains. One client domain set here applies the similarity comparison to every domain in the list — powerful for brand monitoring sweeps."

Click a completed batch to open it (**Batch Detail page**):

**Batch Detail page** (`/batches/{id}`):

What's on screen:
- Batch header (name, domain count, completion percentage, status)
- Progress bar (live-updated while running)
- **Table view** — all investigations with classification, risk score, state
- **Detect Campaigns** button
- Pagination + search within batch

Click **Detect Campaigns**:
> "Campaign detection clusters all investigations in this batch by shared infrastructure — same IP, same nameservers, same ASN, same registrar. Watch..."

The page switches to **Campaign View**:
- Clusters displayed as grouped cards
- Each cluster shows: the shared pivot point (e.g., "Shared IP: 198.51.100.5"), list of domains in the cluster, classification distribution within the cluster
- Clusters sorted by domain count (largest = most important)

Point to a cluster:
> "This cluster has 12 domains all resolving to the same IP, all registered on the same day, all with the same Let's Encrypt certificate pattern. That's not coincidence — that's a single actor's phishing infrastructure."

### Talking Points

- "Batch mode is how you scale. Instead of 50 manual investigations, you upload a file and come back in 10 minutes."
- "Campaign detection is unique — it automatically identifies the infrastructure relationships, so you can block an entire attack campaign, not just one domain at a time."
- "This is particularly powerful when you get a threat intelligence feed — dump the IOC list in, run campaign detection, and understand the full scope in minutes."

---

## Page 12 — Watchlist

**URL:** `http://localhost:3000/watchlist`

### What's On Screen

**Add domain form (top):**
- Domain input field
- Schedule dropdown: No schedule / Weekly / Biweekly / Monthly
- **Add to Watchlist** button

**Watchlist table:**
- Domain (monospace)
- Status badge: ACTIVE (green) / PAUSED (amber) / REMOVED (grey)
- Last classification badge (with color coding)
- Last checked timestamp (relative: "2h ago", "3d ago")
- Schedule badge if set (purple "Weekly")
- Next check countdown ("in 6h")
- Delete (×) button per row

### What To Demo

Type a domain and click **Add to Watchlist**:
> "Say you've identified a suspicious lookalike domain during a brand sweep, but it has no content yet — inconclusive. You add it to the watchlist."

Point to an existing row with a schedule:
> "This domain is checked weekly. If it changes classification — say it was benign and now looks suspicious — the platform flags it."

Point to "Last checked: 2h ago":
> "The Celery Beat scheduler runs checks automatically, every hour at minimum. No manual effort."

### Talking Points

- "Most phishing infrastructure is set up before it's weaponized. They register the domain, get a cert, but the phishing page might not go live for days."
- "The watchlist catches that window — you detect it while it's still in preparation, before any users are targeted."
- "This is your early warning system for brand abuse."

---

## Page 13 — IP Lookup

**URL:** `http://localhost:3000/ip-lookup`

### What's On Screen

**Two-column layout:**

**Left column — History sidebar (280px):**
- List of past IP lookups
- Each entry: IP address, ISP, country, relative timestamp
- **Score badge** on the right of each entry — color-coded (red/amber/green)
- **ThreatFox badge** if ThreatFox matches found (small orange badge with count)
- **×** delete button per entry
- Active entry highlighted with blue left border

**Right column — Results panel:**
- IP input field + **Look Up** button
- **Score hero card** — large SVG arc gauge (0-100), color-coded, score label ("HIGH RISK / SUSPICIOUS / LOW RISK / CLEAN")
- **Metadata section** — ISP, country, usage type, hostnames (reverse DNS)
- **Abuse categories** — chip badges for each abuse type (e.g., Web App Attack, Brute Force)
- **Recent Reports table** — date, country, category badge, comment text
- **ThreatFox IOC cards** — IOC value, type, threat type, malware family, confidence, date, tags

### What To Demo

Click a past lookup in the history sidebar:
> "Every lookup is saved. Click a history entry to reload it instantly without hitting the API again."

Type an IP and click **Look Up**:
> "Same approach — one click, immediate results."

Point to the score gauge:
> "The arc gauge gives an instant visual. 87 in red means this IP is reported for abuse by 87% of AbuseIPDB reporters. 142 separate reports."

Point to the abuse categories:
> "Web App Attack and Brute Force — this IP is actively scanning for vulnerable login pages and hammering credentials. Combined with a phishing domain hosted there, it's a clear picture."

Point to a ThreatFox card (if present):
> "ThreatFox found this IP listed as a C2 server for a known malware family. That escalates this from 'abuse reporting' to 'confirmed threat actor infrastructure.'"

### Talking Points

- "This is your quick triage tool. Got an IP from a firewall alert, a phishing email header, or a log? Check it here in 3 seconds."
- "The history means your team builds up a shared lookup record — if someone already checked an IP, you see it immediately."
- "AbuseIPDB is community-driven. Scores above 75 represent IPs that the entire security community has flagged — that's high-fidelity signal."

---

## Closing the Demo

After completing the tour, return to the **Dashboard** for a closing view:

> "To summarize what you've seen:
>
> — A single domain submitted, and in 90 seconds you have a complete threat assessment backed by 10+ data sources.
>
> — A 5-step AI methodology that applies the same analytical rigor as an experienced threat analyst, every time, at machine speed.
>
> — Full MITRE ATT&CK mapping, so findings connect directly to your existing SOC playbooks.
>
> — Bulk analysis with campaign detection that turns 50 domains into clustered threat actor infrastructure.
>
> — A watchlist that monitors suspicious domains around the clock, so you catch threats before they're weaponized.
>
> — Everything exportable as PDF, Markdown, or JSON for reports, tickets, and SIEM integration.
>
> The platform doesn't replace your analysts. It handles the mechanical collection and initial classification, so your analysts spend their time on decisions — not lookups."

---

## Demo Preparation Checklist

Before a live demo:

- [ ] Platform is running (`docker compose up -d` — all services green)
- [ ] At least one completed **malicious** investigation in history (for the report demo)
- [ ] At least one completed **batch** with 10+ domains (for campaign demo)
- [ ] At least 2-3 entries in the **Watchlist**
- [ ] At least 2-3 entries in **IP Lookup history**
- [ ] Dashboard has data (stats will be empty on a fresh install)
- [ ] API keys configured: `ANTHROPIC_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`
- [ ] Browser window at 1280px+ width (layout is not mobile-optimized)
- [ ] Dark theme renders correctly in your presentation environment

## Suggested Demo Domains

| Domain | Expected Result | Notes |
|---|---|---|
| A known PhishTank domain | MALICIOUS | Pull a current one from phishtank.com |
| `example.com` | BENIGN | Safe, always resolves cleanly |
| A day-old Namecheap domain with no content | INCONCLUSIVE | Shows data gap handling |
| Any brand lookalike from your org | SUSPICIOUS / MALICIOUS | Use your actual client domain for real comparison |
