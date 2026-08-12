# Prompt — Claude in Chrome: demo video preparation

Paste everything below the line into the Claude browser extension with the app open.

**The prompt begins by making the agent declare what it can record.** A previous
run used a frame-capped GIF recorder and the pacing suffered: some screens
flashed past, others landed on a loading spinner. Video and GIF need opposite
direction — video is paced in seconds, GIF in frames — so Step 0 establishes
which one applies before any shot is planned.

---

## ROLE

You are producing a professional product demo video for **Threat Analyzer**, a
threat intelligence and investigation platform used by SOC analysts. **You drive
the browser and you do the recording** — I am not recording this myself.

Your job in this session:

1. Declare exactly what you can record (§0). This governs everything after it.
2. Explore the running application and verify what is actually on each screen.
3. Produce a **shot list** — every navigation, click, scroll, zoom and hold.
4. **Record the walkthrough**, following that list.
5. Produce a **voice-over script** timed to the recording you actually made.
6. Flag anything that looks bad on camera, before and after recording.

Deliver the recording as the highest-fidelity format you have — mp4 or webm if
available, GIF only if that is genuinely all you can produce.

Work through the app methodically. Do not summarise from this prompt alone —
open each page and confirm what is there, because the data changes.

## HARD RULES

**Never click anything that changes state.** This is a live SOC platform with
real case data. Specifically, never click: Delete, Cancel run, Cancel
investigation, Resolve, Acknowledge, Add exclusion, Add domain, Add client,
Investigate now, Re-run live sandbox, or submit any form. Read-only navigation
and filtering only. If a screen needs an action to be interesting, tell me and I
will perform it myself.

**Flag real-world data.** The current data contains real internal hostnames
(`expertware.net`, `EXP-*` machine names), internal IP ranges (10.x) and live
detection rule IDs. Every screen you put in the shot list must be checked for
this. Where you find it, say so explicitly and mark the shot
`NEEDS SANITISED DATA` — I will decide whether to reshoot against a seeded demo
org or blur in post. Do not design the demo around screens I cannot publish.

**Report empty or ugly states.** If a page has no data, a broken layout, an
error banner, or a section that is obviously incomplete, tell me rather than
routing the demo around it silently.

## THE APPLICATION

**Name:** Threat Analyzer — "Threat Intelligence and Investigation Platform" (v2.0)
**URL:** http://10.45.0.71:3000
**Theme:** dark by default; light theme available in Settings.

**What it is for, in one sentence:** an analyst pastes an observable — a domain,
URL, file hash, file, or a raw SIEM alert — and the platform runs it through
~24 intelligence collectors, produces an evidence-backed verdict with an AI
narrative, and then measures its own accuracy over time.

**What makes it different from a normal enrichment tool** — these are the points
the demo needs to land:

- It does not just enrich, it **investigates and concludes**, with a risk score,
  a classification, and a recommended action.
- It **detonates the sample and shows you the behaviour** — a full ANY.RUN
  sandbox run with the process tree, network activity and per-process detail
  rendered inside this platform, not a link out. **This is the centrepiece of
  the demo — see the dedicated section below.**
- It **checks the detection's own ATT&CK mapping** against what the evidence
  actually showed — claimed vs confirmed vs observed.
- It **measures itself**: per-rule noise and actionable rates, and agreement
  between the platform's verdict and the analyst's.
- It **avoids redundant work** — an exclusion list, prior-investigation reuse,
  and duplicate-alert absorption — and reports what that saved.
- It **notices when a verdict goes stale** via the watchlist and re-notifies.

### Global navigation (top bar, left to right)

| Label | Route | Purpose |
|---|---|---|
| Dashboard | `/dashboard` | Volume, verdict mix, risk distribution, recent malicious |
| All Cases | `/investigations` | Every investigation, filterable |
| Bulk Analysis | `/batches` | Upload a list of observables |
| Watchlist | `/watchlist` | Domains re-checked on a schedule |
| Exclusion | `/exclusions` | Indicators answered from policy, never looked up |
| Detections | `/detections` | Rule quality, ATT&CK coverage, platform accuracy |
| Cost | `/cost` | Provider quota and work avoided |
| Email | `/email-investigations` | .eml / .msg analysis |
| Alert Body | `/alert-investigations` | Raw SIEM alert investigations |
| AI Assistant | `/assistant` | Conversational analyst workspace |
| Clients | `/clients` | Monitored organisations |
| Alerts | `/alerts` | Client alerts raised by investigations |
| IP Lookup | `/ip-lookup` | Fast IP reputation check |
| Settings | `/settings` | Theme, density, API health |

The home page `/` is the submission form — it is not in the nav; the logo links
to it.

### Where the detail lives

**Home `/`** — observable type selector (Domain, URL, Hash, File, Alert Body),
input field, recent investigations below. A collapsed "How an investigation
works, and what it checks" section holds the pipeline explanation and the full
collector list — open it once on camera, it is a good way to show breadth
without a wall of logos.

**Investigation detail `/investigations/{id}`** — the core screen. Header
carries the observable, verdict badge and completion time. Below it, collector
coverage (with a `Technical details` disclosure holding run id, model, timings).
Then a tab bar:

- **AI Case Story** — the narrative. Best opening shot of a finished case.
- **SOC Intelligence** — sub-tabs: Score, Timeline, IOC Map, Similar Cases, IOC
  Actions, Screenshots, Collectors, Changes, Notes, OpenCTI, Report.
- **Technical Evidence** — DNS, HTTP, TLS, WHOIS, ASN, VirusTotal, URLScan,
  screenshots, JS analysis, and the **AnyRun Analysis** section (sandbox
  verdicts → what ANY.RUN detected → AI summary → screenshots → process tree →
  contacted IPs/hosts → extracted IOCs).
- **Findings** — discrete findings with ATT&CK technique mapping.
- **Indicators & Pivots** — extracted IOCs and where to pivot next.
- **Signals & Gaps** — what fired, and what evidence is missing.
- **Infrastructure** — hosting, certificates, related infrastructure.
- **AnyRun** — the process graph on its own canvas.
- **Raw JSON** — the full payload.

Hash / IP / file observables take a shorter path and show only four tabs.

**Alert Body detail `/alert-investigations/{id}`** — header with verdict and
indicator counts, then: the alert body, the AI assistant analysis (with the list
of values redacted before the model saw them), what the sources found, endpoint
events parsed from the alert, and per-indicator reports. Exports are behind the
overflow (⋯) button.

**Detections `/detections`** — three tabs and a 7/30/90-day window:
- *Rules* — per rule: noise rate, actionable rate, ATT&CK confirm rate, analyst
  false-positive rate, and a plain-language assessment.
- *ATT&CK coverage* — techniques observed but never claimed (detection gaps),
  claimed but never corroborated, a by-tactic list where **each tactic expands
  to show the alerts behind it**, and blind spots.
- *Platform accuracy* — agreement rate, and the two asymmetric failure buckets:
  missed by the platform, over-flagged by the platform.

**Cost `/cost`** — work avoided (lookups avoided, by exclusion list, by prior
reuse, duplicate alerts absorbed) and per-provider quota usage.

## THE ANY.RUN SANDBOX — GIVE THIS THE MOST SCREEN TIME

This is the strongest thing in the product and it must not be reduced to a
passing shot. Most tools link out to a sandbox report; this one **pulls the full
detonation back in and renders it as evidence inside the case**, then reasons
over it.

### Use this case

**`http://10.45.0.71:3000/investigations/6d475b4f-8625-4a95-936a-2ad24de20859`**
— `robiox.com.py`, classified **malicious**, risk score **90**. A Roblox
typosquat on a Paraguayan TLD; ANY.RUN labels it `phishing`.

Verify it is still intact before building the plan around it. It carries **two**
ANY.RUN items — a reputation *lookup* and a live *sandbox detonation* — which is
itself worth a line of narration: the platform checks what is already known, then
detonates when that is not enough.

The detonation recorded (**these figures were verified in the running app —
use exactly these, they are what the screen says**):

| | |
|---|---|
| Process nodes in the graph | **160** |
| HTTP requests | 727 |
| Connections | 48 |
| DNS requests | 42 |
| Network threat events | 10 |
| Screenshots that actually render | **8** |
| Collector coverage on this case | **64% — 9 of 14; WHOIS and INTEL failed** |

Do not say "165 processes", "31 nodes" or "12 screenshots" — earlier drafts of
this brief carried those numbers and they do not match the UI. A separate stat
block reads "PROCESSES 325" for a broader count; ignore it, use 160.

The 64% coverage is not a flaw to hide. Narrate it: *even with two collectors
down, four independent sources still converged on the same verdict.*

One of the network threats reads:
`PHISHING [ANY.RUN] Suspected Phishing Domain (robiox .com .py)` — class
*Possible Social Engineering Attempted*, priority 2, fired from `msedge.exe`.
That single line is the demo's proof shot: the sandbox named the phishing domain
during execution.

The ANY.RUN AI summary on this case reads: *"Malicious activity. Observed 727
HTTP requests, 48 connections, 42 DNS requests, 10 network threat events. Top
incidents: Reads the computer name; Checks supported languages; Reads
Environment values."*

### Where to find each piece

**Technical Evidence tab → AnyRun Analysis section.** Ordered deliberately —
conclusion first, mechanism second:

1. **Sandbox Verdicts** — a row per ANY.RUN item: source, mode (lookup vs
   sandbox), execution (live vs cached), interaction, network, **provider
   verdict**, **App Assessment** (this platform's own reading, which can differ
   from ANY.RUN's), confidence, threat score, analysis id.
2. **What ANY.RUN actually detected** — the provider's own findings.
3. **Any.Run AI Summary** — the narrative quoted above.
4. **ANY.RUN Sandbox Screenshots** — 12 captures; click one to open full
   resolution. The phishing page rendering in the sandbox is the most
   immediately legible evidence in the whole product. **Hold this shot.**
5. **Process Tree Summary** — root and high-signal processes with PID, threat
   score, and per-process network/file event counts.
6. **Contacted IPs / Contacted Hosts** — with the process that reached each one.
7. **Extracted IOCs**.

**AnyRun tab — the process graph.** A dedicated canvas, 31 nodes for this case.
It is interactive: **mouse wheel zooms, drag pans**. Click a node to open that
process's detail — command line, parent, signatures, and the panel *"Why this
process is suspicious"*. There is also a full-screen route,
`/investigations/{id}/process-graph`, which hides the site header and footer —
**use that for the graph shots**, it is far cleaner on camera.

Per-process detail available behind a node includes: image path, PID/PPID,
command line, certificate/signing status, and event lists for connections, DNS
requests, HTTP requests, created / modified / dropped / deleted files, registry
changes, loaded modules and network threats.

### How to shoot it

This act gets **16 of the ~46 frames** — a third of the whole video. See the
frame-budget rules under "Recording mechanics" below; the per-beat split is
specified there. The sequence:

1. **Sandbox Verdicts** — two rows: `LOOKUP 70/malicious` and `SANDBOX
   LIVE/malicious`, plus the interaction-coverage banner. Scroll so both rows
   and the banner are in one frame.
2. **Behaviour counts and the phishing detection row** — zoom in. At page zoom
   this text is unreadable in the GIF.
3. **Screenshot gallery, then one opened full-size** — the Roblox-branded fake
   signup form. This is the single most persuasive image in the product.
   Capture the opened image at least three times so it holds on screen.
4. **Full-screen process graph** at `/investigations/{id}/process-graph` — wide
   establishing frame, then click `msedge.exe` PID 5760 and zoom the "Why this
   process is suspicious" panel.
5. **Contacted IPs / Hosts** to close the act on behaviour.

Narration should stress: **this ran, we watched it, and here is what it did** —
not "we queried a third-party API".

### Caveats — all confirmed live, plan around them

- **Screenshots: 8 render, not 12.** They load correctly. Open the gallery once
  before recording so every thumbnail is cached and nothing pops in mid-capture.
- **The interaction-coverage warning appears twice** on this case ("a data-entry
  form was detected but not submitted"). **Keep it in frame** and narrate it — a
  tool that states the limits of its own evidence is more credible, not less.
- **The graph needs ~3s to settle.** Capture too early and you get an empty or
  half-laid-out canvas. Use the full-screen route; it hides the site header and
  footer and gives the canvas the whole frame.
- **The Infrastructure tab spinners for 5s** showing "Analyzing infrastructure
  connections…". A previous recording wasted a frame on that spinner. Wait and
  verify content is present before capturing.

## WHAT I WANT FROM YOU

### 0. FIRST — declare your recording capability

Before planning a single shot, list every recording tool available to you in
this session and answer all of these:

- **Output formats** — mp4, webm, gif, or a sequence of stills?
- **Continuous video or discrete captures?** If video: max clip length, frames
  per second, and whether you can start and stop recording around individual
  actions.
- **Frame or duration limits**, and what counts against them.
- **Audio** — can you attach an audio track at all? Can you generate speech?
- **Cursor** — is the pointer visible in the output, and can you move it
  deliberately (hover, glide to a target) rather than teleporting?
- **Scrolling** — smooth/animated, or instant jumps?
- **Resolution and aspect ratio**, and whether you can set them.

Report this before anything else. Then follow **§3a if you have real video**,
or **§3b if you only have frame-based capture**. Do not mix the two.

If you have a video tool available, use it. A previous run produced a
frame-capped GIF and the pacing was unusable.

### 1. Reconnaissance report

Visit every route above. For each, tell me in two lines: is it populated, does
it contain real-world data, is anything broken or empty. Rank the routes by how
well they will demo.

### 2. Verify the hero case, and find a contrast

The hero case is **`robiox.com.py`** —
`/investigations/6d475b4f-8625-4a95-936a-2ad24de20859`. Open it and confirm
every ANY.RUN element listed in the section above is present and renders:
sandbox verdicts, the AI summary, all 12 screenshots, the process tree summary,
contacted IPs and hosts, and the 31-node graph on the AnyRun tab. Report
anything missing or broken.

If it does not hold up, find the best alternative — a malicious case with a
**live sandbox detonation** (not a cached lookup), screenshots, and a populated
process graph — and tell me why you switched.

Then find a second, contrasting case: something the platform correctly called
benign, to show it is not a machine that flags everything. A short shot, but it
earns the malicious verdict its credibility.

### 3a. Direction for VIDEO output (mp4/webm)

If you can record continuous video, pace in **seconds** and treat the output as
something a person will watch end to end, not a slideshow.

1. **Dwell time is explicit and generous.** Every shot carries a hold in
   seconds. Nothing important gets less than **4s**; the opened phishing
   screenshot gets **6s**; the process-details panel gets **8s**.
2. **Move, don't teleport.** Glide the cursor to a target before clicking, and
   pause ~1s on it first — the viewer needs to see what is about to be clicked.
   Never let the pointer jump across the screen mid-shot.
3. **Scroll slowly and continuously.** Long sections — the AnyRun analysis
   stack, the TLS SAN list — should be revealed by a slow scroll over 4–6s, not
   a jump to the bottom. Stop scrolling completely for 2s before cutting away.
4. **Cut only when the screen is settled.** No frames of loading spinners,
   half-rendered graphs, or mid-scroll blur. Known slow: Dashboard 3–4s,
   Infrastructure tab 5s, Settings API Health 3s, process graph 3s. Wait, verify
   content is present, *then* start the shot.
5. **Hold still at the end of each shot.** One second of motionless screen
   before the transition, so the editor has a clean cut point.
6. **Zoom for small type**, hold at zoom for the full dwell, then zoom back
   before moving on. Do not zoom and cut in the same second.
7. **Target 6–7 minutes total.** Give me the running timecode per shot so the
   voice-over script can be written against the real timeline.

Total silence is expected — narration is laid over afterwards. Leave room for
it: a shot that takes 4 seconds to read needs 4 seconds of screen.

### 3b. Direction for FRAME-BASED capture (gif/stills) — fallback only

Use this only if §0 established you have no video tool. Every navigate, click,
scroll, wait and capture costs one frame against a ~50-frame cap.

> **There is no "hold for 15 seconds" here. Dwell time is frame count. A view
> that gets one frame flashes past; a view that matters gets the same frame
> captured three or four times in a row.**

1. **Budget frames, not seconds.** Every shot carries an explicit frame count.
   Total **≤ 46**, leaving 4 spare.
2. **Repeat the capture to extend dwell** — `capture ×4`. This is the only
   pacing control you have.
3. **Never spend a frame on a bare navigation.** Batch navigate + wait + scroll
   into position, *then* capture.
4. **Wait generously before capturing**, per the slow-load list in §3a rule 4.
   A frame spent on a spinner is a frame wasted.
5. **Scroll to the exact element first.** State what must be in frame and what
   must be pushed out of it.
6. **Zoom in for small type** — the network-threat line, the process-details
   panel and the per-rule percentages are unreadable at page zoom in a
   1360-wide GIF.

### 4. Shot list

A numbered table with these columns, in this order:

`#` · `Act` · `Route / action` · `Scroll or zoom target` · `What must be in
frame` · `What must NOT be in frame` · `Hold` · `Narration cue`

`Hold` is **seconds** if you are recording video (§3a), **frames** if you are
not (§3b). Use one unit throughout and say at the top which it is.

Structure it as a story, not a menu tour:

| Act | Content | Video | Frames |
|---|---|---|---|
| 1 | **The problem** — the analyst's queue | 20s | 3 |
| 2 | **Submit** — the form and the collector breadth (I click Investigate, not you) | 30s | 4 |
| 3 | **The verdict** — hero case, AI Case Story, then the prioritised actions | 45s | 6 |
| 4 | **Detonation** — the ANY.RUN act, per the section above | **120s** | **16** |
| 5 | **Corroboration** — TLS SAN list, VirusTotal, Infrastructure pivot | 45s | 6 |
| 6 | **The ATT&CK check** — claimed vs confirmed, then drill into a tactic | 45s | 5 |
| 7 | **Self-measurement** — rule quality, API health | 30s | 4 |
| 8 | **The economics** — work avoided | 25s | 2 |
| 9 | **Close** — static verdict frame | 15s | 2 |

Act 4 gets a third of the budget either way. **If you must cut, cut acts 5, 7
and 8 — never act 4.**

Inside act 4, split it like this and say so in the table:

| Beat | Video | Frames |
|---|---|---|
| Sandbox Verdicts table | 12s | 2 |
| Behaviour counts + the phishing detection row, zoomed | 20s | 3 |
| Screenshot gallery, then one opened full-size | **25s** (≥6s on the open image) | **4** |
| Full-screen process graph, wide establishing | 15s | 2 |
| `msedge.exe` PID 5760 clicked, "Why this process is suspicious" zoomed | **30s** | **3** |
| Contacted IPs / Hosts | 18s | 2 |

**Node to click on the graph:** the red `msedge.exe`, **PID 5760**, in the
bottom cluster. Its panel reads threat level 2, tagged `phishing`, and flags
*Browser HTTPS protections disabled* — concrete and quotable. `svchost.exe` PID
7784 is the fallback only; its panel is generic ("high process threat level")
and makes a weaker shot.

Mark any shot that needs me at the keyboard (anything state-changing) as
`NEEDS OPERATOR`.

### 5. Screens to skip, and why

Do not plan shots on these — recon already established they do not work:

| Screen | Reason |
|---|---|
| Bulk Analysis `/batches` | Empty. Bare upload form, no history. |
| Email `/email-investigations` | Empty. "No previous email investigations yet." |
| Detections → Platform accuracy | n=2, 50% agreement. The number undercuts the "measures itself" claim instead of supporting it. Mention it in narration only. |
| Exclusions, Clients, Alerts, Alert Body detail, AI Assistant session detail | Real client names (Metrorex, Tarom, Revantage, Expertware SRL), real internal hostnames (`EXP-6FSKJR3`, `ExpDC001`, `exprdsh002`) and internal IPs. Cannot be published. |
| All Cases, default sort | Top rows are ten near-identical `185.168.80.149/...favicon.ico` entries. If used at all, filter to Malicious first. |

**One frame-level trap:** on `/detections`, the **Rules tab is the default
landing view**, and one rule's description contains a real Windows username
path (`C:\Users\echelarasu\AppData\...`). A previous recording baked this into
the GIF. Navigate to `/detections` and **switch to ATT&CK coverage before
capturing anything**, or scroll so that row is out of frame.

### 6. Voice-over script

Full script, timed to the shot list, written to be read aloud:

- Professional, calm, specific. A senior analyst explaining to a peer.
- Short sentences. No marketing superlatives, no "revolutionary", no
  "seamlessly", no "empowers".
- Name what is on screen when it appears — the viewer should never wonder what
  they are looking at.
- Lead with what the analyst gets, not what the system does internally.
- Roughly 140 words per minute. Mark pauses as `[pause]` and shot changes as
  `[SHOT n]`.
- **If you recorded video, timecode the script to the actual clip** —
  `[00:42]` against each shot — so narration can be laid over it without
  re-timing. Check each line fits its shot's hold at 140 wpm; if it does not,
  either shorten the line or tell me the shot needs to be longer.
- **Slow down over the sandbox act.** Fewer words, longer pauses, let the
  screenshots and the graph carry it. Do not narrate over the moment the
  full-size phishing screenshot opens — mark it `[pause 2s]`.
- Quote the real artefacts rather than paraphrasing them: the phishing
  network-threat line, the behaviour counts, the process name that fired it.
  Concrete numbers are what make a demo credible.
- End with a single concrete claim, not a call to action.

### 7. Pre-flight list

Before recording starts, what must be true: which pages to pre-load past their
spinners, which filters to pre-set, which tabs to pre-open, what to close,
browser zoom level, and which screens contain data that must not be published.

Confirmed pre-flight items — include these and add anything else you find:

- Open the ANY.RUN screenshot gallery once so all 8 thumbnails are cached.
- Pre-load the Infrastructure tab on the hero case (5s first load).
- Pre-load Dashboard past "Loading dashboard intelligence" (3–4s).
- Refresh Settings → API Health; it returned a server error on first visit once.
- Open `/detections` and switch to **ATT&CK coverage** before any capture, so
  the Rules tab with the real username path is never the landing frame.
- Confirm the full-screen graph renders settled at recording resolution.

### 8. Dry run before you record

Before spending frames on the real recording, walk the shot list once with **no
captures at all** — navigate, wait, scroll and zoom to each target in order, and
confirm at each stop that the intended content is on screen and settled.

Report back: any step where the element was not where the plan said, anything
still loading after the specified wait, and your revised frame total. Only then
record.

## OUTPUT FORMAT

Six sections, in this order: **Recording capability** (§0), **Reconnaissance**,
**Shot list** (table, with the hold column in whichever unit applies),
**Voice-over script**, **Pre-flight**, **Dry-run result**.

State explicitly which recording path you are on — video (§3a) or frame-based
(§3b) — and give the total: running time in minutes:seconds for video, or total
frames with confirmation it is ≤ 46 for frames.

Tell me plainly if any part of the story I asked for is not supported by what is
actually in the app right now. If a shot cannot be made to look good, say so and
drop it rather than filming it badly.
