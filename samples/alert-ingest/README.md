# Alert ingest samples

Ten Wazuh-shaped alert documents with the exact key set of the production feed
(`_id`, `title`, `rule.*`, `agent.*`, `data.win.eventdata.*`,
`data.win.system.message`, `_source`, …). Each one exercises a different part of
extraction, so a manual run over the whole folder tells you whether a change to
the parser helped or hurt.

## Sending one

Dry run — parses only, starts no collectors, spends no quota:

```bash
curl -s -X POST "$API/api/alert-investigations/extract" \
     -H "Content-Type: application/json" \
     --data-binary @01-lateral-movement-powershell.json | jq
```

Real run — queues the investigation pipeline:

```bash
curl -s -X POST "$API/api/alert-investigations?dedupe=false" \
     -H "Content-Type: application/json" \
     --data-binary @01-lateral-movement-powershell.json | jq
```

In Postman: **POST**, Body → *raw* → *JSON*, paste the file contents. No
escaping — the document goes in exactly as your SIEM emits it.

## What each sample is for

| # | File | Exercises | Investigable indicators (verified) |
|---|---|---|---|
| 1 | `01-lateral-movement-powershell` | The shape of the real alert you receive; hostname → eTLD+1; digest set | `expertware.net`, sha256 |
| 2 | `02-phishing-click-defanged-url` | Defanged URL (`hxxps://…[.]…`), public destination IP, sender e-mail, **CVE in the rule text** | URL, `myspotifypremium.info`, `evil-corp.com`, `102.135.105.190` |
| 3 | `03-encoded-powershell-dropper` | Base64 `-enc`, hidden window, `certutil` cradle, execution from `\Temp\` | URL, `expertware.net`, sha256 |
| 4 | `04-ransomware-precursor` | `vssadmin delete shadows`, `wevtutil cl`, `taskkill` — behaviour only, no network IOC | `expertware.net`, sha256 |
| 5 | `05-dns-query-deep-subdomain` | Sysmon EID 22; 4-label host under a multi-part TLD; two IPs in `QueryResults` | `evil-corp.co.uk`, two public IPs |
| 6 | `06-c2-beaconing-ipv6` | Sysmon EID 3; **IPv6** alongside IPv4; `.io` domain | `telemetry-sync.io`, `185.220.101.47`, IPv6 |
| 7 | `07-office-spawns-shell` | WINWORD → cmd → PowerShell, `IEX`+`DownloadString`, parent/child chain | URL, `expertware.net`, sha256 |
| 8 | `08-credential-dumping-lsass` | `comsvcs.dll MiniDump` against LSASS at System integrity | `expertware.net`, sha256 |
| 9 | `09-persistence-scheduled-task` | `schtasks /create`, the same URL twice (dedupe), an e-mail in `Details` | URL, `expertware.net`, sha256 |
| 10 | `10-benign-admin-noise` | The quiet case: internal names only, `BOOTX64.EFI`/`mmx64.efi` in the text, no public IOC | `expertware.net`, sha256 |

## Expected endpoint-event verdicts

| Sample | Verdict | Signals |
|---|---|---|
| 1 | suspicious 50 | hidden/unrestricted PowerShell, lateral-movement tooling, recon |
| 2 | inconclusive 0 | a network-connection event has no command line to judge |
| 3 | **malicious 80** | download cradle, encoded PowerShell, hidden window, user-writable path |
| 4 | **malicious 80** | log clearing, backup tampering, forced termination |
| 5 | inconclusive 0 | DNS event — the value is in the indicators |
| 6 | suspicious 50 | binary under `ProgramData` |
| 7 | **malicious 80** | download cradle, in-memory execution, Word spawned a shell |
| 8 | **malicious 80** | credential-store access |
| 9 | **malicious 80** | download cradle, persistence mechanism |
| 10 | benign 25 | elevated integrity only |

## Things worth checking by eye

* **No field names as indicators.** None of `rule.id`, `alert.category`,
  `decoder.name`, `data.win.*` may appear. They are valid-looking domains
  (`.id`, `.name` are real TLDs) and every one would start a full investigation.
* **No file names as indicators** — `BOOTX64.EFI`, `mmx64.efi`, `CBS.log`,
  `a.exe` (sample 10 and 9 contain them deliberately).
* **Private IPs are reported, not investigated** — every sample's `agent.ip` is
  RFC1918 and must come back with `investigable: false`.
* **One file, not three digests.** Each `Hashes:` field carries MD5 + SHA256 +
  IMPHASH; exactly one hash indicator should appear, with the others under
  `other_digests`. An IMPHASH must never be looked up as a file.
* **`expertware.net` appears in all ten** — it comes from
  `data.win.system.computer`. That is correct, and after the first run the
  prior-investigation reuse answers it without spending collectors.
