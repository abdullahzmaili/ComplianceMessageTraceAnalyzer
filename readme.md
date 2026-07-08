# Compliance Message Trace Analyzer

Generate a modern, interactive, self-contained **HTML report** from Exchange Online **Message Trace CSV exports** — with automatic resolution of DLP rules, Sensitive Information Types (SITs), Sensitivity Labels, Server-Side Auto-Labeling (SSAM) rules, and Transport rules.

> ⚠️ **Handle output as CONFIDENTIAL.** The generated report and companion CSVs contain compliance metadata and personal data (senders, recipients, subjects, message IDs). See [Security notice](#-security-notice).

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Parameters](#parameters)
- [How it works](#how-it-works)
- [Output files](#output-files)
- [The HTML report](#the-html-report)
- [Security notice](#-security-notice)
- [Troubleshooting](#troubleshooting)
- [Related docs](#related-docs)
- [License](#license)

---

## Overview

`ComplianceMessageTraceAnalyzer.ps1` reads a Message Trace CSV exported from Exchange Online, parses the `custom_data` field of each record to extract compliance identifiers, optionally resolves those identifiers to human-readable names via Exchange Online / Security & Compliance PowerShell, and produces a single interactive HTML file you can open in any modern browser.

It is designed for compliance investigators, Exchange administrators, and security analysts who need to understand **why** DLP, auto-labeling, or sensitivity labeling behaved a certain way for specific messages.

## Features

- **Auto encoding detection** — handles Unicode/UTF-16, UTF-8, and default-encoded exports.
- **Flexible column mapping** — recognizes many possible column name variants (portal export vs. PowerShell export).
- **Compliance ID extraction** from `custom_data`:
  - DLP execution rule IDs (`S:DPA=DPR`)
  - Server-Side Auto-Labeling rule IDs (`S:MLA=MLR`)
  - Sensitive Information Type DCIDs (`S:DPA=DC`)
  - Sensitivity Label IDs (`S:DPA=DC|labelId=`)
  - Transport rule IDs (`S:TRA=ETR`)
- **Name resolution** (optional) via Exchange Online + Security & Compliance PowerShell:
  - DLP rules & parent policies (mode, scope, priority, workload)
  - SSAM rules & policies (incl. simulation mode)
  - SIT names, publisher, custom/built-in, recommended confidence
  - Sensitivity labels (priority, hierarchy, encryption/marking/watermark settings)
  - Transport rules
- **Interactive HTML report** with five tabs:
  1. **Data Loss Prevention** — rule evaluations, predicates, actions, modes, override tracking.
  2. **Sensitive Information Types** — DCID detections with confidence, count, false-positive risk hints.
  3. **Server-Side Auto Labeling** — auto-label rule matches and predicates.
  4. **Sensitivity Labels** — applied labels, content bits (header/footer/watermark/encryption), label changes.
  5. **Message View** — per-message timeline combining all compliance events, event flow, anti-spam/malware preemption, and bifurcation (fork) details.
- **Per-tab tooling** — full-text search, dropdown filters, column sorting, pagination, clickable summary stats, and **CSV export**.
- **Bifurcation detection** — flags messages forked for external recipients.
- **Decision-tree helpers** — "Why didn't DLP fire?" and "Why was this label applied?".
- **Glossary** — expands DLP predicate/action abbreviations, content bits, confidence levels, and event IDs.
- **Print-friendly** styling for archiving.
- **Authenticode signed** for tamper detection.

## Requirements

- **Windows** with **Windows PowerShell 5.1** (uses `System.Windows.Forms` for the file dialog).
- A **Message Trace CSV** exported from the Microsoft 365 / Exchange admin portal.
- For name resolution only (optional):
  - **ExchangeOnlineManagement** PowerShell module (`Connect-ExchangeOnline`, `Connect-IPPSSession`).
  - A least-privilege admin account (e.g., **Compliance Data Administrator** or **Security Reader**).

Install the Exchange Online module if needed:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Installation

1. Copy `ComplianceMessageTraceAnalyzer.ps1` to a **non-synced** local folder (avoid OneDrive/SharePoint/Desktop sync folders).
2. (Optional) Verify the script signature:

   ```powershell
   Get-AuthenticodeSignature .\ComplianceMessageTraceAnalyzer.ps1
   ```

3. Ensure your execution policy allows running the script for your session:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
   ```

## Usage

Open a file browser to pick the CSV, then run with name resolution:

```powershell
.\ComplianceMessageTraceAnalyzer.ps1
```

Specify the CSV directly:

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv"
```

Provide an admin UPN up front (skips the interactive prompt):

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -AdminUPN "admin@contoso.onmicrosoft.com"
```

Offline mode — parse only, no online lookups:

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -SkipDlpLookup
```

Custom output path and verbose diagnostics:

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -OutputPath "C:\Reports\Report.html" -Verbose
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-CsvPath` | string | No | Path to the Message Trace CSV. If omitted, a file browser dialog opens. |
| `-OutputPath` | string | No | Path for the generated HTML report. Defaults to the CSV path with a `.html` extension. |
| `-AdminUPN` | string | No | Admin UPN used to connect to Exchange Online and Security & Compliance PowerShell. Prompted interactively if needed. |
| `-SkipDlpLookup` | switch | No | Skip all online lookups. Produces the report using only data present in the CSV. |

## How it works

1. **Import** — `Import-MessageTraceCSV` reads the CSV, auto-detecting encoding and cleaning quoted column names.
2. **Map columns** — `Get-ColumnMappings` maps varied column names to canonical fields (DateTime, Sender, Recipient, Subject, CustomData, NetworkMessageId, etc.).
3. **Extract IDs** — `Get-CustomDataIds` uses regex to pull unique DLP, SSAM, DCID, Label, and Transport rule IDs from `custom_data`. Extracted IDs are exported to companion CSVs.
4. **Connect (optional)** — establishes Exchange Online + IPPS sessions once, reusing existing sessions when present.
5. **Resolve names (optional)** — `Get-DlpRuleNames`, `Get-SSAMRuleNames`, `Get-SITNames`, `Get-LabelNames`, and `Get-TransportRuleNames` build ID → metadata maps.
6. **Serialize** — message data and mappings are converted to compact JSON.
7. **Render** — `Get-HtmlContent` returns a full HTML template; JSON is injected via placeholder replacement (`%%JSONDATA%%`, `%%RULENAMEMAPPING%%`, etc.).
8. **Save & open** — writes UTF-8 HTML and offers to open it.

## Output files

Generated in the same directory as the input CSV:

| File | Description |
|------|-------------|
| `<name>.html` | The interactive report (or your `-OutputPath`). |
| `<name>_ExecutionRuleIds.csv` | Unique DLP execution rule IDs found. |
| `<name>_SSAMRuleIds.csv` | Unique Server-Side Auto-Labeling rule IDs found. |
| `<name>_DCIDs.csv` | Unique Sensitive Information Type DCIDs found. |
| `<name>_LabelIds.csv` | Unique Sensitivity Label IDs found. |

> Companion CSVs are only written when the corresponding IDs are found.

## The HTML report

- **Self-contained** — no internet connection or external assets required to view.
- **Tabs** — DLP, SIT, SSAM, Labels, and Message View (see [Features](#features)).
- **Search & filter** — per-tab full-text search plus dropdowns (rule/policy/label name, mode, confidence, bifurcation).
- **Sort & paginate** — clickable sortable headers and adjustable page sizes.
- **Export** — each tab exports the current filtered view to CSV.
- **Glossary** — reference for abbreviations, content bits, confidence levels, and event IDs.

## 🔒 Security notice

- **Least privilege** — run with Compliance Data Administrator or Security Reader; **do not** use Global Admin.
- **Input trust** — only process CSVs you exported directly from the Microsoft 365 admin portal. Do **not** process files from untrusted sources.
- **Output classification** — the HTML and companion CSVs are **CONFIDENTIAL**. They contain DLP identifiers, SIT GUIDs, labels, policy structure, and personal data. Apply your organization's sensitivity label and share only via protected channels.
- **Location** — run from a non-synced directory.
- **Cleanup** — delete output files after review per your retention policy, and disconnect sessions:

  ```powershell
  Disconnect-ExchangeOnline -Confirm:$false
  ```

- **Integrity** — verify the Authenticode signature (Subject `CN=AbdullahZmailiCodeSigningComplianceMessageTraceAnalyzer`, Thumbprint `459E24AAECC4E0EB0BC2C790DEBABA9DB3C1ED2E`).

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| Garbled column names or 0 records | Encoding mismatch — run with `-Verbose` to see detection; re-export as CSV from the portal. |
| "No file selected. Exiting." | The file dialog was cancelled. Re-run and select a CSV, or pass `-CsvPath`. |
| Rule/label names show as "Unknown" | ID not found in tenant, or lookup skipped. Ensure you connected with a valid `-AdminUPN` and adequate permissions. |
| Connection failures | Install/update `ExchangeOnlineManagement`; confirm the account can run `Connect-ExchangeOnline` and `Connect-IPPSSession`. |
| Empty tabs in the report | The CSV had no matching `custom_data` for that compliance type. |
| Script won't run (blocked) | Set a session execution policy: `Set-ExecutionPolicy -Scope Process RemoteSigned`. |

## Related docs

- [instructions.md](instructions.md) — detailed operational guide and reference.
- [quickstart.md](quickstart.md) — get a report in a few minutes.

## License

MIT License. Provided **AS IS**, without warranty of any kind. You are responsible for how you use this script and any outcomes from its execution. See the header of `ComplianceMessageTraceAnalyzer.ps1` for the full disclaimer.
