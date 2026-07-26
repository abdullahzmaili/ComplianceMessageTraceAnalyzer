# Instructions — Compliance Message Trace Analyzer

Detailed operational guidance for running `ComplianceMessageTraceAnalyzer.ps1`, understanding its output, and interpreting the interactive HTML report.

For a fast path, see [quickstart.md](quickstart.md). For an overview, see [readme.md](readme.md).

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Exporting a Message Trace CSV](#2-exporting-a-message-trace-csv)
3. [Running the script](#3-running-the-script)
4. [Execution flow explained](#4-execution-flow-explained)
5. [Understanding the output files](#5-understanding-the-output-files)
6. [Navigating the HTML report](#6-navigating-the-html-report)
7. [Interpreting compliance data](#7-interpreting-compliance-data)
8. [Reference tables](#8-reference-tables)
9. [Security & handling](#9-security--handling)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

- **Windows PowerShell 5.1** on Windows (the file-picker dialog uses `System.Windows.Forms`).
- A **Message Trace CSV** exported from Exchange Online.
- **For name resolution only (optional):**
  - `ExchangeOnlineManagement` module:

    ```powershell
    Install-Module ExchangeOnlineManagement -Scope CurrentUser
    ```

  - A **least-privilege** admin account (Compliance Data Administrator or Security Reader). **Do not** use Global Admin.

Allow the script to run in your session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

(Optional) Verify integrity before first use:

```powershell
Get-AuthenticodeSignature .\ComplianceMessageTraceAnalyzer.ps1
```

Expected: Subject `CN=AbdullahZmailiCodeSigningComplianceMessageTraceAnalyzer`, Thumbprint `459E24AAECC4E0EB0BC2C790DEBABA9DB3C1ED2E`.

## 2. Exporting a Message Trace CSV

1. Go to the **Exchange admin center** → **Mail flow** → **Message trace** (or the Microsoft 365 Defender portal message trace).
2. Run a trace scoped to the messages you want to investigate.
3. For compliance data, request a **detailed / extended** report so the export includes the **`custom_data`** column — this is where DLP, SIT, label, and SSAM identifiers live.
4. **Download** the results as CSV.
5. Save the CSV to a **non-synced** local folder.

> The script parses `custom_data`. Without it, the compliance tabs will be empty (basic message data still renders).

## 3. Running the script

### Interactive (file picker + prompts)

```powershell
.\ComplianceMessageTraceAnalyzer.ps1
```

You'll be asked whether to connect for name resolution and, if yes, for your admin UPN.

### Specify the CSV

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv"
```

### Non-interactive with lookups

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 `
  -CsvPath "C:\Reports\MessageTrace.csv" `
  -AdminUPN "admin@contoso.onmicrosoft.com"
```

### Offline (no online lookups)

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -SkipDlpLookup
```

IDs will be shown, but names appear as "Unknown".

### Custom output + diagnostics

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 `
  -CsvPath "C:\Reports\MessageTrace.csv" `
  -OutputPath "C:\Reports\Investigation.html" `
  -Verbose
```

Use `-Verbose` to see encoding detection and column mapping details.

### Parameter reference

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `-CsvPath` | No | File dialog | Path to the input CSV. |
| `-OutputPath` | No | CSV path with `.html` | Where to write the report. |
| `-AdminUPN` | No | Prompted | UPN for EXO + IPPS connections. |
| `-SkipDlpLookup` | No | Off | Disable all online lookups. |

## 4. Execution flow explained

1. **Resolve input** — uses `-CsvPath` or opens a file dialog; validates the file exists.
2. **Import CSV** — auto-detects encoding (Unicode → UTF-8 → Default) and strips quoted column names.
3. **Map columns** — maps varied header names to canonical fields.
4. **Extract IDs** from `custom_data` via regex and export them to companion CSVs.
5. **Prompt (if needed)** — if no `-AdminUPN` and not `-SkipDlpLookup`, asks whether to connect.
6. **Connect once** — establishes Exchange Online + Security & Compliance sessions, reusing existing ones.
7. **Resolve names** — builds ID → metadata maps for DLP, SSAM, SITs, labels, and transport rules.
8. **Serialize to JSON** — message records and mapping tables.
9. **Render HTML** — injects JSON into the template via placeholder replacement.
10. **Save & open** — writes UTF-8 HTML and offers to open it.

## 5. Understanding the output files

All files are written next to the input CSV (unless `-OutputPath` changes the HTML location):

| File | When produced | Contents |
|------|---------------|----------|
| `<name>.html` | Always | The interactive report. |
| `<name>_ExecutionRuleIds.csv` | DLP rule IDs found | One `ExecutionRuleId` per row. |
| `<name>_SSAMRuleIds.csv` | SSAM rule IDs found | One `SSAMRuleId` per row. |
| `<name>_DCIDs.csv` | DCIDs found | One `DCID` per row. |
| `<name>_LabelIds.csv` | Label IDs found | One `LabelId` per row. |

These companion CSVs are useful for cross-referencing IDs in other tools or scripts.

## 6. Navigating the HTML report

The report opens to the **compliance panel** with five tabs. Each tab count badge shows how many events were detected.

| Tab | Purpose | Key columns |
|-----|---------|-------------|
| **Data Loss Prevention** | DLP rule evaluations | Subject, Sender, Recipient, Rule Name, Policy, Mode, Status, Actions |
| **Sensitive Information Types** | SIT detections | Subject, Sender, Recipient, DCID, SIT Name, Policy, Count, Confidence |
| **Server Side Auto Labeling** | Auto-label rule matches | Subject, Sender, Recipient, Rule Name, Rule ID, Predicate |
| **Sensitivity Labels** | Applied labels | Subject, Sender, Recipient, Label ID, Label Name, Type, Content Bits |
| **Message View** | Per-message timeline | Combined events, event flow, forks, anti-spam/malware |

Common controls on every data tab:

- **Search all fields** — free-text filter (debounced).
- **Dropdown filters** — by rule/policy/label/SIT name, mode, confidence, and bifurcation.
- **Sortable headers** — click to sort ascending/descending.
- **Summary stat cards** — click to filter (e.g., Matched, Not Matched, High Confidence, Bifurcated).
- **Pagination** — Previous/Next with adjustable page size (10/25/50/100).
- **Export CSV** — exports the current filtered view.
- **Reset** — clears filters.
- **Row expansion** — click a row to reveal full details (IDs, policy metadata, predicates, actions, raw `custom_data`).

Below the tabs, the **Glossary & Reference** panel expands to explain abbreviations and codes.

## 7. Interpreting compliance data

### DLP rule status

- **Matched** — the rule produced actions for the message.
- **Not Matched** — the rule was evaluated but its condition was not met. Expand the row for a **"Why didn't DLP fire?"** decision tree (checks AGENTINFO presence, anti-spam/malware preemption, directionality, low-confidence SITs).

### Mode badges

- **Enforce** — actions are applied.
- **Test + Notify / Test Only** — policy is in test mode; actions may not be enforced.

### Confidence levels (SIT)

| Level | Range | Meaning |
|-------|-------|---------|
| High | 85–100% | Very likely a true match. |
| Medium | 65–84% | Probable; review recommended. |
| Low | < 65% | Possible false positive. |

Expanded SIT rows may show **FP Risk** hints (low confidence, single occurrence, custom SIT) and **count vs. unique count** interpretation.

### Content bits (labels)

Content bits are a bitmask of applied protections:

| Bit | Value | Action |
|-----|-------|--------|
| 1 | 1 | Header marking |
| 2 | 2 | Footer marking |
| 3 | 4 | Watermark |
| 4 | 8 | Encryption |

Example: `9` = Header (1) + Encryption (8). The report also verifies applied protections against the label's configured settings and flags **label downgrades** as compliance alerts.

### Bifurcation (forking)

When a message is split for external recipients, each copy gets its own `network_message_id`. Rows are flagged **Bifurcated**, and expanded details list the other network message IDs for the same original message.

### Message View timeline

For each message, the timeline combines DLP, SIT, SSAM, and label events in order, plus:

- **Event flow** (RECEIVE → AGENTINFO → … → DELIVER/DROP).
- **Anti-spam / anti-malware** preemption banners.
- **Distribution list expansion** notes.
- **Connector / protocol** info from source context.
- **Label source** — server auto-label, DLP-applied, or manual/client.

## 8. Reference tables

### Event IDs

| Event | Meaning |
|-------|---------|
| RECEIVE | Message received by transport. |
| AGENTINFO | Transport agents (DLP, rules) processed the message. |
| ROUTING | Routing decision made. |
| DELIVER | Delivered to mailbox. |
| DROP | Message dropped (blocked). |
| EXPAND | Distribution list expansion. |
| REDIRECT | Message redirected. |
| DEFER | Delivery deferred. |
| FAIL | Delivery failed. |

### Common `custom_data` markers

| Marker | Meaning |
|--------|---------|
| `S:DPA=DPR` | DLP policy rule evaluation. |
| `S:DPA=DC` | Sensitive Information Type detection (DCID). |
| `S:DPA=DC\|labelId=` | Sensitivity label application. |
| `S:MLA=MLR` | Server-Side Auto-Labeling rule. |
| `S:TRA=ETR` | Exchange transport rule. |
| `S:DPA=OVR` | DLP policy override. |
| `S:DPA=NOT` | DLP notification. |
| `S:SFA=SUM` | Anti-spam summary. |
| `S:AMA=SUM` | Anti-malware summary. |

> The Glossary panel in the report expands the full DLP predicate and action abbreviations (e.g., `BA` = BlockAccess, `EQ` = ExQuarantine, `ESLA` = ExStampLabelAction).

### Deeper investigation

Message traces don't contain everything. For detection location or label-change justifications, use the Unified Audit Log:

```powershell
Search-UnifiedAuditLog -Operations DlpRuleMatch -StartDate {date} -EndDate {date}
Search-UnifiedAuditLog -Operations SensitivityLabelChanged -StartDate {date} -EndDate {date}
```

## 9. Security & handling

- **Least privilege** — Compliance Data Administrator or Security Reader only.
- **Trusted input** — only CSVs you exported yourself from the M365 admin portal.
- **Confidential output** — apply your organization's sensitivity label; share via protected channels only.
- **Non-synced location** — avoid OneDrive/SharePoint/Desktop sync folders.
- **Cleanup** — delete outputs per retention policy and disconnect sessions:

  ```powershell
  Disconnect-ExchangeOnline -Confirm:$false
  ```

## 10. Troubleshooting

| Symptom | Likely cause | Resolution |
|---------|--------------|-----------|
| 0 records / garbled headers | Encoding mismatch | Run with `-Verbose`; re-export CSV from the portal. |
| Compliance tabs empty | No `custom_data` in export | Re-run trace requesting detailed/extended results. |
| Names show "Unknown" | Lookup skipped or ID not in tenant | Provide a valid `-AdminUPN` with adequate permissions; avoid `-SkipDlpLookup`. |
| Cannot connect to EXO/IPPS | Module missing/outdated | `Install-Module ExchangeOnlineManagement`; retry. |
| Script blocked from running | Execution policy | `Set-ExecutionPolicy -Scope Process RemoteSigned`. |
| File dialog didn't appear | Non-interactive host | Pass `-CsvPath` explicitly. |

---

See also: [readme.md](readme.md) · [quickstart.md](quickstart.md)
