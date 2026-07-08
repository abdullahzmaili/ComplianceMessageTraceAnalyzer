# Quick Start — Compliance Message Trace Analyzer

Get an interactive compliance report from an Exchange Online Message Trace CSV in a few minutes.

> Full details: [readme.md](readme.md) · [instructions.md](instructions.md)

---

## 1. Prerequisites (1 minute)

- **Windows PowerShell 5.1** (Windows).
- A **Message Trace CSV** exported from Exchange Online with the **`custom_data`** column (choose a detailed/extended trace).
- *(Only for friendly names)* the Exchange Online module:

  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```

## 2. Allow the script to run

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

## 3. Run it

Pick the fastest path for your needs:

**A. Easiest — pick the file, resolve names interactively**

```powershell
.\ComplianceMessageTraceAnalyzer.ps1
```

Answer the prompts (connect? → `Y`, then your admin UPN).

**B. Point at the CSV and provide your UPN (no prompts)**

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -AdminUPN "admin@contoso.onmicrosoft.com"
```

**C. Offline — parse only, no sign-in**

```powershell
.\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -SkipDlpLookup
```

## 4. Open the report

When prompted **"Would you like to open the report now?"**, press `Y`.
The HTML opens in your browser next to the CSV (or at your `-OutputPath`).

## 5. Explore

The report has five tabs:

| Tab | Shows |
|-----|-------|
| **Data Loss Prevention** | DLP rule matches, modes, actions |
| **Sensitive Information Types** | SIT detections + confidence |
| **Server Side Auto Labeling** | Auto-label rule matches |
| **Sensitivity Labels** | Applied labels + protections |
| **Message View** | Per-message timeline of all events |

On any tab you can **search**, **filter**, **sort**, **click summary cards to filter**, **expand rows for full detail**, and **export CSV**.

## What you get

Next to your CSV:

- `MessageTrace.html` — the interactive report
- `MessageTrace_ExecutionRuleIds.csv`, `_SSAMRuleIds.csv`, `_DCIDs.csv`, `_LabelIds.csv` — extracted IDs (when found)

## Cleanup (important)

The outputs are **confidential**. When done:

```powershell
Disconnect-ExchangeOnline -Confirm:$false
```

Delete the report and companion CSVs per your retention policy.

## Common quick fixes

| Problem | Fix |
|---------|-----|
| Empty compliance tabs | Re-export the trace as detailed/extended so `custom_data` is included. |
| Names show "Unknown" | Re-run with a valid `-AdminUPN` (don't use `-SkipDlpLookup`). |
| 0 records / garbled text | Add `-Verbose` and re-export the CSV from the portal. |
| Script won't run | `Set-ExecutionPolicy -Scope Process RemoteSigned`. |

---

Need more? See [instructions.md](instructions.md) for a full walkthrough and reference tables.
