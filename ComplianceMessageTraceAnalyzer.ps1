<#
.SYNOPSIS
    Generates an interactive HTML report from Exchange Online Message Trace CSV exports.

.DESCRIPTION
    This script reads a Message Trace CSV file exported from Exchange Online and creates
    a modern, interactive HTML report with filtering, sorting, and visualization capabilities.

.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks.

.NOTES
    ============================================================
    SECURITY NOTICE
    ============================================================
    
    PERMISSIONS & CREDENTIALS:
    - Run this script with a least-privilege account such as Compliance Data Administrator or Security Reader.
    - Do NOT run with Global Admin credentials.
    - Use the -SkipDlpLookup parameter when compliance lookups are not needed.
    - Always disconnect Exchange Online and IPPS sessions after use (Disconnect-ExchangeOnline).
    
    INPUT TRUST:
    - Only process CSV files that you exported directly from the Microsoft 365 admin portal.
    - Do NOT process CSV files received from third parties or untrusted sources.
    
    OUTPUT CLASSIFICATION:
    - The generated HTML report and companion CSV files contain sensitive compliance metadata
      including DLP rule identifiers, SIT GUIDs, sensitivity labels, and policy structure.
    - Treat all output files as CONFIDENTIAL per your organization's data classification policy.
    - Run the script from a non-synced directory (avoid OneDrive/SharePoint/Desktop sync folders).
    - Delete output files after review per your organization's data retention policy.
    - The HTML report contains personal data (senders, recipients, message subjects, message IDs).
      Apply your organization's appropriate sensitivity label and share only via protected channels.
    
    ENCODING DIAGNOSTICS:
    - Run with -Verbose to see encoding detection details and confirm all records imported correctly.
    
    SIGNATURE VERIFICATION:
    - This script is signed with a self-signed Authenticode certificate for tamper detection.
    - Certificate Subject: CN=AbdullahZmailiCodeSigningComplianceMessageTraceAnalyzer
    - Certificate Thumbprint: 459E24AAECC4E0EB0BC2C790DEBABA9DB3C1ED2E
    - To verify integrity: Get-AuthenticodeSignature .\ComplianceMessageTraceAnalyzer.ps1
    ============================================================

.PARAMETER CsvPath
    Path to the Message Trace CSV file. If not specified, a file browser dialog will open.

.PARAMETER OutputPath
    Path for the generated HTML report. Defaults to same directory as CSV with .html extension.

.PARAMETER AdminUPN
    Admin User Principal Name (UPN) for connecting to Exchange Online and Security & Compliance PowerShell.
    Example: admin@contoso.onmicrosoft.com
    If not provided, you will be prompted interactively.

.PARAMETER SkipDlpLookup
    Skip the DLP rule name lookup. Use this if you don't want to connect to Exchange Online.

.EXAMPLE
    .\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv"

.EXAMPLE
    .\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -AdminUPN "admin@contoso.onmicrosoft.com"

.EXAMPLE
    .\ComplianceMessageTraceAnalyzer.ps1 -CsvPath "C:\Reports\MessageTrace.csv" -SkipDlpLookup

.EXAMPLE
    .\ComplianceMessageTraceAnalyzer.ps1
    # Opens file browser to select CSV file

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$AdminUPN,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDlpLookup
)

#region Show-FileDialog
function Show-FileDialog {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dialog.Title = "Select Message Trace CSV File"
    $dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
    return $null
}
#endregion

#region Get-SafeProperty
function Get-SafeProperty { param($Object, $PropertyName); if ($PropertyName -and $Object.PSObject.Properties[$PropertyName]) { return $Object.$PropertyName }; return "" }
#endregion

#region Import-MessageTraceCSV
# Function to import and clean CSV data with auto-encoding detection
function Import-MessageTraceCSV {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Information -MessageData "Reading Message Trace data from: $Path" -InformationAction Continue

    # Try different encodings - Exchange exports often use Unicode/UTF-16
    $encodings = @('Unicode', 'UTF8', 'Default')
    $rawData = $null

    foreach ($enc in $encodings) {
        try {
            $testData = Import-Csv -Path $Path -Encoding $enc
            if ($testData.Count -gt 0) {
                $firstProp = ($testData | Select-Object -First 1).PSObject.Properties.Name | Select-Object -First 1
                # Check if property name looks reasonable (no null bytes)
                if ($firstProp -and $firstProp.Length -lt 50 -and $firstProp -notmatch '\x00') {
                    $rawData = $testData
                    break
                }
            }
        } catch { Write-Verbose "Non-critical error suppressed: $_" }
    }

    if (-not $rawData) {
        $rawData = Import-Csv -Path $Path
    }

    # Check if column names have embedded quotes and create clean objects
    $firstItem = $rawData | Select-Object -First 1
    $propNames = $firstItem.PSObject.Properties.Name
    $hasQuotedColumns = ($propNames | Where-Object { $_ -match '^"' -or $_ -match '"$' }).Count -gt 0
    if ($hasQuotedColumns) {
        Write-Warning -Message "Detected quoted column names, cleaning..."
        $messageData = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($row in $rawData) {
            $cleanObj = New-Object PSObject
            foreach ($prop in $row.PSObject.Properties) {
                $cleanName = $prop.Name -replace '^"|"$', ''  # Remove leading/trailing quotes
                $cleanValue = if ($prop.Value) { $prop.Value.ToString() -replace '^"|"$', '' } else { "" }
                $cleanObj | Add-Member -NotePropertyName $cleanName -NotePropertyValue $cleanValue -Force
            }
            $messageData.Add($cleanObj)
        }
    } else { $messageData = $rawData }
    Write-Information -MessageData "Successfully loaded $($messageData.Count) records" -InformationAction Continue
    return $messageData
}
#endregion

#region Get-ColumnMappings
function Get-ColumnMappings {
    param([Parameter(Mandatory = $true)][array]$MessageData)
    $availableColumns = $MessageData | Select-Object -First 1 | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    Write-Verbose -Message "Detected columns: $($availableColumns -join ', ')"
    $cleanColumns = @{}; foreach ($col in $availableColumns) { $cleanColumns[$col] = $col }

    # Define column mappings (possible column names for each field)
    $colMappings = @{
        DateTime = @('date_time_utc', 'DateTime', 'Received', 'Date', 'origin_timestamp_utc', 'Timestamp')
        Sender = @('sender_address', 'SenderAddress', 'Sender', 'From', 'sender_from_address', 'P1FromAddress', 'P2FromAddresses')
        Recipient = @('recipient_address', 'RecipientAddress', 'Recipient', 'To', 'Recipients', 'recipient_status')
        Subject = @('message_subject', 'Subject', 'MessageSubject', 'subject')
        EventId = @('event_id', 'EventId', 'Event', 'Status', 'DeliveryStatus', 'EventType')
        Source = @('source', 'Source', 'EventSource')
        Direction = @('directionality', 'Directionality', 'Direction', 'MessageDirection')
        MessageId = @('internet_message_id', 'InternetMessageId', 'message_id', 'MessageId', 'message_trace_id', 'MessageTraceId')
        TotalBytes = @('total_bytes', 'TotalBytes', 'Size', 'MessageSize')
        RecipientCount = @('recipient_count', 'RecipientCount')
        ClientIP = @('client_ip', 'ClientIP', 'original_client_ip', 'OriginalClientIP', 'SenderIP', 'FromIP')
        ServerHostname = @('server_hostname', 'ServerHostname', 'Server')
        RecipientStatus = @('recipient_status', 'RecipientStatus', 'Status', 'DeliveryStatus')
        CustomData = @('custom_data', 'CustomData', 'customdata')
        SourceContext = @('source_context', 'SourceContext')
        MessageInfo = @('message_info', 'MessageInfo')
        TenantId = @('tenant_id', 'TenantId')
        NetworkMessageId = @('network_message_id', 'NetworkMessageId')
    }
    $actualColumns = @{}
    foreach ($key in $colMappings.Keys) {
        $found = $false
        foreach ($possibleName in $colMappings[$key]) {
            if ($found) { break }
            if ($cleanColumns.ContainsKey($possibleName)) { $actualColumns[$key] = $possibleName; $found = $true; break }
        }
        if (-not $found) { $actualColumns[$key] = $null }
    }
    Write-Information -MessageData "Column mapping:" -InformationAction Continue
    $actualColumns.GetEnumerator() | ForEach-Object { Write-Verbose -Message "  $($_.Key): $($_.Value)" }
    return $actualColumns
}
#endregion

#region ConvertTo-MessageTraceJson
function ConvertTo-MessageTraceJson {
    param([Parameter(Mandatory = $true)][array]$MessageData, [Parameter(Mandatory = $true)][hashtable]$ColumnMappings)
    $jsonItems = @($MessageData | ForEach-Object { @{ date_time = Get-SafeProperty $_ $ColumnMappings['DateTime']; sender = Get-SafeProperty $_ $ColumnMappings['Sender']; recipient = Get-SafeProperty $_ $ColumnMappings['Recipient']; subject = Get-SafeProperty $_ $ColumnMappings['Subject']; event_id = Get-SafeProperty $_ $ColumnMappings['EventId']; source = Get-SafeProperty $_ $ColumnMappings['Source']; directionality = Get-SafeProperty $_ $ColumnMappings['Direction']; message_id = Get-SafeProperty $_ $ColumnMappings['MessageId']; total_bytes = Get-SafeProperty $_ $ColumnMappings['TotalBytes']; recipient_count = Get-SafeProperty $_ $ColumnMappings['RecipientCount']; recipient_status = Get-SafeProperty $_ $ColumnMappings['RecipientStatus']; client_ip = Get-SafeProperty $_ $ColumnMappings['ClientIP']; server_hostname = Get-SafeProperty $_ $ColumnMappings['ServerHostname']; original_client_ip = Get-SafeProperty $_ $ColumnMappings['ClientIP']; custom_data = Get-SafeProperty $_ $ColumnMappings['CustomData']; source_context = Get-SafeProperty $_ $ColumnMappings['SourceContext']; message_info = Get-SafeProperty $_ $ColumnMappings['MessageInfo']; tenant_id = Get-SafeProperty $_ $ColumnMappings['TenantId']; network_message_id = Get-SafeProperty $_ $ColumnMappings['NetworkMessageId'] } })
    if ($jsonItems.Count -eq 0) { $jsonData = "[]" } elseif ($jsonItems.Count -eq 1) { $jsonData = "[" + ($jsonItems | ConvertTo-Json -Depth 3 -Compress) + "]" } else { $jsonData = $jsonItems | ConvertTo-Json -Depth 3 -Compress }
    Write-Information -MessageData "Generated JSON with $($jsonItems.Count) items" -InformationAction Continue
    return $jsonData
}
#endregion

#region ConvertTo-MappingJson
function ConvertTo-MappingJson {
    param([Parameter(Mandatory=$true)][hashtable]$Mapping)
    if ($Mapping.Count -eq 0) { return "{}" }
    $obj = @{}; foreach ($key in $Mapping.Keys) { $obj[$key] = $Mapping[$key] }
    return ($obj | ConvertTo-Json -Depth 3 -Compress)
}
#endregion

#region Get-CustomDataIds
function Get-CustomDataIds {
    param(
        [Parameter(Mandatory=$true)][array]$MessageData,
        [Parameter(Mandatory=$true)][hashtable]$ColumnMappings,
        [Parameter(Mandatory=$true)][string]$Pattern,
        [Parameter(Mandatory=$true)][string]$IdType
    )
    $idList = [System.Collections.Generic.List[string]]::new()
    $customDataColumn = $ColumnMappings['CustomData']
    if (-not $customDataColumn) {
        Write-Warning -Message "CustomData column not found. Cannot extract $IdType."
        return @($idList)
    }
    foreach ($msg in $MessageData) {
        $customData = Get-SafeProperty $msg $customDataColumn
        if ($customData) {
            $regexMatches = [regex]::Matches($customData, $Pattern, 'IgnoreCase')
            foreach ($match in $regexMatches) {
                if ($match.Groups.Count -gt 1) {
                    $id = $match.Groups[1].Value
                    if ($id -and -not $idList.Contains($id)) { $idList.Add($id) }
                }
            }
        }
    }
    Write-Information -MessageData "Found $($idList.Count) unique $IdType" -InformationAction Continue
    return @($idList)
}
#endregion

#region Export-IdsToCsv
function Export-IdsToCsv {
    param(
        [Parameter(Mandatory=$true)][array]$Ids,
        [Parameter(Mandatory=$true)][string]$CsvFilePath,
        [Parameter(Mandatory=$true)][string]$ColumnName,
        [Parameter(Mandatory=$true)][string]$FileSuffix
    )
    $outputDir = [System.IO.Path]::GetDirectoryName($CsvFilePath)
    $outputFileName = [System.IO.Path]::GetFileNameWithoutExtension($CsvFilePath) + "_$FileSuffix.csv"
    $outputPath = [System.IO.Path]::Combine($outputDir, $outputFileName)
    $idObjects = $Ids | ForEach-Object { [PSCustomObject]@{ $ColumnName = $_ } }
    $idObjects | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Information -MessageData "Exported $($Ids.Count) unique $ColumnName to: $outputPath" -InformationAction Continue
    return $outputPath
}
#endregion

#region Invoke-ComplianceLookup
function Invoke-ComplianceLookup {
    param(
        [Parameter(Mandatory = $true)][array]$Ids,
        [Parameter(Mandatory = $true)][string]$ItemType,
        [Parameter(Mandatory = $true)][scriptblock]$GetAllItems,
        [Parameter(Mandatory = $true)][scriptblock]$MatchItem,
        [Parameter(Mandatory = $true)][scriptblock]$BuildFoundMapping,
        [Parameter(Mandatory = $true)][scriptblock]$BuildNotFoundMapping,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    $mapping = @{}

    if ($Ids.Count -eq 0) {
        Write-Warning -Message "No $ItemType to look up."
        return $mapping
    }

    if ($SkipLookup) {
        Write-Warning -Message "Skipping $ItemType lookup (SkipDlpLookup specified)."
        return $mapping
    }

    try {
        Write-Information -MessageData "`nRetrieving $ItemType..." -InformationAction Continue
        $allItems = & $GetAllItems
        if (-not $allItems) {
            Write-Warning -Message "Could not retrieve $ItemType."
            return $mapping
        }

        foreach ($id in $Ids) {
            try {
                $match = & $MatchItem $allItems $id
                if ($match) {
                    $mapping[$id] = & $BuildFoundMapping $match
                } else {
                    $mapping[$id] = & $BuildNotFoundMapping
                }
            } catch {
                $mapping[$id] = & $BuildNotFoundMapping
            }
        }
        Write-Information -MessageData "Resolved $($mapping.Count) $ItemType." -InformationAction Continue
    } catch {
        Write-Warning -Message "Error retrieving $ItemType`: $_"
    }

    return $mapping
}
#endregion

#region Get-LabelNames
function Get-LabelNames {
    param(
        [Parameter(Mandatory = $true)][array]$LabelIds,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    return Invoke-ComplianceLookup `
        -Ids $LabelIds `
        -ItemType "Sensitivity Label names for $($LabelIds.Count) Label IDs" `
        -GetAllItems { Get-Label -ErrorAction SilentlyContinue } `
        -MatchItem { param($all, $id) $all | Where-Object { $_.Guid -eq $id } } `
        -BuildFoundMapping {
            param($item)
            @{
                Name = $item.DisplayName
                Priority = $item.Priority
                ParentLabelId = if ($item.ParentId) { $item.ParentId.ToString() } else { $null }
                IsParent = [bool]($item.PSObject.Properties['Settings'] -and $item.Settings)
                Tooltip = $item.Tooltip
                EncryptionEnabled = [bool]($item.EncryptionEnabled)
                ContentMarkingHeaderEnabled = [bool]($item.ContentMarkingHeaderEnabled)
                ContentMarkingFooterEnabled = [bool]($item.ContentMarkingFooterEnabled)
                WatermarkEnabled = [bool]($item.WatermarkingEnabled)
            }
        } `
        -BuildNotFoundMapping {
            @{
                Name = "Unknown Label"
                Priority = $null
                ParentLabelId = $null
                IsParent = $false
                Tooltip = $null
                EncryptionEnabled = $false
                ContentMarkingHeaderEnabled = $false
                ContentMarkingFooterEnabled = $false
                WatermarkEnabled = $false
            }
        } `
        -SkipLookup $SkipLookup
}
#endregion

#region Get-SITNames
function Get-SITNames {
    param(
        [Parameter(Mandatory = $true)][array]$DCIDs,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    return Invoke-ComplianceLookup `
        -Ids $DCIDs `
        -ItemType "Sensitive Information Type names for $($DCIDs.Count) DCIDs" `
        -GetAllItems { Get-DlpSensitiveInformationType -ErrorAction SilentlyContinue } `
        -MatchItem { param($all, $id) $all | Where-Object { $_.Id -eq $id } } `
        -BuildFoundMapping {
            param($item)
            @{
                Name = $item.Name
                Publisher = if ($item.Publisher) { $item.Publisher } else { "Microsoft" }
                Type = if ($item.Type) { $item.Type.ToString() } else { "BuiltIn" }
                IsCustom = ($item.Publisher -and $item.Publisher -ne "Microsoft Corporation" -and $item.Publisher -ne "Microsoft")
                RecommendedConfidence = if ($item.RecommendedConfidence) { $item.RecommendedConfidence } else { $null }
                Description = if ($item.Description) { $item.Description.Substring(0, [Math]::Min(200, $item.Description.Length)) } else { $null }
            }
        } `
        -BuildNotFoundMapping {
            @{
                Name = "Unknown SIT"
                Publisher = $null
                Type = $null
                IsCustom = $false
                RecommendedConfidence = $null
                Description = $null
            }
        } `
        -SkipLookup $SkipLookup
}
#endregion

#region Get-DlpRuleNames
function Get-DlpRuleNames {
    param(
        [Parameter(Mandatory = $true)][array]$ExecutionRuleIds,
        [Parameter(Mandatory = $false)][string]$AdminUPN,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    $ruleNameMapping = @{}

    if ($ExecutionRuleIds.Count -eq 0) {
        Write-Warning -Message "No Execution Rule IDs to look up."
        return $ruleNameMapping
    }

    if ($SkipLookup) {
        Write-Warning -Message "Skipping DLP rule name lookup (SkipDlpLookup specified)."
        return $ruleNameMapping
    }

    Write-Information -MessageData "`nDLP Rule Name Lookup" -InformationAction Continue

    $upn = $AdminUPN
    if (-not $upn) {
        Write-Warning -Message "No UPN provided. Skipping DLP rule name lookup."
        return $ruleNameMapping
    }

    Write-Information -MessageData "Using admin UPN: $upn" -InformationAction Continue

    # Check for existing Exchange Online session
    $existingEXOSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not $existingEXOSession) {
        try {
            Write-Information -MessageData "Connecting to Exchange Online..." -InformationAction Continue
            Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false
        }
        catch {
            Write-Warning -Message "Failed to connect to Exchange Online: $_"
            return $ruleNameMapping
        }
    }

    # Check for existing IPPS session
    $existingIPPS = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*compliance*' -and $_.State -eq 'Opened' }
    if (-not $existingIPPS) {
        try {
            Write-Information -MessageData "Connecting to Security & Compliance PowerShell..." -InformationAction Continue
            Connect-IPPSSession -UserPrincipalName $upn -ShowBanner:$false
        }
        catch {
            Write-Warning -Message "Failed to connect to Security & Compliance PowerShell: $_"
            return $ruleNameMapping
        }
    }

    try {
        Write-Information -MessageData "`nRetrieving DLP Compliance Rules..." -InformationAction Continue
        $allDlpRules = Get-DlpComplianceRule -IncludeExecutionRuleGuids $true
        Write-Information -MessageData "Retrieved $($allDlpRules.Count) DLP Compliance Rules." -InformationAction Continue

        # Retrieve DLP Compliance Policies for mode/scope information
        Write-Information -MessageData "Retrieving DLP Compliance Policies..." -InformationAction Continue
        $allDlpPolicies = @{}
        try {
            $policies = Get-DlpCompliancePolicy
            foreach ($policy in $policies) {
                $allDlpPolicies[$policy.Name] = @{
                    PolicyMode = if ($policy.Mode) { $policy.Mode.ToString() } else { $null }
                    PolicyEnabled = $policy.Enabled
                    PolicyPriority = $policy.Priority
                    PolicyWorkload = if ($policy.Workload) { $policy.Workload.ToString() } else { $null }
                    PolicyExchangeLocation = if ($policy.ExchangeLocation) { ($policy.ExchangeLocation | ForEach-Object { $_.DisplayName }) -join ', ' } else { 'All' }
                    PolicyCreatedBy = $policy.CreatedBy
                    PolicyLastModifiedBy = $policy.LastModifiedBy
                }
            }
        } catch {
            Write-Warning -Message "Warning: Could not retrieve DLP policies: $_"
        }

        foreach ($ruleId in $ExecutionRuleIds) {
            $matchingRule = $allDlpRules | Where-Object { $_.ExecutionRuleGuids -eq $ruleId }
            if ($matchingRule) {
                $ruleNameMapping[$ruleId] = @{
                    Name = $matchingRule.Name
                    Priority = $matchingRule.Priority
                    Workload = $matchingRule.Workload
                    Disabled = $matchingRule.Disabled
                    Mode = if ($matchingRule.Mode) { $matchingRule.Mode.ToString() } else { $null }
                    WhenChangedUTC = if ($matchingRule.WhenChangedUTC) { $matchingRule.WhenChangedUTC.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                    WhenCreated = if ($matchingRule.WhenCreated) { $matchingRule.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                    CreatedBy = $matchingRule.CreatedBy
                    LastModifiedBy = $matchingRule.LastModifiedBy
                    GUID = if ($matchingRule.Guid) { $matchingRule.Guid.ToString() } else { $null }
                    ParentPolicyName = $matchingRule.ParentPolicyName
                    PolicyMode = $null
                    PolicyEnabled = $null
                    PolicyPriority = $null
                    PolicyWorkload = $null
                    PolicyExchangeLocation = $null
                }
                $policyInfo = $allDlpPolicies[$matchingRule.ParentPolicyName]
                if ($policyInfo) {
                    $ruleNameMapping[$ruleId]['PolicyMode'] = $policyInfo.PolicyMode
                    $ruleNameMapping[$ruleId]['PolicyEnabled'] = $policyInfo.PolicyEnabled
                    $ruleNameMapping[$ruleId]['PolicyPriority'] = $policyInfo.PolicyPriority
                    $ruleNameMapping[$ruleId]['PolicyWorkload'] = $policyInfo.PolicyWorkload
                    $ruleNameMapping[$ruleId]['PolicyExchangeLocation'] = $policyInfo.PolicyExchangeLocation
                }
            }
            else {
                $ruleNameMapping[$ruleId] = @{
                    Name = "Unknown Rule"
                    Priority = $null
                    Workload = $null
                    Disabled = $null
                    Mode = $null
                    WhenChangedUTC = $null
                    WhenCreated = $null
                    CreatedBy = $null
                    LastModifiedBy = $null
                    GUID = $null
                    ParentPolicyName = $null
                    PolicyMode = $null
                    PolicyEnabled = $null
                    PolicyPriority = $null
                    PolicyWorkload = $null
                    PolicyExchangeLocation = $null
                }
            }
        }
    }
    catch {
        Write-Warning -Message "Error retrieving DLP rules: $_"
    }

    return $ruleNameMapping
}
#endregion

#region Get-SSAMRuleNames
function Get-SSAMRuleNames {
    param(
        [Parameter(Mandatory = $true)][array]$SSAMRuleIds,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    $ssamRuleNameMapping = @{}

    if ($SSAMRuleIds.Count -eq 0) {
        Write-Warning -Message "No SSAM Rule IDs to look up."
        return $ssamRuleNameMapping
    }

    if ($SkipLookup) {
        Write-Warning -Message "Skipping SSAM rule name lookup (SkipDlpLookup specified)."
        return $ssamRuleNameMapping
    }

    try {
        Write-Information -MessageData "`nRetrieving Auto Sensitivity Label Rules..." -InformationAction Continue
        $allAutoLabelRules = Get-AutoSensitivityLabelRule -IncludeExecutionRuleGuids $true
        Write-Information -MessageData "Retrieved $($allAutoLabelRules.Count) Auto Sensitivity Label Rules." -InformationAction Continue

        # Retrieve Auto Sensitivity Label Policies for mode/scope information
        Write-Information -MessageData "Retrieving Auto Sensitivity Label Policies..." -InformationAction Continue
        $allAutoLabelPolicies = @{}
        try {
            $policies = Get-AutoSensitivityLabelPolicy
            foreach ($policy in $policies) {
                $allAutoLabelPolicies[$policy.Name] = @{
                    PolicyMode = if ($policy.Mode) { $policy.Mode.ToString() } else { $null }
                    PolicyEnabled = $policy.Enabled
                    PolicyPriority = $policy.Priority
                    PolicyWorkload = if ($policy.Workload) { $policy.Workload.ToString() } else { $null }
                    PolicyExchangeLocation = if ($policy.ExchangeLocation) { ($policy.ExchangeLocation | ForEach-Object { $_.DisplayName }) -join ', ' } else { 'All' }
                    SimulationMode = if ($policy.Mode -and $policy.Mode.ToString() -like '*Simulation*') { $true } else { $false }
                }
            }
        } catch {
            Write-Warning -Message "Warning: Could not retrieve Auto Label policies: $_"
        }

        foreach ($ruleId in $SSAMRuleIds) {
            $matchingRule = $allAutoLabelRules | Where-Object { $_.ExecutionRuleGuids -eq $ruleId }
            if ($matchingRule) {
                $ssamRuleNameMapping[$ruleId] = @{
                    Name = $matchingRule.Name
                    Priority = $matchingRule.Priority
                    Workload = $matchingRule.Workload
                    Disabled = $matchingRule.Disabled
                    Mode = if ($matchingRule.Mode) { $matchingRule.Mode.ToString() } else { $null }
                    WhenChangedUTC = if ($matchingRule.WhenChangedUTC) { $matchingRule.WhenChangedUTC.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                    WhenCreated = if ($matchingRule.WhenCreated) { $matchingRule.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                    CreatedBy = $matchingRule.CreatedBy
                    LastModifiedBy = $matchingRule.LastModifiedBy
                    GUID = if ($matchingRule.Guid) { $matchingRule.Guid.ToString() } else { $null }
                    ParentPolicyName = $matchingRule.ParentPolicyName
                    PolicyMode = $null
                    PolicyEnabled = $null
                    PolicyPriority = $null
                    PolicyWorkload = $null
                    PolicyExchangeLocation = $null
                    SimulationMode = $false
                }
                # Enrich with parent policy data
                $policyInfo = $allAutoLabelPolicies[$matchingRule.ParentPolicyName]
                if ($policyInfo) {
                    $ssamRuleNameMapping[$ruleId]['PolicyMode'] = $policyInfo.PolicyMode
                    $ssamRuleNameMapping[$ruleId]['PolicyEnabled'] = $policyInfo.PolicyEnabled
                    $ssamRuleNameMapping[$ruleId]['PolicyPriority'] = $policyInfo.PolicyPriority
                    $ssamRuleNameMapping[$ruleId]['PolicyWorkload'] = $policyInfo.PolicyWorkload
                    $ssamRuleNameMapping[$ruleId]['PolicyExchangeLocation'] = $policyInfo.PolicyExchangeLocation
                    $ssamRuleNameMapping[$ruleId]['SimulationMode'] = $policyInfo.SimulationMode
                }
            }
            else {
                $ssamRuleNameMapping[$ruleId] = @{
                    Name = "Unknown Rule"
                    Priority = $null
                    Workload = $null
                    Disabled = $null
                    Mode = $null
                    WhenChangedUTC = $null
                    WhenCreated = $null
                    CreatedBy = $null
                    LastModifiedBy = $null
                    GUID = $null
                    ParentPolicyName = $null
                    PolicyMode = $null
                    PolicyEnabled = $null
                    PolicyPriority = $null
                    PolicyWorkload = $null
                    PolicyExchangeLocation = $null
                    SimulationMode = $false
                }
            }
        }
    }
    catch {
        Write-Warning -Message "Error retrieving Auto Sensitivity Label rules: $_"
    }

    return $ssamRuleNameMapping
}
#endregion

#region Get-TransportRuleNames
function Get-TransportRuleNames {
    param(
        [Parameter(Mandatory = $true)][array]$TransportRuleIds,
        [Parameter(Mandatory = $false)][bool]$SkipLookup = $false
    )

    return Invoke-ComplianceLookup `
        -Ids $TransportRuleIds `
        -ItemType "Transport Rules" `
        -GetAllItems {
            $rules = Get-TransportRule -ResultSize Unlimited
            Write-Information -MessageData "Retrieved $($rules.Count) Transport Rules." -InformationAction Continue
            return $rules
        } `
        -MatchItem { param($all, $id) $all | Where-Object { $_.Guid -eq $id } } `
        -BuildFoundMapping {
            param($item)
            @{
                Name = $item.Name
                Priority = $item.Priority
                State = if ($item.State) { $item.State.ToString() } else { $null }
                Mode = if ($item.Mode) { $item.Mode.ToString() } else { $null }
                DlpPolicy = $item.DlpPolicy
                IsDlpGenerated = [bool]$item.DlpPolicy
                Comments = $item.Comments
            }
        } `
        -BuildNotFoundMapping {
            @{
                Name = "Unknown Transport Rule"
                Priority = $null
                State = $null
                Mode = $null
                DlpPolicy = $null
                IsDlpGenerated = $false
                Comments = $null
            }
        } `
        -SkipLookup $SkipLookup
}
#endregion

#region Main Script Execution
#region Invoke-MessageTraceReport
function Invoke-MessageTraceReport {
    param(
        [Parameter(Mandatory = $false)][string]$CsvFilePath,
        [Parameter(Mandatory = $false)][string]$OutputFilePath,
        [Parameter(Mandatory = $false)][string]$AdminUPN,
        [Parameter(Mandatory = $false)][bool]$SkipDlpLookup = $false
    )
    if (-not $CsvFilePath) { Write-Information -MessageData "No CSV path provided. Opening file browser..." -InformationAction Continue; $CsvFilePath = Show-FileDialog; if (-not $CsvFilePath) { Write-Warning -Message "No file selected. Exiting."; return } }
    if (-not (Test-Path $CsvFilePath)) { Write-Error -Message "Error: CSV file not found at '$CsvFilePath'"; return }
    if (-not $OutputFilePath) { $OutputFilePath = [System.IO.Path]::ChangeExtension($CsvFilePath, ".html") }
    try { $messageData = Import-MessageTraceCSV -Path $CsvFilePath } catch { Write-Warning -Message "Error reading CSV file: $_"; Write-Warning -Message $_.Exception.Message; return }
    $columnMappings = Get-ColumnMappings -MessageData $messageData

    # Extract unique IDs from CustomData
    $executionRuleIds = @(Get-CustomDataIds -MessageData $messageData -ColumnMappings $columnMappings -Pattern 'S:DPA=DPR\|[^;]*ruleId=([a-f0-9-]+)' -IdType 'Execution Rule IDs')
    if ($executionRuleIds.Count -gt 0) {
        $null = Export-IdsToCsv -Ids $executionRuleIds -CsvFilePath $CsvFilePath -ColumnName 'ExecutionRuleId' -FileSuffix 'ExecutionRuleIds'
    }
    $ssamRuleIds = @(Get-CustomDataIds -MessageData $messageData -ColumnMappings $columnMappings -Pattern 'S:MLA=MLR\|ruleId=([a-f0-9-]+)' -IdType 'Server Side Auto Labeling Rule IDs')
    if ($ssamRuleIds.Count -gt 0) {
        $null = Export-IdsToCsv -Ids $ssamRuleIds -CsvFilePath $CsvFilePath -ColumnName 'SSAMRuleId' -FileSuffix 'SSAMRuleIds'
    }
    $dcids = @(Get-CustomDataIds -MessageData $messageData -ColumnMappings $columnMappings -Pattern 'S:DPA=DC\|(?![^;]*labelId=)[^;]*dcid=([a-f0-9-]+)' -IdType 'DCIDs')
    if ($dcids.Count -gt 0) {
        $null = Export-IdsToCsv -Ids $dcids -CsvFilePath $CsvFilePath -ColumnName 'DCID' -FileSuffix 'DCIDs'
    }
    $labelIds = @(Get-CustomDataIds -MessageData $messageData -ColumnMappings $columnMappings -Pattern 'S:DPA=DC\|labelId=([a-f0-9-]+)' -IdType 'Label IDs')
    if ($labelIds.Count -gt 0) {
        $null = Export-IdsToCsv -Ids $labelIds -CsvFilePath $CsvFilePath -ColumnName 'LabelId' -FileSuffix 'LabelIds'
    }
    $transportRuleIds = @(Get-CustomDataIds -MessageData $messageData -ColumnMappings $columnMappings -Pattern 'S:TRA=ETR\|ruleId=([a-f0-9-]+)' -IdType 'Transport Rule IDs')

    # If AdminUPN is not provided and SkipDlpLookup is not set, prompt user once
    if (-not $AdminUPN -and -not $SkipDlpLookup) {
        Write-Warning -Message "`nTo retrieve DLP rule names, you need to connect to Exchange Online and Security & Compliance PowerShell."
        $connectChoice = Read-Host "`nWould you like to connect and retrieve DLP rule names? (Y/N)"
        if ($connectChoice -ne 'Y' -and $connectChoice -ne 'y') {
            Write-Warning -Message "Skipping DLP rule name lookup."
            $SkipDlpLookup = $true
        } else {
            $AdminUPN = Read-Host "`nEnter your admin UPN (e.g., admin@M365x96455577.onmicrosoft.com)"
            if (-not $AdminUPN) {
                Write-Warning -Message "No UPN provided. Skipping all lookups."
                $SkipDlpLookup = $true
            }
        }
    }

    # Centralized connection management — establish EXO + IPPS sessions before any lookups
    if (-not $SkipDlpLookup -and $AdminUPN) {
        # Check for existing Exchange Online session
        $existingEXOSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingEXOSession) {
            Write-Information -MessageData "`nUsing existing Exchange Online connection." -InformationAction Continue
        } else {
            try {
                Write-Information -MessageData "`nConnecting to Exchange Online..." -InformationAction Continue
                Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false
                Write-Information -MessageData "Connected to Exchange Online successfully." -InformationAction Continue
            }
            catch {
                Write-Warning -Message "Failed to connect to Exchange Online: $_"
                Write-Warning -Message "Skipping all online lookups."
                $SkipDlpLookup = $true
            }
        }
    }
    if (-not $SkipDlpLookup -and $AdminUPN) {
        # Check for existing IPPS session
        $existingIPPS = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and $_.ComputerName -like '*compliance*' -and $_.State -eq 'Opened' }
        if ($existingIPPS) {
            Write-Information -MessageData "Using existing Security & Compliance session." -InformationAction Continue
        } else {
            try {
                Write-Information -MessageData "Connecting to Security & Compliance PowerShell (IPPSSession)..." -InformationAction Continue
                Connect-IPPSSession -UserPrincipalName $AdminUPN -ShowBanner:$false
                Write-Information -MessageData "Connected to Security & Compliance PowerShell successfully." -InformationAction Continue
            }
            catch {
                Write-Warning -Message "Failed to connect to Security & Compliance PowerShell: $_"
                Write-Warning -Message "Some lookups may fail without IPPS session."
            }
        }
    }

    # Get DLP Rule Names
    $ruleNameMapping = @{}
    if ($executionRuleIds.Count -gt 0) {
        $ruleNameMapping = Get-DlpRuleNames -ExecutionRuleIds $executionRuleIds -AdminUPN $AdminUPN -SkipLookup $SkipDlpLookup
    }

    # Get SSAM Rule Names
    $ssamRuleNameMapping = @{}
    if ($ssamRuleIds.Count -gt 0) {
        $ssamRuleNameMapping = Get-SSAMRuleNames -SSAMRuleIds $ssamRuleIds -SkipLookup $SkipDlpLookup
    }

    # Get SIT Names from DCIDs
    $sitNameMapping = @{}
    if ($dcids.Count -gt 0) {
        $sitNameMapping = Get-SITNames -DCIDs $dcids -SkipLookup $SkipDlpLookup
    }

    # Get Label Names from Label IDs
    $labelNameMapping = @{}
    if ($labelIds.Count -gt 0) {
        $labelNameMapping = Get-LabelNames -LabelIds $labelIds -SkipLookup $SkipDlpLookup
    }

    # Get Transport Rule Names
    $transportRuleNameMapping = @{}
    if ($transportRuleIds.Count -gt 0) {
        $transportRuleNameMapping = Get-TransportRuleNames -TransportRuleIds $transportRuleIds -SkipLookup $SkipDlpLookup
    }

    # Convert mappings to JSON for injection into HTML
    $ruleNameMappingJson = ConvertTo-MappingJson -Mapping $ruleNameMapping
    $ssamRuleNameMappingJson = ConvertTo-MappingJson -Mapping $ssamRuleNameMapping
    $sitNameMappingJson = ConvertTo-MappingJson -Mapping $sitNameMapping
    $labelNameMappingJson = ConvertTo-MappingJson -Mapping $labelNameMapping
    $transportRuleNameMappingJson = ConvertTo-MappingJson -Mapping $transportRuleNameMapping

    $jsonData = ConvertTo-MessageTraceJson -MessageData $messageData -ColumnMappings $columnMappings
    $htmlContent = Get-HtmlContent

    $replacements = @{
        '%%JSONDATA%%' = $jsonData
        '%%RULENAMEMAPPING%%' = $ruleNameMappingJson
        '%%SSAMRULENAMEMAPPING%%' = $ssamRuleNameMappingJson
        '%%DCIDNAMEMAPPING%%' = $sitNameMappingJson
        '%%LABELNAMEMAPPING%%' = $labelNameMappingJson
        '%%TRANSPORTRULEMAPPING%%' = $transportRuleNameMappingJson
    }
    foreach ($key in $replacements.Keys) {
        $htmlContent = $htmlContent.Replace($key, $replacements[$key])
    }
    Write-Information -MessageData "HTML content length: $($htmlContent.Length)" -InformationAction Continue
    try { $htmlContent | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force; Write-Information -MessageData "`nReport generated successfully!" -InformationAction Continue; Write-Information -MessageData "Output file: $OutputFilePath" -InformationAction Continue; $openReport = Read-Host "`nWould you like to open the report now? (Y/N)"; if ($openReport -eq 'Y' -or $openReport -eq 'y') { Start-Process $OutputFilePath } } catch { Write-Warning -Message "Error saving HTML report: $_" }
}
#endregion

#region Get-HtmlContent
function Get-HtmlContent {
    param()
    # Helper to generate pagination HTML for a tab
    function Get-PaginationHtml {
        param([string]$Prefix, [string]$Unit = 'entries', [bool]$ShowPageSize = $true)
        $pageSizeHtml = if ($ShowPageSize) {
            @"
                            <select class="filter-select" style="width:auto;padding:4px 8px;font-size:0.8rem;" onchange="changePageSize('$Prefix', this)">
                                <option value="10" selected>10</option>
                                <option value="25">25</option>
                                <option value="50">50</option>
                                <option value="100">100</option>
                            </select>
                            <span> per page</span>
"@
        } else { '' }
        return @"
                    <div class="pagination">
                        <div class="pagination-info">
                            Showing <span id="${Prefix}ShowingStart">0</span> to <span id="${Prefix}ShowingEnd">0</span> of <span id="${Prefix}TotalFiltered">0</span> $Unit
$pageSizeHtml
                        </div>
                        <div class="pagination-controls">
                            <button class="btn btn-secondary" id="${Prefix}PrevBtn" onclick="${Prefix}PreviousPage()">Previous</button>
                            <span id="${Prefix}PageInfo" style="padding: 8px 12px;">Page 1</span>
                            <button class="btn btn-secondary" id="${Prefix}NextBtn" onclick="${Prefix}NextPage()">Next</button>
                        </div>
                    </div>
"@
    }
    $paginationDlpRules = Get-PaginationHtml -Prefix 'dlpRules'
    $paginationDlp = Get-PaginationHtml -Prefix 'dlp'
    $paginationSsam = Get-PaginationHtml -Prefix 'ssam'
    $paginationLabels = Get-PaginationHtml -Prefix 'labels'
    $paginationMv = Get-PaginationHtml -Prefix 'mv' -Unit 'messages' -ShowPageSize $false
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Message Trace</title>
    <style>
:root {
    --bg-primary: #f8f9fa;
    --bg-surface: #ffffff;
    --bg-elevated: #f0f2f5;
    --text-primary: #1a1a2e;
    --text-secondary: #605e5c;
    --accent-blue: #0078d4;
    --accent-green: #107c10;
    --accent-amber: #ff8c00;
    --accent-red: #d13438;
    --accent-purple: #8764b8;
    --border: #e1e1e1;
}

.mode-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
.mode-badge.enforce { background: rgba(76,175,80,0.2); color: #4caf50; }
.mode-badge.test { background: rgba(255,183,77,0.2); color: #ffb74d; }
.mode-badge.test-notify { background: rgba(77,166,255,0.2); color: #4da6ff; }
.predicate-badge { display: inline-block; margin-right: 4px; font-size: 0.8rem; }
.predicate-badge.pass { color: #4caf50; }
.predicate-badge.fail { color: #ef5350; }
.message-view-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }
.message-view-header { background: var(--bg-elevated); padding: 14px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
.message-view-header:hover { background: var(--bg-primary); }
.message-view-body { padding: 16px 20px; display: none; }
.message-view-body.show { display: block; }
.message-timeline { position: relative; padding-left: 30px; }
.timeline-item { position: relative; padding: 8px 0 8px 20px; border-left: 2px solid var(--border); margin-left: 8px; }
.timeline-item:last-child { border-left-color: transparent; }
.timeline-dot { position: absolute; left: -7px; top: 12px; width: 12px; height: 12px; border-radius: 50%; border: 2px solid var(--bg-surface); }
.timeline-dot.dlp { background: var(--accent-blue); }
.timeline-dot.sit { background: var(--accent-amber); }
.timeline-dot.ssam { background: var(--accent-purple); }
.timeline-dot.label { background: var(--accent-green); }
.timeline-dot.transport { background: var(--accent-red); }
.timeline-content { font-size: 0.85rem; color: var(--text-primary); }
.timeline-type { font-weight: 600; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 2px; }
.timeline-detail { color: var(--text-secondary); font-size: 0.8rem; }
.eval-chain { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; margin: 8px 0; }
.eval-step { padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; border: 1px solid var(--border); }
.eval-step.matched { background: rgba(76,175,80,0.15); color: var(--accent-green); border-color: var(--accent-green); }
.eval-step.unmatched { background: rgba(239,83,80,0.15); color: var(--accent-red); border-color: var(--accent-red); }
.eval-arrow { color: var(--text-secondary); font-size: 0.7rem; }
.override-banner { background: rgba(255,183,77,0.15); border: 1px solid var(--accent-amber); border-radius: 8px; padding: 10px 14px; margin: 8px 0; }
.override-banner .override-type { font-weight: 600; color: var(--accent-amber); }
.decision-tree { background: var(--bg-elevated); border-radius: 8px; padding: 14px; margin: 10px 0; }
.decision-tree .dt-title { font-weight: 600; color: var(--accent-amber); margin-bottom: 8px; }
.decision-tree .dt-check { padding: 4px 0; font-size: 0.85rem; }
.decision-tree .dt-check.pass { color: var(--accent-green); }
.decision-tree .dt-check.fail { color: var(--accent-red); }
.decision-tree .dt-check.unknown { color: var(--text-secondary); }
.badge-sm { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; }
.badge-md { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
.direction-badge { }
.direction-badge.outbound { background: rgba(77,166,255,0.2); color: var(--accent-blue); }
.direction-badge.inbound { background: rgba(179,157,219,0.2); color: var(--accent-purple); }
.direction-badge.intraorg { background: rgba(76,175,80,0.2); color: var(--accent-green); }
.custom-sit-badge { background: rgba(255,183,77,0.2); color: var(--accent-amber); margin-left: 4px; }
.label-change-indicator { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; border-radius: 6px; font-size: 0.8rem; }
.label-change-indicator.downgrade { background: rgba(239,83,80,0.15); color: var(--accent-red); }
.label-change-indicator.upgrade { background: rgba(76,175,80,0.15); color: var(--accent-green); }
.event-flow { display: flex; flex-wrap: wrap; gap: 2px; align-items: center; margin: 6px 0; }
.event-flow .ef-step { padding: 3px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
.event-flow .ef-step.receive { background: rgba(77,166,255,0.2); color: var(--accent-blue); }
.event-flow .ef-step.agent { background: rgba(179,157,219,0.2); color: var(--accent-purple); }
.event-flow .ef-step.deliver { background: rgba(76,175,80,0.2); color: var(--accent-green); }
.event-flow .ef-step.drop { background: rgba(239,83,80,0.2); color: var(--accent-red); }
.event-flow .ef-step.other { background: rgba(160,160,176,0.2); color: var(--text-secondary); }
.event-flow .ef-arrow { color: var(--text-secondary); font-size: 0.6rem; padding: 0 2px; }
.label-source-badge { }
.label-source-badge.auto { background: rgba(179,157,219,0.2); color: var(--accent-purple); }
.label-source-badge.manual { background: rgba(77,166,255,0.2); color: var(--accent-blue); }
.ssam-simulation-banner { background: rgba(255,183,77,0.15); border: 1px solid var(--accent-amber); border-radius: 6px; padding: 6px 10px; font-size: 0.8rem; margin: 4px 0; }
@media print {
    body { background: white !important; color: black !important; font-size: 10pt; }
    .pagination, .pagination-controls, .filters, .section-header, .btn { display: none !important; }
    .compliance-panel { display: block !important; page-break-inside: avoid; }
    .compliance-tab { display: none !important; }
    table { font-size: 9pt; }
    th, td { border: 1px solid #ccc !important; padding: 4px !important; }
    .detail-row { display: table-row !important; }
    .detail-row td { display: table-cell !important; }
    a { color: black; text-decoration: underline; }
    :root { --bg-primary: white; --bg-surface: white; --bg-elevated: #f5f5f5; --text-primary: black; --text-secondary: #555; --border: #ccc; }
}
.abbr-tooltip { position: relative; cursor: help; border-bottom: 1px dotted var(--text-secondary); }
.abbr-tooltip:hover::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: var(--bg-elevated); color: var(--text-primary); padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; white-space: nowrap; z-index: 100; border: 1px solid var(--border); box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
th.sortable { cursor: pointer; user-select: none; position: relative; }
th.sortable:hover { background: var(--bg-elevated); }
th.sortable::after { content: '\21C5'; position: absolute; right: 6px; opacity: 0.3; font-size: 0.7rem; }
th.sortable.sort-asc::after { content: '\2191'; opacity: 1; }
th.sortable.sort-desc::after { content: '\2193'; opacity: 1; }
.filter-chips { display: flex; flex-wrap: wrap; gap: 4px; padding: 4px 20px; }
.filter-chip { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; background: var(--accent-blue); color: white; cursor: pointer; }
.filter-chip:hover { opacity: 0.8; }
.filter-chip .chip-remove { font-weight: bold; font-size: 0.85rem; }
tr.table-row:focus-visible { outline: 2px solid var(--accent-blue); outline-offset: -2px; }
.compliance-tab:focus-visible { outline: 2px solid var(--accent-blue); outline-offset: 2px; }
.notification-badge { background: rgba(77,166,255,0.2); color: var(--accent-blue); }
.fp-risk-badge { background: rgba(255,183,77,0.25); color: var(--accent-amber); }
.incident-link { color: var(--accent-blue); text-decoration: none; font-size: 0.8rem; }
.incident-link:hover { text-decoration: underline; }
.system-msg-badge { background: rgba(160,160,176,0.2); color: var(--text-secondary); }
.journal-badge { background: rgba(179,157,219,0.2); color: var(--accent-purple); }
.slow-badge { background: rgba(239,83,80,0.15); color: var(--accent-red); }
.info-note { background: var(--bg-elevated); border-left: 3px solid var(--accent-blue); padding: 8px 12px; margin: 6px 0; font-size: 0.8rem; color: var(--text-secondary); border-radius: 0 6px 6px 0; }
.cross-ref-link { color: var(--accent-purple); cursor: pointer; font-size: 0.8rem; text-decoration: none; }
.cross-ref-link:hover { text-decoration: underline; }
:root{--primary-color:#0078d4;--secondary-color:#106ebe;--success-color:#107c10;--warning-color:#ff8c00;--danger-color:#d13438;--bg-color:#f3f2f1;--card-bg:#fff;--text-color:#323130;--text-muted:#605e5c;--border-color:#edebe9}*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background-color:var(--bg-color);color:var(--text-color);line-height:1.6}.container{max-width:1600px;margin:0 auto;padding:20px}header{background:linear-gradient(135deg,var(--primary-color),var(--secondary-color));color:#fff;padding:30px;border-radius:12px;margin-bottom:24px;box-shadow:0 4px 12px rgba(0,120,212,0.3)}header h1{font-size:2rem;font-weight:600;margin-bottom:8px}header p{opacity:0.9;font-size:0.95rem}.stats-grid{display:grid;grid-template-columns:repeat(8,1fr);gap:16px;margin-bottom:24px}.stat-card{background:var(--card-bg);padding:20px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);border-left:4px solid var(--primary-color);transition:transform 0.2s,box-shadow 0.2s}.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,0.12)}.stat-card.clickable{cursor:pointer}.stat-card.clickable:hover{background:linear-gradient(135deg,rgba(0,120,212,0.05),rgba(0,120,212,0.1));border-left-width:6px}.stat-card.clickable.active{background:linear-gradient(135deg,rgba(0,120,212,0.1),rgba(0,120,212,0.15));box-shadow:0 4px 20px rgba(0,120,212,0.25)}.stat-card.success{border-left-color:var(--success-color)}.stat-card.warning{border-left-color:var(--warning-color)}.stat-card.danger{border-left-color:var(--danger-color)}.stat-value{font-size:2rem;font-weight:700;color:var(--primary-color)}.stat-label{color:var(--text-muted);font-size:0.875rem;text-transform:uppercase;letter-spacing:0.5px}.charts-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}.chart-card{background:var(--card-bg);padding:16px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08)}.chart-card h3{color:var(--text-color);margin-bottom:12px;font-weight:600;font-size:0.95rem}.chart-container{position:relative;height:250px}.data-section{background:var(--card-bg);border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden}.section-header{padding:20px 24px;background:var(--bg-color);border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}.section-header h2{font-weight:600;font-size:1.25rem}.filters{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.filter-input{padding:8px 12px;border:1px solid var(--border-color);border-radius:6px;font-size:0.875rem;min-width:200px;transition:border-color 0.2s,box-shadow 0.2s}.filter-input:focus{outline:none;border-color:var(--primary-color);box-shadow:0 0 0 3px rgba(0,120,212,0.1)}.filter-select{padding:8px 12px;border:1px solid var(--border-color);border-radius:6px;font-size:0.875rem;background:#fff;cursor:pointer}.btn{padding:8px 16px;border:none;border-radius:6px;font-size:0.875rem;cursor:pointer;transition:background-color 0.2s}.btn-primary{background:var(--primary-color);color:#fff}.btn-primary:hover{background:var(--secondary-color)}.btn-secondary{background:var(--bg-color);color:var(--text-color);border:1px solid var(--border-color)}.btn-secondary:hover{background:var(--border-color)}.table-container{overflow-x:auto;max-height:600px;overflow-y:auto}table{width:100%;border-collapse:collapse;font-size:0.875rem}th{background:var(--bg-color);padding:12px 16px;text-align:left;font-weight:600;color:var(--text-color);border-bottom:2px solid var(--border-color);position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}th:hover{background:var(--border-color)}th::after{content:'';margin-left:8px}th.sort-asc::after{content:'\25B2'}th.sort-desc::after{content:'\25BC'}td{padding:12px 16px;border-bottom:1px solid var(--border-color);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tr:hover{background:rgba(0,120,212,0.04)}.badge{display:inline-block;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase}.badge-deliver{background:#dff6dd;color:#107c10}.badge-receive{background:#deecf9;color:#0078d4}.badge-send{background:#fff4ce;color:#d29200}.badge-fail{background:#fde7e9;color:#d13438}.badge-incoming{background:#e1dfdd;color:#323130}.badge-outgoing{background:#f3f2f1;color:#605e5c}.pagination{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;background:var(--bg-color);border-top:1px solid var(--border-color)}.pagination-info{color:var(--text-muted);font-size:0.875rem}.pagination-controls{display:flex;gap:8px}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:1000;justify-content:center;align-items:center;backdrop-filter:blur(4px);animation:modalFadeIn 0.2s ease-out}@keyframes modalFadeIn{from{opacity:0}to{opacity:1}}@keyframes modalSlideIn{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}.modal.active{display:flex}.modal-content{background:var(--card-bg);border-radius:16px;max-width:900px;width:95%;max-height:85vh;overflow-y:auto;box-shadow:0 25px 50px rgba(0,0,0,0.25);animation:modalSlideIn 0.3s ease-out}.modal-header{padding:0;border-bottom:none;position:relative}.modal-header-bg{padding:24px 28px;background:linear-gradient(135deg,var(--primary-color),var(--secondary-color));color:#fff;border-radius:16px 16px 0 0}.modal-header-bg.event-deliver{background:linear-gradient(135deg,#107c10,#0e6b0e)}.modal-header-bg.event-receive{background:linear-gradient(135deg,#0078d4,#106ebe)}.modal-header-bg.event-send{background:linear-gradient(135deg,#ff8c00,#d27500)}.modal-header-bg.event-fail{background:linear-gradient(135deg,#d13438,#a52a2d)}.modal-header h3{font-weight:600;font-size:1.1rem;margin-bottom:4px}.modal-subject{font-size:1.25rem;font-weight:700;margin-top:8px;line-height:1.3;word-break:break-word}.modal-meta{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}.modal-meta-item{display:flex;align-items:center;gap:6px;font-size:0.875rem;opacity:0.9}.modal-close{position:absolute;top:16px;right:16px;background:rgba(255,255,255,0.2);border:none;font-size:1.25rem;cursor:pointer;color:#fff;padding:8px 12px;border-radius:8px;transition:background 0.2s}.modal-close:hover{background:rgba(255,255,255,0.3)}.modal-body{padding:24px 28px;padding-bottom:80px}.modal-footer{padding:16px 28px;border-top:1px solid var(--border-color);display:flex;justify-content:center;background:var(--card-bg);position:sticky;bottom:0;box-shadow:0 -4px 12px rgba(0,0,0,0.1)}.detail-section{margin-bottom:20px;border:1px solid var(--border-color);border-radius:12px;background:var(--card-bg);box-shadow:0 2px 8px rgba(0,0,0,0.06);overflow:hidden}.detail-section:last-child{margin-bottom:0}.detail-section-header{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,var(--primary-color),var(--secondary-color));border-bottom:1px solid var(--border-color);color:#fff}.detail-section-header.section-subject{background:linear-gradient(135deg,#8764b8,#6b4c9a)}.detail-section-header.section-participants{background:linear-gradient(135deg,#107c10,#0e6b0e)}.detail-section-header.section-message{background:linear-gradient(135deg,#0078d4,#106ebe)}.detail-section-header.section-delivery{background:linear-gradient(135deg,#ff8c00,#d27500)}.detail-section-header.section-technical{background:linear-gradient(135deg,#00b7c3,#009ca6)}.detail-section-header.section-custom{background:linear-gradient(135deg,#d13438,#a52a2d)}.detail-section.collapsed .detail-section-header{border-bottom:none}.detail-section-icon{font-size:1.25rem}.detail-section-title{font-weight:600;font-size:1rem;flex-grow:1;color:#fff}.detail-toggle-btn{padding:6px 14px;border:1px solid #fff;background:rgba(255,255,255,0.2);color:#fff;border-radius:6px;font-size:0.75rem;font-weight:600;cursor:pointer;transition:all 0.2s;display:flex;align-items:center;gap:6px}.detail-toggle-btn:hover{background:rgba(255,255,255,0.3);color:#fff}.detail-toggle-btn.hide-btn{background:rgba(255,255,255,0.3);color:#fff}.detail-toggle-btn.hide-btn:hover{background:rgba(255,255,255,0.4);border-color:#fff}.detail-section.collapsed .detail-section-content{display:none}.detail-section-content{padding:16px 20px;background:#fafbfc}.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.detail-item{padding:14px 16px;background:#fff;border-radius:10px;border:1px solid var(--border-color);transition:all 0.2s;position:relative}.detail-item:hover{border-color:var(--primary-color);box-shadow:0 2px 8px rgba(0,120,212,0.1)}.detail-item.full-width{grid-column:1/-1}.detail-item-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}.detail-label{display:flex;align-items:center;gap:6px;font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;font-weight:600}.detail-label-icon{font-size:0.875rem}.detail-value{font-size:0.9rem;word-break:break-all;color:var(--text-color);line-height:1.5}.detail-value.monospace{font-family:'Consolas','Monaco',monospace;font-size:0.8rem;background:#e8e8e8;padding:8px 10px;border-radius:6px;margin-top:4px}.copy-btn{background:none;border:1px solid var(--border-color);padding:4px 8px;border-radius:4px;cursor:pointer;font-size:0.7rem;color:var(--text-muted);transition:all 0.2s;display:flex;align-items:center;gap:4px}.copy-btn:hover{background:var(--primary-color);color:#fff;border-color:var(--primary-color)}.copy-btn.copied{background:var(--success-color);color:#fff;border-color:var(--success-color)}.status-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:0.8rem;font-weight:600}.status-badge.deliver{background:#dff6dd;color:#107c10}.status-badge.receive{background:#deecf9;color:#0078d4}.status-badge.send{background:#fff4ce;color:#d29200}.status-badge.fail{background:#fde7e9;color:#d13438}.direction-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:0.8rem;font-weight:600;background:#e8e8e8}.direction-badge.incoming{background:#deecf9;color:#0078d4}.direction-badge.outgoing{background:#fff4ce;color:#d29200}.custom-data-section{margin-top:20px;border-top:1px solid var(--border-color)}.custom-data-container{display:grid;grid-template-columns:1fr;gap:16px}.custom-data-block{background:var(--bg-color);border-radius:8px;padding:12px;border-left:4px solid var(--primary-color)}.custom-data-header{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}.custom-data-key{font-weight:600;color:var(--primary-color);cursor:help}.custom-data-code{font-family:'Consolas',monospace;font-size:0.75rem;color:var(--text-muted);background:#e0e0e0;padding:2px 6px;border-radius:4px}.custom-data-value{font-size:0.875rem;padding:8px;background:#fff;border-radius:4px;word-break:break-word}.custom-data-table{width:100%;font-size:0.8rem;border-collapse:collapse}.custom-data-table td{padding:6px 8px;border-bottom:1px solid var(--border-color);vertical-align:top}.custom-data-table tr:last-child td{border-bottom:none}.custom-data-table .sub-key{font-weight:500;color:var(--text-color);width:40%;background:rgba(0,120,212,0.05);cursor:help}.custom-data-table .sub-value{color:var(--text-muted);word-break:break-all}.code-hint{font-family:'Consolas',monospace;font-size:0.7rem;color:#888}.raw-data-details{margin-top:16px}.raw-data-details summary{cursor:pointer;color:var(--primary-color);font-size:0.875rem;padding:8px;background:var(--bg-color);border-radius:4px}.raw-data-details summary:hover{background:#e0e0e0}.raw-data-pre{margin-top:8px;padding:12px;background:#2d2d2d;color:#f0f0f0;border-radius:6px;font-family:'Consolas',monospace;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto}.loading{text-align:center;padding:40px;color:var(--text-muted)}.export-buttons{display:flex;gap:8px}.nav-menu{position:sticky;top:0;z-index:100;background:var(--card-bg);padding:12px 20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,0.1);display:flex;gap:8px;flex-wrap:wrap;justify-content:center}.nav-btn{padding:10px 20px;border:none;border-radius:6px;font-size:0.9rem;font-weight:600;cursor:pointer;transition:all 0.2s;display:flex;align-items:center;gap:8px;background:var(--bg-color);color:var(--text-color);border:1px solid var(--border-color)}.nav-btn:hover{background:var(--primary-color);color:#fff;border-color:var(--primary-color);transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,120,212,0.3)}.nav-btn.active{background:var(--primary-color);color:#fff;border-color:var(--primary-color)}.nav-btn .nav-icon{font-size:1.1rem}.journey-section{background:var(--card-bg);border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1);margin-bottom:24px;overflow:hidden}.journey-header{padding:24px;background:linear-gradient(135deg,#667eea,#764ba2);border-bottom:none}.journey-header h2{font-weight:600;font-size:1.4rem;margin-bottom:16px;color:#fff;display:flex;align-items:center;gap:12px}.journey-search{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.journey-search input{flex:1;min-width:300px;padding:14px 20px;border:none;border-radius:10px;font-size:1rem;background:rgba(255,255,255,0.95);box-shadow:0 2px 10px rgba(0,0,0,0.1);transition:all 0.3s}.journey-search input:focus{outline:none;box-shadow:0 4px 20px rgba(0,0,0,0.15);transform:translateY(-1px)}.journey-search input::placeholder{color:#999}.journey-search button{padding:14px 28px;font-size:1rem;border-radius:10px;font-weight:600;transition:all 0.3s}.journey-search .btn-primary{background:rgba(255,255,255,0.2);border:2px solid #fff;color:#fff}.journey-search .btn-primary:hover{background:#fff;color:#667eea}.journey-search .btn-secondary{background:transparent;border:2px solid rgba(255,255,255,0.5);color:#fff}.journey-search .btn-secondary:hover{background:rgba(255,255,255,0.1);border-color:#fff}.journey-results{padding:24px;background:#f8f9fa}.journey-empty{text-align:center;padding:80px 20px;color:var(--text-muted);background:linear-gradient(180deg,#fff,#f8f9fa);border-radius:16px;border:2px dashed var(--border-color)}.journey-empty-icon{font-size:5rem;margin-bottom:20px;opacity:0.4;animation:float 3s ease-in-out infinite}@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}@keyframes slideIn{from{opacity:0;transform:translateX(-20px)}to{opacity:1;transform:translateX(0)}}@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.1)}}.journey-card{background:#fff;border-radius:16px;padding:0;margin-bottom:24px;box-shadow:0 4px 20px rgba(0,0,0,0.08);overflow:hidden;animation:slideIn 0.4s ease-out;border:1px solid rgba(0,0,0,0.05)}.journey-card-header{padding:24px;background:linear-gradient(135deg,#f8f9fa,#fff);border-bottom:1px solid var(--border-color)}.journey-card-title{font-size:1.2rem;font-weight:700;color:var(--text-color);word-break:break-word;margin-bottom:12px;line-height:1.4}.journey-card-meta{display:flex;gap:20px;flex-wrap:wrap;font-size:0.9rem;color:var(--text-muted)}.journey-card-meta span{display:flex;align-items:center;gap:6px;background:#f0f0f0;padding:6px 12px;border-radius:20px}.journey-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;padding:20px 24px;background:linear-gradient(135deg,#667eea,#764ba2);margin:0}.journey-summary-item{text-align:center;color:#fff}.journey-summary-value{font-size:1.8rem;font-weight:700;display:block}.journey-summary-label{font-size:0.8rem;opacity:0.9;text-transform:uppercase;letter-spacing:1px}.journey-flow{padding:24px;background:#fff}.journey-flow-visual{display:flex;align-items:center;justify-content:center;gap:8px;padding:20px;background:linear-gradient(135deg,#f8f9fa,#fff);border-radius:12px;margin-bottom:24px;flex-wrap:wrap}.journey-flow-node{display:flex;flex-direction:column;align-items:center;gap:8px;padding:16px 20px;background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.08);transition:all 0.3s;cursor:pointer;min-width:100px;border:2px solid transparent}.journey-flow-node:hover{transform:translateY(-4px);box-shadow:0 8px 25px rgba(0,0,0,0.15)}.journey-flow-node.active{border-color:var(--primary-color);background:rgba(0,120,212,0.05)}.journey-flow-node.deliver{border-color:var(--success-color)}.journey-flow-node.fail{border-color:var(--danger-color)}.journey-flow-node-icon{font-size:2rem}.journey-flow-node-label{font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted)}.journey-flow-arrow{font-size:1.5rem;color:var(--border-color);animation:arrowMove 1s ease-in-out infinite}@keyframes arrowMove{0%,100%{transform:translateX(0);opacity:0.5}50%{transform:translateX(5px);opacity:1}}.journey-timeline{position:relative;padding:0 24px 24px}.journey-timeline-line{position:absolute;left:47px;top:0;bottom:24px;width:3px;background:linear-gradient(180deg,var(--primary-color),var(--success-color));border-radius:3px}.journey-step{position:relative;padding-left:60px;padding-bottom:24px;animation:slideIn 0.4s ease-out backwards}.journey-step:nth-child(1){animation-delay:0.1s}.journey-step:nth-child(2){animation-delay:0.2s}.journey-step:nth-child(3){animation-delay:0.3s}.journey-step:nth-child(4){animation-delay:0.4s}.journey-step:nth-child(5){animation-delay:0.5s}.journey-step:last-child{padding-bottom:0}.journey-step-dot{position:absolute;left:0;top:0;width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1rem;color:#fff;z-index:2;box-shadow:0 4px 15px rgba(0,0,0,0.2);transition:all 0.3s;cursor:pointer}.journey-step-dot:hover{transform:scale(1.15)}.journey-step-dot.deliver{background:linear-gradient(135deg,#10b981,#059669)}.journey-step-dot.receive{background:linear-gradient(135deg,#3b82f6,#2563eb)}.journey-step-dot.send{background:linear-gradient(135deg,#f59e0b,#d97706)}.journey-step-dot.fail,.journey-step-dot.defer{background:linear-gradient(135deg,#ef4444,#dc2626)}.journey-step-dot.default{background:linear-gradient(135deg,#6b7280,#4b5563)}.journey-step-connector{position:absolute;left:18px;top:40px;bottom:-24px;width:4px;background:linear-gradient(180deg,currentColor,var(--border-color))}.journey-step:last-child .journey-step-connector{display:none}.journey-step-content{background:#fff;border-radius:12px;padding:20px;border:1px solid var(--border-color);transition:all 0.3s;cursor:pointer;position:relative;overflow:hidden}.journey-step-content::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:var(--primary-color);opacity:0;transition:opacity 0.3s}.journey-step-content:hover{box-shadow:0 8px 25px rgba(0,0,0,0.1);transform:translateX(4px)}.journey-step-content:hover::before{opacity:1}.journey-step-content.expanded{background:#f8f9fa}.journey-step-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:12px}.journey-step-event{font-weight:700;font-size:0.95rem;padding:8px 16px;border-radius:20px;display:inline-flex;align-items:center;gap:8px}.journey-step-event.deliver{background:#d1fae5;color:#065f46}.journey-step-event.receive{background:#dbeafe;color:#1e40af}.journey-step-event.send{background:#fef3c7;color:#92400e}.journey-step-event.fail,.journey-step-event.defer{background:#fee2e2;color:#991b1b}.journey-step-event.default{background:#f3f4f6;color:#374151}.journey-step-time{font-size:0.85rem;color:var(--text-muted);display:flex;align-items:center;gap:6px;background:#f3f4f6;padding:6px 12px;border-radius:6px}.journey-step-details{display:none;margin-top:16px;padding-top:16px;border-top:1px dashed var(--border-color);animation:slideIn 0.3s ease-out}.journey-step-details.show{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.journey-step-detail{background:#f8f9fa;padding:12px;border-radius:8px;transition:all 0.2s}.journey-step-detail:hover{background:#f0f0f0}.journey-step-detail-label{font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;font-weight:600}.journey-step-detail-value{font-size:0.9rem;color:var(--text-color);word-break:break-all;font-weight:500}.journey-step-expand{font-size:0.8rem;color:var(--primary-color);cursor:pointer;display:flex;align-items:center;gap:4px;margin-top:12px;font-weight:600;transition:all 0.2s}.journey-step-expand:hover{color:var(--secondary-color)}.journey-ids{padding:20px 24px;background:#f8f9fa;border-top:1px solid var(--border-color)}.journey-ids-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}.journey-id-item{background:#fff;padding:16px;border-radius:10px;border:1px solid var(--border-color)}.journey-id-label{font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;font-weight:600}.journey-id-value{font-family:'Consolas',monospace;font-size:0.85rem;color:var(--text-color);word-break:break-all;background:#f8f9fa;padding:10px;border-radius:6px;cursor:pointer;transition:all 0.2s;display:flex;justify-content:space-between;align-items:center;gap:8px}.journey-id-value:hover{background:#e8e8e8}.journey-id-copy{font-size:0.7rem;color:var(--primary-color);white-space:nowrap}.journey-no-results{text-align:center;padding:60px;color:var(--text-muted);background:#fff;border-radius:16px;border:2px dashed var(--border-color)}.journey-no-results .journey-empty-icon{animation:float 3s ease-in-out infinite}.compliance-section{background:var(--card-bg);border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1);margin-bottom:24px;overflow:hidden}.compliance-header{padding:24px;background:linear-gradient(135deg,#e74c3c,#c0392b);border-bottom:none}.compliance-header h2{font-weight:600;font-size:1.4rem;margin-bottom:8px;color:#fff;display:flex;align-items:center;gap:12px}.compliance-header p{color:rgba(255,255,255,0.9);font-size:0.9rem}.compliance-tabs{display:flex;gap:0;background:#f8f9fa;border-bottom:1px solid var(--border-color)}.compliance-tab{flex:1;padding:16px 24px;background:transparent;border:none;font-size:0.95rem;font-weight:600;cursor:pointer;transition:all 0.3s;color:var(--text-muted);border-bottom:3px solid transparent;display:flex;align-items:center;justify-content:center;gap:8px}.compliance-tab:hover{background:#fff;color:var(--text-color)}.compliance-tab.active{background:#fff;color:var(--primary-color);border-bottom-color:var(--primary-color)}.compliance-tab-icon{font-size:1.2rem}.compliance-tab-count{background:var(--primary-color);color:#fff;padding:2px 8px;border-radius:12px;font-size:0.75rem;min-width:24px;text-align:center}.compliance-content{padding:24px}.compliance-panel{display:none;animation:slideIn 0.3s ease-out}.compliance-panel.active{display:block}.compliance-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}.compliance-stat{background:linear-gradient(135deg,#f8f9fa,#fff);padding:20px;border-radius:12px;border:1px solid var(--border-color);text-align:center;transition:all 0.3s}.compliance-stat:hover{transform:translateY(-2px);box-shadow:0 4px 15px rgba(0,0,0,0.1)}.compliance-stat.clickable{cursor:pointer}.compliance-stat.clickable:hover{background:linear-gradient(135deg,rgba(0,120,212,0.1),rgba(0,120,212,0.15))}.compliance-stat.clickable.active{background:linear-gradient(135deg,rgba(0,120,212,0.15),rgba(0,120,212,0.2));box-shadow:0 4px 20px rgba(0,120,212,0.25);border-color:var(--primary-color)}.compliance-stat-value{font-size:2rem;font-weight:700;color:var(--primary-color);display:block}.compliance-stat-label{font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px}.compliance-stat.warning .compliance-stat-value{color:var(--warning-color)}.compliance-stat.danger .compliance-stat-value{color:var(--danger-color)}.compliance-stat.success .compliance-stat-value{color:var(--success-color)}.compliance-table-container{background:#fff;border-radius:12px;border:1px solid var(--border-color);overflow:hidden}.compliance-table{width:100%;border-collapse:collapse}.compliance-table th{background:linear-gradient(135deg,#f8f9fa,#fff);padding:14px 16px;text-align:left;font-weight:600;font-size:0.85rem;color:var(--text-color);border-bottom:2px solid var(--border-color)}.compliance-table td{padding:14px 16px;border-bottom:1px solid var(--border-color);font-size:0.9rem}.compliance-table tr:hover{background:rgba(0,120,212,0.04)}.compliance-table tr:last-child td{border-bottom:none}.confidence-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:0.8rem;font-weight:600}.confidence-high{background:#d1fae5;color:#065f46}.confidence-medium{background:#fef3c7;color:#92400e}.confidence-low{background:#fee2e2;color:#991b1b}.label-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px;font-size:0.85rem;font-weight:500;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}.content-bits-badge{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;font-size:0.75rem;font-weight:600;background:#f3f4f6;color:#374151;margin:2px}.content-bits-badge.encryption{background:#fee2e2;color:#991b1b}.content-bits-badge.watermark{background:#dbeafe;color:#1e40af}.content-bits-badge.header{background:#d1fae5;color:#065f46}.content-bits-badge.footer{background:#fef3c7;color:#92400e}.sit-id{font-family:'Consolas',monospace;font-size:0.8rem;color:var(--text-muted);word-break:break-all}.compliance-detail-row{cursor:pointer;transition:all 0.2s}.compliance-detail-row:hover{background:rgba(0,120,212,0.08)}.compliance-expand-icon{transition:transform 0.3s}.compliance-detail-row.expanded .compliance-expand-icon{transform:rotate(90deg)}.compliance-detail-content{display:none;background:#f8f9fa;padding:16px;border-bottom:1px solid var(--border-color)}.compliance-detail-content.show{display:block}.compliance-detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}.compliance-detail-item{background:#fff;padding:12px;border-radius:8px;border:1px solid var(--border-color);overflow:hidden;min-width:0}.compliance-detail-label{font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;font-weight:600}.compliance-detail-value{font-size:0.9rem;color:var(--text-color);word-break:break-word;overflow-wrap:break-word;white-space:normal}.compliance-empty{text-align:center;padding:60px 20px;color:var(--text-muted)}.compliance-empty-icon{font-size:4rem;margin-bottom:16px;opacity:0.4}.dlp-rule-status{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:0.8rem;font-weight:600}.dlp-rule-status.matched{background:#d1fae5;color:#065f46}.dlp-rule-status.not-matched{background:#fee2e2;color:#991b1b}.dlp-actions-list,.dlp-predicates-list{max-height:100px;overflow-y:auto;font-size:0.8rem;display:flex;flex-wrap:wrap}.dlp-predicates-list{max-width:200px}.dlp-action-item,.dlp-predicate-item{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;margin:2px 4px 2px 0;background:#f3f4f6;border-radius:4px;font-family:'Consolas',monospace;font-size:0.75rem;white-space:nowrap;width:fit-content}.dlp-action-item{background:#d1fae5;color:#065f46}.dlp-predicate-item{background:#dbeafe;color:#1e40af}.dlp-predicate-item.compact{font-size:0.7rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:3px 6px}.dlp-rule-detail-row{cursor:pointer;transition:all 0.2s}.dlp-rule-detail-row:hover{background:rgba(0,120,212,0.08)}.dlp-rule-expand-icon{transition:transform 0.3s}.dlp-rule-detail-row.expanded .dlp-rule-expand-icon{transform:rotate(90deg)}.dlp-rule-detail-content{display:none;background:#f8f9fa;padding:16px;border-bottom:1px solid var(--border-color)}.dlp-rule-detail-content.show{display:block}.fork-badge{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:20px;font-size:0.75rem;font-weight:600}.fork-badge.no-fork{background:#f3f4f6;color:#6b7280}.fork-badge.forked{background:#fef3c7;color:#92400e}.fork-badge.multi-fork{background:#fee2e2;color:#991b1b}.fork-network-id{font-family:'Consolas',monospace;font-size:0.8rem;background:#f3f4f6;padding:4px 8px;border-radius:4px;margin:2px;display:inline-block;word-break:break-all}.fork-network-id.current{background:#dbeafe;color:#1e40af;font-weight:600}@media(max-width:1400px){.charts-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:768px){.charts-grid{grid-template-columns:1fr}.filters{flex-direction:column;width:100%}.filter-input,.filter-select{width:100%}.nav-menu{flex-direction:column}.nav-btn{width:100%;justify-content:center}.journey-search{flex-direction:column}.journey-search input{min-width:100%}.journey-flow-visual{flex-direction:column}.journey-flow-arrow{transform:rotate(90deg)}.journey-summary{grid-template-columns:repeat(2,1fr)}}
    </style>
</head>
<body>
    <div class="container">
        <div id="compliance-section"class="compliance-section">
            <div class="compliance-header">
                <h2>&#128274; Compliance Message Trace</h2>
                <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Data Loss Prevention, Sensitive Information Types (SIT), and Sensitivity Labels detected in messages</p>
            </div>
            <div class="compliance-tabs">
                <button class="compliance-tab active" tabindex="0" role="tab" onclick="switchComplianceTab('dlpRules', this)">
                    <span class="compliance-tab-icon">&#128737;</span>
                    Data Loss Prevention
                    <span class="compliance-tab-count" id="dlpRulesCount">0</span>
                </button>
                <button class="compliance-tab" tabindex="0" role="tab" onclick="switchComplianceTab('dlp', this)">
                    <span class="compliance-tab-icon">&#128373;</span>
                    Sensitive Information Types
                    <span class="compliance-tab-count" id="dlpCount">0</span>
                </button>
                <button class="compliance-tab" tabindex="0" role="tab" onclick="switchComplianceTab('ssam', this)">
                    <span class="compliance-tab-icon">&#127991;</span>
                    Server Side Auto Labeling
                    <span class="compliance-tab-count" id="ssamCount">0</span>
                </button>
                <button class="compliance-tab" tabindex="0" role="tab" onclick="switchComplianceTab('labels', this)">
                    <span class="compliance-tab-icon">&#127991;</span>
                    Sensitivity Labels
                    <span class="compliance-tab-count" id="labelsCount">0</span>
                </button>
                <button class="compliance-tab" tabindex="0" role="tab" onclick="switchComplianceTab('messageView', this)">
                    <span class="compliance-tab-icon">&#128231;</span>
                    Message View
                    <span class="compliance-tab-count" id="messageViewCount">0</span>
                </button>
            </div>
            <div class="compliance-content">
                <div id="dlpRulesPanel" class="compliance-panel active">
                    <div class="compliance-summary" id="dlpRulesSummary"></div>
                    <div class="section-header" style="background:#fff;padding:16px 20px;">
                        <div class="filters">
                            <input type="text" class="filter-input" id="dlpRulesFilterAll" placeholder="&#128269; Search all fields..." oninput="debouncedFilterDLPRules()" style="min-width:250px;">
                            <select class="filter-select" id="dlpRulesFilterRuleName" onchange="filterDLPRulesTable()">
                                <option value="">All Rule Names</option>
                            </select>
                            <select class="filter-select" id="dlpRulesFilterPolicyName" onchange="filterDLPRulesTable()">
                                <option value="">All Policies</option>
                            </select>
                            <select class="filter-select" id="dlpRulesFilterMatch" onchange="filterDLPRulesTable()">
                                <option value="">All Statuses</option>
                                <option value="matched">Matched (Has Actions)</option>
                                <option value="notmatched">Not Matched</option>
                            </select>
                            <select class="filter-select" id="dlpRulesFilterMode" onchange="filterDLPRulesTable()">
                                <option value="">All Modes</option>
                                <option value="Enforce">Enforce</option>
                                <option value="TestWithNotifications">Test with Notifications</option>
                                <option value="TestWithoutNotifications">Test without Notifications</option>
                            </select>
                            <select class="filter-select" id="dlpRulesFilterBifurcated" onchange="filterDLPRulesTable()">
                                <option value="">Bifurcated?</option>
                                <option value="yes">Bifurcated</option>
                                <option value="no">Not Bifurcated</option>
                            </select>

                        </div>
                        <div class="export-buttons">
                            <button class="btn btn-secondary" onclick="resetDLPRulesFilters()">&#10005; Reset</button>
                            <button class="btn btn-primary" onclick="exportDLPRulesToCSV()">&#128190; Export CSV</button>
                        </div>
                    </div>
                    <div class="compliance-table-container">
                        <table class="compliance-table">
                            <thead>
                                <tr>
                                    <th style="width:30px"></th>
                                    <th class="sortable" onclick="sortTableData('dlpRules', filteredDLPRulesData, filterDLPRulesTable, renderDLPRulesTable, 'subject', this)">Subject</th>
                                    <th class="sortable" onclick="sortTableData('dlpRules', filteredDLPRulesData, filterDLPRulesTable, renderDLPRulesTable, 'sender', this)">Sender</th>
                                    <th class="sortable" onclick="sortTableData('dlpRules', filteredDLPRulesData, filterDLPRulesTable, renderDLPRulesTable, 'recipient', this)">Recipient</th>
                                    <th>Rule Name</th>
                                    <th>Policy Name</th>
                                    <th>Mode</th>
                                    <th class="sortable" onclick="sortTableData('dlpRules', filteredDLPRulesData, filterDLPRulesTable, renderDLPRulesTable, 'matched', this)">Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="dlpRulesTableBody"></tbody>
                        </table>
                    </div>
$paginationDlpRules
                </div>
                <div id="dlpPanel" class="compliance-panel">
                    <div class="compliance-summary" id="dlpSummary"></div>
                    <div class="section-header" style="background:#fff;padding:16px 20px;">
                        <div class="filters">
                            <input type="text" class="filter-input" id="dlpFilterAll" placeholder="&#128269; Search all fields..." oninput="debouncedFilterDLP()" style="min-width:250px;">
                            <select class="filter-select" id="dlpFilterSITName" onchange="filterDLPTable()">
                                <option value="">All SIT Names</option>
                            </select>
                            <select class="filter-select" id="dlpFilterPolicyName" onchange="filterDLPTable()">
                                <option value="">All Policy Names</option>
                            </select>
                            <select class="filter-select" id="dlpFilterBifurcated" onchange="filterDLPTable()">
                                <option value="">Bifurcated?</option>
                                <option value="yes">Bifurcated</option>
                                <option value="no">Not Bifurcated</option>
                            </select>
                        </div>
                        <div class="export-buttons">
                            <button class="btn btn-secondary" onclick="resetDLPFilters()">&#10005; Reset</button>
                            <button class="btn btn-primary" onclick="exportDLPToCSV()">&#128190; Export CSV</button>
                        </div>
                    </div>
                    <div class="compliance-table-container">
                        <table class="compliance-table">
                            <thead>
                                <tr>
                                    <th style="width:30px"></th>
                                    <th class="sortable" onclick="sortTableData('dlp', filteredDLPData, filterDLPTable, renderDLPTable, 'subject', this)">Subject</th>
                                    <th class="sortable" onclick="sortTableData('dlp', filteredDLPData, filterDLPTable, renderDLPTable, 'sender', this)">Sender</th>
                                    <th class="sortable" onclick="sortTableData('dlp', filteredDLPData, filterDLPTable, renderDLPTable, 'recipient', this)">Recipient</th>
                                    <th>DCID</th>
                                    <th>SIT Name</th>
                                    <th>Policy Name</th>
                                    <th>Count</th>
                                    <th class="sortable" onclick="sortTableData('dlp', filteredDLPData, filterDLPTable, renderDLPTable, 'confidence', this)">Confidence</th>
                                </tr>
                            </thead>
                            <tbody id="dlpTableBody"></tbody>
                        </table>
                    </div>
$paginationDlp
                </div>
                <div id="ssamPanel" class="compliance-panel">
                    <div class="compliance-summary" id="ssamSummary"></div>
                    <div class="section-header" style="background:#fff;padding:16px 20px;">
                        <div class="filters">
                            <input type="text" class="filter-input" id="ssamFilterAll" placeholder="&#128269; Search all fields..." oninput="debouncedFilterSSAM()" style="min-width:250px;">
                            <select class="filter-select" id="ssamFilterRuleName" onchange="filterSSAMTable()"><option value="">All Rule Names</option></select>
                            <select class="filter-select" id="ssamFilterPolicyName" onchange="filterSSAMTable()"><option value="">All Policy Names</option></select>
                            <select class="filter-select" id="ssamFilterBifurcated" onchange="filterSSAMTable()"><option value="">Bifurcated?</option><option value="yes">Bifurcated</option><option value="no">Not Bifurcated</option></select>
                        </div>
                        <div class="export-buttons">
                            <button class="btn btn-secondary" onclick="resetSSAMFilters()">&#10005; Reset</button>
                            <button class="btn btn-primary" onclick="exportSSAMToCSV()">&#128190; Export CSV</button>
                        </div>
                    </div>
                    <div class="compliance-table-container">
                        <table class="compliance-table">
                            <thead>
                                <tr>
                                    <th style="width:30px"></th>
                                    <th class="sortable" onclick="sortTableData('ssam', filteredSSAMData, filterSSAMTable, renderSSAMTable, 'subject', this)">Subject</th>
                                    <th class="sortable" onclick="sortTableData('ssam', filteredSSAMData, filterSSAMTable, renderSSAMTable, 'sender', this)">Sender</th>
                                    <th class="sortable" onclick="sortTableData('ssam', filteredSSAMData, filterSSAMTable, renderSSAMTable, 'recipient', this)">Recipient</th>
                                    <th>Rule Name</th>
                                    <th>Rule ID</th>
                                    <th>Predicate</th>
                                </tr>
                            </thead>
                            <tbody id="ssamTableBody"></tbody>
                        </table>
                    </div>
$paginationSsam
                </div>
                <div id="labelsPanel" class="compliance-panel">
                    <div class="compliance-summary" id="labelsSummary"></div>
                    <div class="section-header" style="background:#fff;padding:16px 20px;">
                        <div class="filters">
                            <input type="text" class="filter-input" id="labelsFilterAll" placeholder="&#128269; Search all fields..." oninput="debouncedFilterLabels()" style="min-width:250px;">
                            <select class="filter-select" id="labelsFilterLabelName" onchange="filterLabelsTable()">
                                <option value="">All Label Names</option>
                            </select>
                            <select class="filter-select" id="labelsFilterBifurcated" onchange="filterLabelsTable()">
                                <option value="">Bifurcated?</option>
                                <option value="yes">Bifurcated</option>
                                <option value="no">Not Bifurcated</option>
                            </select>
                        </div>
                        <div class="export-buttons">
                            <button class="btn btn-secondary" onclick="resetLabelsFilters()">&#10005; Reset</button>
                            <button class="btn btn-primary" onclick="exportLabelsToCSV()">&#128190; Export CSV</button>
                        </div>
                    </div>
                    <div class="compliance-table-container">
                        <table class="compliance-table">
                            <thead>
                                <tr>
                                    <th style="width:30px"></th>
                                    <th class="sortable" onclick="sortTableData('labels', filteredLabelsData, filterLabelsTable, renderLabelsTable, 'subject', this)">Subject</th>
                                    <th class="sortable" onclick="sortTableData('labels', filteredLabelsData, filterLabelsTable, renderLabelsTable, 'sender', this)">Sender</th>
                                    <th class="sortable" onclick="sortTableData('labels', filteredLabelsData, filterLabelsTable, renderLabelsTable, 'recipient', this)">Recipient</th>
                                    <th>Label ID</th>
                                    <th>Label Name</th>
                                    <th>Label Type</th>
                                    <th>Content Bits</th>
                                </tr>
                            </thead>
                            <tbody id="labelsTableBody"></tbody>
                        </table>
                    </div>
$paginationLabels
                </div>
                <div id="messageViewPanel" class="compliance-panel">
                    <div class="section-header" style="background:#fff;padding:16px 20px;">
                        <div class="filters">
                            <input type="text" class="filter-input" id="messageViewFilter" placeholder="&#128269; Search by subject, sender, message ID..." oninput="debouncedFilterMV()" style="min-width:350px;">
                        </div>
                    </div>
                    <div id="messageViewContent" style="padding: 16px;"></div>
$paginationMv
                </div>
            </div>
        </div>
        <div id="glossaryPanel" style="margin-top:20px;">
            <button class="compliance-tab" style="width:100%;text-align:left;padding:12px 20px;" onclick="document.getElementById('glossaryContent').style.display = document.getElementById('glossaryContent').style.display === 'none' ? 'block' : 'none'">&#128214; Glossary &amp; Reference</button>
            <div id="glossaryContent" style="display:none;background:var(--bg-surface);border:1px solid var(--border);border-radius:0 0 8px 8px;padding:20px;">
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(300px, 1fr));gap:20px;">
                    <div>
                        <h4 style="color:var(--accent-blue);margin-bottom:8px;">DLP Predicate Abbreviations</h4>
                        <div id="glossaryPredicates" style="font-size:0.8rem;color:var(--text-primary);"></div>
                    </div>
                    <div>
                        <h4 style="color:var(--accent-green);margin-bottom:8px;">DLP Action Abbreviations</h4>
                        <div id="glossaryActions" style="font-size:0.8rem;color:var(--text-primary);"></div>
                    </div>
                    <div>
                        <h4 style="color:var(--accent-purple);margin-bottom:8px;">Content Bits Reference</h4>
                        <div style="font-size:0.8rem;color:var(--text-primary);">
                            <div><strong>Bit 1 (1):</strong> Header Marking</div>
                            <div><strong>Bit 2 (2):</strong> Footer Marking</div>
                            <div><strong>Bit 3 (4):</strong> Watermark</div>
                            <div><strong>Bit 4 (8):</strong> Encryption</div>
                        </div>
                        <h4 style="color:var(--accent-amber);margin-top:12px;margin-bottom:8px;">Confidence Levels</h4>
                        <div style="font-size:0.8rem;color:var(--text-primary);">
                            <div><span style="color:var(--accent-green);">&#9679;</span> <strong>High (85-100%):</strong> Very likely a true match</div>
                            <div><span style="color:var(--accent-amber);">&#9679;</span> <strong>Medium (65-84%):</strong> Probable match, review recommended</div>
                            <div><span style="color:var(--accent-red);">&#9679;</span> <strong>Low (&lt;65%):</strong> Possible false positive</div>
                        </div>
                        <h4 style="color:var(--accent-red);margin-top:12px;margin-bottom:8px;">Event ID Reference</h4>
                        <div style="font-size:0.8rem;color:var(--text-primary);">
                            <div><strong>RECEIVE:</strong> Message received by transport</div>
                            <div><strong>AGENTINFO:</strong> Transport agents (DLP, rules) processed</div>
                            <div><strong>ROUTING:</strong> Routing decision made</div>
                            <div><strong>DELIVER:</strong> Delivered to mailbox</div>
                            <div><strong>DROP:</strong> Message dropped (blocked)</div>
                            <div><strong>EXPAND:</strong> Distribution list expansion</div>
                            <div><strong>REDIRECT:</strong> Message redirected</div>
                            <div><strong>DEFER:</strong> Delivery deferred</div>
                            <div><strong>FAIL:</strong> Delivery failed</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Data
        let rawData = [];
        let ruleNameMapping = {};
        let ssamRuleNameMapping = {};
        let dcidNameMapping = {};
        let labelNameMapping = {};
        let transportRuleMapping = {};

        // Helper to ensure array
        function ensureArray(data) {
            if (!data) return [];
            if (Array.isArray(data)) return data;
            return [data];
        }

        try {
            rawData = ensureArray(%%JSONDATA%%);
            ruleNameMapping = %%RULENAMEMAPPING%%;
            ssamRuleNameMapping = %%SSAMRULENAMEMAPPING%%;
            dcidNameMapping = %%DCIDNAMEMAPPING%%;
            labelNameMapping = %%LABELNAMEMAPPING%%;
            transportRuleMapping = %%TRANSPORTRULEMAPPING%%;
            console.log('Data loaded successfully. Records:', rawData.length);
            console.log('Rule name mappings loaded:', Object.keys(ruleNameMapping).length);
            console.log('SSAM rule name mappings loaded:', Object.keys(ssamRuleNameMapping).length);
            console.log('DCID name mappings loaded:', Object.keys(dcidNameMapping).length);
            console.log('Label name mappings loaded:', Object.keys(labelNameMapping).length);
            console.log('Transport rule mappings loaded:', Object.keys(transportRuleMapping).length);
        } catch(e) {
            console.error('Error parsing data:', e);
            alert('Error loading data: ' + e.message);
        }

        // Build bifurcation map: detect forked messages via recipient_status
        // Also track message_id -> Set of network_message_ids for fork details
        let bifurcationMap = {};       // message_id -> Set of network_message_ids
        let bifurcatedMsgIds = {};     // message_id -> true if recipient_status indicates forking
        let forkedExternalMsgIds = {}; // message_id -> true if recipient_status contains "Message forked: External Recipients"
        function buildBifurcationMap() {
            bifurcationMap = {};
            bifurcatedMsgIds = {};
            forkedExternalMsgIds = {};
            rawData.forEach(function(msg) {
                const msgId = (msg.message_id || '').toLowerCase().trim();
                const netId = (msg.network_message_id || '').trim();
                if (!msgId) return;
                // Track network_message_ids per message_id
                if (netId) {
                    if (!bifurcationMap[msgId]) bifurcationMap[msgId] = new Set();
                    bifurcationMap[msgId].add(netId);
                }
                // Check recipient_status for fork indicator
                const rs = (msg.recipient_status || '').toLowerCase();
                if (rs.includes('message forked')) {
                    bifurcatedMsgIds[msgId] = true;
                }
                // Track "Message forked: External Recipients" specifically
                if (rs.includes('message forked: external recipients')) {
                    forkedExternalMsgIds[msgId] = true;
                }
            });
            const forkedCount = Object.keys(bifurcatedMsgIds).length;
            const forkedExtCount = Object.keys(forkedExternalMsgIds).length;
            console.log('Bifurcation map built:', Object.keys(bifurcationMap).length, 'unique message IDs,', forkedCount, 'bifurcated messages,', forkedExtCount, 'forked external recipients');
        }
        try { buildBifurcationMap(); } catch(e) { console.error('Error building bifurcation map:', e); }

        // Get bifurcation info for a given message
        // isBifurcated is true only when recipient_status contains "Message forked"
        function getBifurcationInfo(messageId, networkMessageId) {
            const msgId = (messageId || '').toLowerCase().trim();
            const netId = (networkMessageId || '').trim();
            const isBifurcated = !!bifurcatedMsgIds[msgId];
            const isForkedExternal = !!forkedExternalMsgIds[msgId];
            const networkIds = bifurcationMap[msgId];
            if (!isBifurcated) return { isBifurcated: false, isForkedExternal: false, otherForks: [] };
            const otherForks = [];
            if (networkIds) { networkIds.forEach(function(id) { if (id !== netId) otherForks.push(id); }); }
            return { isBifurcated: true, isForkedExternal: isForkedExternal, otherForks: otherForks };
        }

        // Helper function to get rule name from mapping
        function getRuleName(ruleId) {
            if (!ruleId) return 'N/A';
            const ruleInfo = ruleNameMapping[ruleId];
            if (!ruleInfo) return 'N/A';
            // Handle both old format (string) and new format (object)
            if (typeof ruleInfo === 'string') return ruleInfo;
            return ruleInfo.Name || 'N/A';
        }

        // Helper function to get full rule info object
        function getRuleInfo(ruleId) {
            if (!ruleId) return null;
            const ruleInfo = ruleNameMapping[ruleId];
            if (!ruleInfo) return null;
            // Handle old format (string) - convert to object
            if (typeof ruleInfo === 'string') {
                return { Name: ruleInfo, Priority: null, Workload: null, Disabled: null, Mode: null, WhenChangedUTC: null, WhenCreated: null, CreatedBy: null, LastModifiedBy: null, GUID: null, ParentPolicyName: null };
            }
            return ruleInfo;
        }
        // Helper function to get SSAM rule name from mapping
        function getSSAMRuleName(ruleId) {
            if (!ruleId) return 'N/A';
            const ruleInfo = ssamRuleNameMapping[ruleId];
            if (!ruleInfo) return 'N/A';
            if (typeof ruleInfo === 'string') return ruleInfo;
            return ruleInfo.Name || 'N/A';
        }

        // Helper function to get SSAM parent policy name from mapping
        function getSSAMPolicyName(ruleId) {
            if (!ruleId) return 'N/A';
            const ruleInfo = ssamRuleNameMapping[ruleId];
            if (!ruleInfo) return 'N/A';
            if (typeof ruleInfo === 'string') return 'N/A';
            return ruleInfo.ParentPolicyName || 'N/A';
        }

        // Helper function to get full SSAM rule info object
        function getSSAMRuleInfo(ruleId) {
            if (!ruleId) return null;
            const ruleInfo = ssamRuleNameMapping[ruleId];
            if (!ruleInfo) return null;
            if (typeof ruleInfo === 'string') {
                return { Name: ruleInfo, Priority: null, Workload: null, Disabled: null, Mode: null, WhenChangedUTC: null, WhenCreated: null, CreatedBy: null, LastModifiedBy: null, GUID: null, ParentPolicyName: null };
            }
            return ruleInfo;
        }
        // Phase 2: New parsing and helper functions
        function parseOverridesFromCustomData(customData) {
            const overrides = [];
            if (!customData) return overrides;
            const ovrRegex = /S:DPA=OVR\|ruleId=([a-f0-9-]+)(?:\|overrideType=([^|;]+))?(?:\|justification=([^|;]+))?/gi;
            let m;
            while ((m = ovrRegex.exec(customData)) !== null) {
                overrides.push({
                    ruleId: m[1],
                    overrideType: m[2] || 'Unknown',
                    justification: m[3] ? decodeURIComponent(m[3].replace(/\+/g, ' ')) : ''
                });
            }
            return overrides;
        }

        function parseSFAFromCustomData(customData) {
            if (!customData) return null;
            const sfaMatch = customData.match(/S:SFA=SUM\|([^;]+)/i);
            if (!sfaMatch) return null;
            const parts = sfaMatch[1].split('|');
            const result = { action: '', reason: '', scl: '' };
            parts.forEach(p => {
                const [k, v] = p.split('=');
                if (k === 'action') result.action = v;
                else if (k === 'reason') result.reason = v;
                else if (k === 'scl') result.scl = v;
            });
            return result;
        }

        function parseAMAFromCustomData(customData) {
            if (!customData) return null;
            const amaMatch = customData.match(/S:AMA=SUM\|([^;]+)/i);
            if (!amaMatch) return null;
            const parts = amaMatch[1].split('|');
            const result = { action: '', reason: '' };
            parts.forEach(p => {
                const [k, v] = p.split('=');
                if (k === 'action') result.action = v;
                else if (k === 'reason') result.reason = v;
            });
            return result;
        }

        function parseMEPFromCustomData(customData) {
            if (!customData) return null;
            const mepMatch = customData.match(/S:MEP=([^;|]+)/i);
            if (!mepMatch) return null;
            return { type: mepMatch[1] };
        }

        function parseSourceContext(sourceContext) {
            if (!sourceContext) return null;
            const result = { protocol: '', connector: '', raw: sourceContext };
            if (/SMTP/i.test(sourceContext)) result.protocol = 'SMTP';
            else if (/MAPI/i.test(sourceContext)) result.protocol = 'MAPI';
            else if (/StoreDriver/i.test(sourceContext)) result.protocol = 'StoreDriver';
            const connMatch = sourceContext.match(/(?:connector|Connector)\s*[:=]\s*([^;,]+)/i);
            if (connMatch) result.connector = connMatch[1].trim();
            return result;
        }

        function getDirectionalityBadge(dir) {
            if (!dir) return '';
            const d = dir.toLowerCase();
            if (d === 'outbound' || d === 'originating') return '<span class="badge-md direction-badge outbound">⬆ Outbound</span>';
            if (d === 'inbound' || d === 'incoming') return '<span class="badge-md direction-badge inbound">⬇ Inbound</span>';
            if (d === 'intraorg' || d.includes('intra')) return '<span class="badge-md direction-badge intraorg">↔ IntraOrg</span>';
            return '<span class="badge-md direction-badge" style="background:rgba(160,160,176,0.2);color:var(--text-secondary);">' + escapeHtml(dir) + '</span>';
        }

        function buildEventFlow(networkMsgId) {
            if (!networkMsgId) return '';
            const events = rawData.filter(r => (r.network_message_id || '').toLowerCase().trim() === networkMsgId.toLowerCase().trim());
            if (events.length === 0) return '';
            const eventOrder = ['RECEIVE', 'AGENTINFO', 'ROUTING', 'TRANSFER', 'DELIVER', 'DROP', 'REDIRECT', 'RESOLVE', 'EXPAND', 'SUBMIT', 'DEFER', 'FAIL'];
            const seen = {};
            const flow = [];
            events.forEach(e => {
                const eid = (e.event_id || '').toUpperCase();
                if (eid && !seen[eid]) { seen[eid] = true; flow.push(eid); }
            });
            flow.sort((a, b) => {
                const ai = eventOrder.indexOf(a); const bi = eventOrder.indexOf(b);
                return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
            });
            if (flow.length === 0) return '';
            return '<div class="event-flow">' + flow.map(f => {
                let cls = 'other';
                if (f === 'RECEIVE') cls = 'receive';
                else if (f === 'AGENTINFO') cls = 'agent';
                else if (f === 'DELIVER') cls = 'deliver';
                else if (f === 'DROP' || f === 'FAIL') cls = 'drop';
                return '<span class="ef-step ' + cls + '">' + f + '</span>';
            }).join('<span class="ef-arrow">→</span>') + '</div>';
        }

        function dtCheck(type, msg) {
            const icon = type === 'pass' ? '✅' : type === 'fail' ? '❌' : '⚠️';
            return '<div class="dt-check ' + type + '">' + icon + ' ' + msg + '</div>';
        }

        function buildWhyNoDLPTree(msg) {
            const netId = (msg.network_message_id || msg.message_id || '').toLowerCase().trim();
            const hasSIT = allDLPData.some(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId);
            const hasDLP = allDLPRulesData.some(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId);
            if (!hasSIT || hasDLP) return '';

            const dir = msg.directionality || '';
            const sfa = parseSFAFromCustomData(msg.custom_data);
            const ama = parseAMAFromCustomData(msg.custom_data);
            const hasAgentInfo = rawData.some(r => (r.network_message_id || '').toLowerCase().trim() === netId && (r.event_id || '').toUpperCase() === 'AGENTINFO');

            let html = '<div class="decision-tree"><div class="dt-title">🔍 Why Didn\'t DLP Fire? (SIT detected but no DLP rule matched)</div>';

            html += dtCheck(hasAgentInfo ? 'pass' : 'fail', 'DLP agent was invoked (AGENTINFO event' + (hasAgentInfo ? ' found' : ' MISSING — DLP never evaluated this message') + ')');

            if (sfa && (sfa.action === 'quarantine' || sfa.action === 'block')) {
                html += dtCheck('fail', 'Anti-spam quarantined/blocked BEFORE DLP could evaluate (Action: ' + escapeHtml(sfa.action) + ', Reason: ' + escapeHtml(sfa.reason) + ')');
            } else {
                html += dtCheck('pass', 'No anti-spam preemption detected');
            }
            if (ama && (ama.action === 'quarantine' || ama.action === 'block')) {
                html += dtCheck('fail', 'Anti-malware quarantined/blocked BEFORE DLP (Action: ' + escapeHtml(ama.action) + ')');
            }

            if (dir.toLowerCase() === 'intraorg' || dir.toLowerCase().includes('intra')) {
                html += dtCheck('unknown', 'Message is IntraOrg — external-scoped DLP policies do not apply to internal messages');
            } else {
                html += dtCheck('pass', 'Message is ' + escapeHtml(dir || 'Unknown direction') + ' — DLP policies should apply');
            }

            const sitForMsg = allDLPData.filter(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId);
            const lowConf = sitForMsg.filter(s => s.confidence < 65);
            if (lowConf.length > 0) {
                html += dtCheck('unknown', lowConf.length + ' SIT detection(s) below 65% confidence — may be below DLP rule threshold');
            }

            html += dtCheck('unknown', 'ℹ️ Check: Is the DLP policy enabled? Is the policy scoped to this workload? Is the sender/recipient in scope?');
            html += '</div>';
            return html;
        }
        function buildWhyLabelGuide(msg, labelEvent) {
            const netId = (msg.network_message_id || msg.message_id || '').toLowerCase().trim();
            const hasSSAM = allSSAMData.some(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId);
            const hasDLPLabel = allDLPRulesData.some(d => {
                if ((d.networkMessageId || d.messageId || '').toLowerCase().trim() !== netId) return false;
                return d.actions && d.actions.some(a => a.name === 'ESLA' || a.name === 'ALA');
            });

            let html = '<div class="decision-tree"><div class="dt-title">🏷️ Why Was This Label Applied?</div>';
            if (hasSSAM) {
                html += dtCheck('pass', 'Server-side Auto-Labeling (SSAM) rule matched for this message');
            } else if (hasDLPLabel) {
                html += dtCheck('pass', 'DLP rule applied this label via ESLA/ALA action');
            } else {
                html += dtCheck('unknown', 'ℹ️ No server-side rule matched — label was likely applied by client (Outlook/OWA) or inherited from container');
            }
            html += '</div>';
            return html;
        }
        function detectLabelChanges(networkMsgId) {
            if (!networkMsgId) return [];
            const labels = allLabelsData.filter(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === networkMsgId.toLowerCase().trim());
            if (labels.length < 2) return [];
            const changes = [];
            for (let i = 1; i < labels.length; i++) {
                const prev = labels[i-1];
                const curr = labels[i];
                const prevInfo = labelNameMapping[prev.labelId];
                const currInfo = labelNameMapping[curr.labelId];
                const prevPriority = (prevInfo && typeof prevInfo === 'object') ? (prevInfo.Priority || 0) : 0;
                const currPriority = (currInfo && typeof currInfo === 'object') ? (currInfo.Priority || 0) : 0;
                if (prevPriority !== currPriority) {
                    changes.push({
                        from: (prevInfo && typeof prevInfo === 'object') ? prevInfo.Name : (typeof prevInfo === 'string' ? prevInfo : prev.labelId),
                        to: (currInfo && typeof currInfo === 'object') ? currInfo.Name : (typeof currInfo === 'string' ? currInfo : curr.labelId),
                        direction: currPriority > prevPriority ? 'upgrade' : 'downgrade',
                        fromPriority: prevPriority,
                        toPriority: currPriority
                    });
                }
            }
            return changes;
        }
        function getLabelDisplayName(labelId) {
            const info = labelNameMapping[labelId];
            if (!info) return labelId;
            if (typeof info === 'string') return info;
            return info.Name || labelId;
        }
        function getSITDisplayName(dcid) {
            const info = dcidNameMapping[dcid];
            if (!info) return dcid;
            if (typeof info === 'string') return info;
            return info.Name || dcid;
        }
        function getSITInfo(dcid) {
            const info = dcidNameMapping[dcid];
            if (!info || typeof info === 'string') return null;
            return info;
        }
        function getLabelInfo(labelId) {
            const info = labelNameMapping[labelId];
            if (!info || typeof info === 'string') return null;
            return info;
        }
        // Task 3.1 — DLP Notifications Parser
        function parseNotificationsFromCustomData(customData) {
            const notifs = [];
            if (!customData) return notifs;
            const notRegex = /S:DPA=NOT\|(?:notificationType=([^|;]+))?(?:\|policyId=([a-f0-9-]+))?/gi;
            let m;
            while ((m = notRegex.exec(customData)) !== null) {
                notifs.push({ type: m[1] || 'Unknown', policyId: m[2] || '' });
            }
            return notifs;
        }
        // Task 3.7 — Journaling Detection
        function isJournalMessage(msg) {
            const sc = (msg.source_context || '').toLowerCase();
            const src = (msg.source || '').toLowerCase();
            return sc.includes('journal') || src.includes('journal') || sc.includes('journaling');
        }
        // Task 3.9 — Hybrid Exchange Detection
        function isHybridRouted(msg) {
            const hostname = (msg.server_hostname || '').toLowerCase();
            const sc = (msg.source_context || '').toLowerCase();
            return (hostname && !hostname.includes('.protection.outlook.com') && !hostname.includes('.mail.protection')) || sc.includes('onpremises') || sc.includes('on-premises');
        }
        // Task 3.12 — System Message Detection
        function isSystemMessage(msg) {
            const subject = (msg.subject || '').toLowerCase();
            const sender = (msg.sender || '').toLowerCase();
            const msgId = (msg.message_id || '');
            if (sender === '' || sender === '<>' || sender.includes('postmaster') || sender.includes('mailer-daemon')) return true;
            if (subject.startsWith('automatic reply:') || subject.startsWith('out of office:') || subject.startsWith('read:') || subject.startsWith('undeliverable:') || subject.startsWith('delivery status notification')) return true;
            if (/^<[^>]*\.(oof|dsn|ndr)/i.test(msgId)) return true;
            return false;
        }
        // Task 3.3 — False Positive Risk Assessment
        function assessFPRisk(sitItem) {
            const reasons = [];
            if (sitItem.confidence < 65) reasons.push('Low confidence (' + sitItem.confidence + '%)');
            if (sitItem.count === 1 && sitItem.uniqueCount === 1) reasons.push('Single occurrence');
            const sitInfo = getSITInfo(sitItem.dcid);
            if (sitInfo && sitInfo.IsCustom) reasons.push('Custom SIT (higher FP rate)');
            return reasons;
        }
        // Task 3.11 — Slow Evaluation Detection
        function isSlowEvaluation(timeSpent) {
            const t = parseInt(timeSpent);
            return !isNaN(t) && t > 5000;
        }
        // Task 3.2 — Incident Report Link Builder
        function buildIncidentLink(policyId, policyName) {
            if (!policyId) return '';
            const url = 'https://compliance.microsoft.com/datalossprevention/incidents?policyId=' + encodeURIComponent(policyId);
            return '<a class="incident-link" href="' + url + '" target="_blank" rel="noopener">📋 View DLP Incidents for ' + escapeHtml(policyName || 'this policy') + ' →</a>';
        }


        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            try {
                console.log('Initializing with', rawData.length, 'records');
                if (!rawData || rawData.length === 0) {
                    console.warn('No data loaded');
                    return;
                }
                initializeCompliance();
                console.log('Initialization complete');
            } catch(e) {
                console.error('Initialization error:', e);
                alert('Error initializing: ' + e.message);
            }
        });


        // Compliance Investigation Functions
        let allDLPRulesData = [];
        let filteredDLPRulesData = [];

        let allDLPData = [];
        let filteredDLPData = [];

        let allSSAMData = [];
        let filteredSSAMData = [];

        let allLabelsData = [];
        let filteredLabelsData = [];

        // Generic pagination state and controller
        const pageState = { dlpRules:{page:1,size:10}, dlp:{page:1,size:10}, ssam:{page:1,size:10}, labels:{page:1,size:10}, mv:{page:1,size:10} };
        const pageDataMap = {
            dlpRules: function(){ return filteredDLPRulesData; },
            dlp: function(){ return filteredDLPData; },
            ssam: function(){ return filteredSSAMData; },
            labels: function(){ return filteredLabelsData; },
            mv: function(){ return filteredMessageViewData; }
        };
        const pageRenderMap = {
            dlpRules: function(){ renderDLPRulesTable(); },
            dlp: function(){ renderDLPTable(); },
            ssam: function(){ renderSSAMTable(); },
            labels: function(){ renderLabelsTable(); },
            mv: function(){ renderMessageView(); }
        };
        function pgPrev(prefix) {
            var s = pageState[prefix];
            if (s.page > 1) { s.page--; pageRenderMap[prefix](); pgUpdate(prefix); }
        }
        function pgNext(prefix) {
            var s = pageState[prefix], total = Math.ceil(pageDataMap[prefix]().length / s.size);
            if (s.page < total) { s.page++; pageRenderMap[prefix](); pgUpdate(prefix); }
        }
        function pgUpdate(prefix) {
            var s = pageState[prefix], data = pageDataMap[prefix](), len = data.length;
            var totalPages = Math.ceil(len / s.size) || 1;
            var start = len === 0 ? 0 : (s.page - 1) * s.size + 1;
            var end = Math.min(s.page * s.size, len);
            document.getElementById(prefix + 'ShowingStart').textContent = start;
            document.getElementById(prefix + 'ShowingEnd').textContent = end;
            document.getElementById(prefix + 'TotalFiltered').textContent = len;
            document.getElementById(prefix + 'PageInfo').textContent = 'Page ' + s.page + ' of ' + totalPages;
            document.getElementById(prefix + 'PrevBtn').disabled = s.page <= 1;
            document.getElementById(prefix + 'NextBtn').disabled = s.page >= totalPages;
        }

        function initializeCompliance() {
            allDLPRulesData = parseAllDLPRulesData();
            allDLPData = parseAllDLPData();
            allSSAMData = parseAllSSAMData();
            allLabelsData = parseAllLabelData();

            document.getElementById('dlpRulesCount').textContent = allDLPRulesData.length;
            document.getElementById('dlpCount').textContent = allDLPData.length;
            document.getElementById('ssamCount').textContent = allSSAMData.length;
            document.getElementById('labelsCount').textContent = allLabelsData.length;

            renderDLPRulesSummary(allDLPRulesData);
            populateRuleNameDropdown(allDLPRulesData);
            populatePolicyNameDropdown(allDLPRulesData);
            renderDLPSummary(allDLPData);
            populateSITNameDropdown(allDLPData);
            populateDLPPolicyNameDropdown(allDLPData);
            populateSSAMRuleNameDropdown(allSSAMData);
            populateSSAMPolicyNameDropdown(allSSAMData);
            renderSSAMSummary(allSSAMData);
            renderLabelsSummary(allLabelsData);
            populateLabelNameDropdown(allLabelsData);

            filterDLPRulesTable();
            filterDLPTable();
            filterSSAMTable();
            filterLabelsTable();

            // Parse overrides from all raw data
            allDLPRulesData.forEach(d => {
                if (!d.overrides) d.overrides = parseOverridesFromCustomData(d.originalCustomData || '');
            });

            buildMessageViewData();
            filteredMessageViewData = [].concat(allMessageViewData);
            document.getElementById('messageViewCount').textContent = allMessageViewData.length;
            renderMessageView();
            updateMVPagination();
            populateGlossary();
        }

        // Debounce utility
        function debounce(fn, delay) {
            let timer;
            return function() {
                clearTimeout(timer);
                timer = setTimeout(() => fn.apply(this, arguments), delay);
            };
        }
        const debouncedFilterDLPRules = debounce(filterDLPRulesTable, 300);
        const debouncedFilterDLP = debounce(filterDLPTable, 300);
        const debouncedFilterSSAM = debounce(filterSSAMTable, 300);
        const debouncedFilterLabels = debounce(filterLabelsTable, 300);
        const debouncedFilterMV = debounce(filterMessageView, 300);

        // Column sorting
        let currentSortState = {};
        function sortTableData(tabKey, dataArray, filterFn, renderFn, field, element) {
            const state = currentSortState[tabKey] || { field: null, dir: 'asc' };
            if (state.field === field) {
                state.dir = state.dir === 'asc' ? 'desc' : 'asc';
            } else {
                state.field = field;
                state.dir = 'asc';
            }
            currentSortState[tabKey] = state;
            var headers = element.closest('thead').querySelectorAll('th.sortable');
            headers.forEach(function(h) { h.classList.remove('sort-asc', 'sort-desc'); });
            element.classList.add('sort-' + state.dir);
            dataArray.sort(function(a, b) {
                var va = a[field] || '';
                var vb = b[field] || '';
                if (typeof va === 'number' && typeof vb === 'number') return state.dir === 'asc' ? va - vb : vb - va;
                va = String(va).toLowerCase(); vb = String(vb).toLowerCase();
                if (va < vb) return state.dir === 'asc' ? -1 : 1;
                if (va > vb) return state.dir === 'asc' ? 1 : -1;
                return 0;
            });
            renderFn();
        }

        // Page size changer
        function changePageSize(tabKey, selectEl) {
            var size = parseInt(selectEl.value);
            var s = pageState[tabKey];
            if (s) { s.size = size; s.page = 1; pageRenderMap[tabKey](); pgUpdate(tabKey); }
        }

        // Abbreviation tooltips
        function wrapAbbreviation(abbr) {
            var full = expandPredicateName(abbr);
            if (full !== abbr) return '<span class="abbr-tooltip" data-tooltip="' + escapeHtml(full) + '">' + escapeHtml(full) + '</span>';
            var fullAction = expandActionName(abbr);
            if (fullAction !== abbr) return '<span class="abbr-tooltip" data-tooltip="' + escapeHtml(fullAction) + '">' + escapeHtml(fullAction) + '</span>';
            return escapeHtml(abbr);
        }

        // Glossary population
        function populateGlossary() {
            var predDiv = document.getElementById('glossaryPredicates');
            var actDiv = document.getElementById('glossaryActions');
            if (predDiv) predDiv.innerHTML = Object.keys(PREDICATE_MAP).map(function(k) { return '<div><strong>' + k + ':</strong> ' + PREDICATE_MAP[k] + '</div>'; }).join('');
            if (actDiv) actDiv.innerHTML = Object.keys(ACTION_MAP).map(function(k) { return '<div><strong>' + k + ':</strong> ' + ACTION_MAP[k] + '</div>'; }).join('');
        }

        // Keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.target.classList && e.target.classList.contains('compliance-tab')) {
                var tabs = Array.from(document.querySelectorAll('.compliance-tab'));
                var idx = tabs.indexOf(e.target);
                if (e.key === 'ArrowRight' && idx < tabs.length - 1) { e.preventDefault(); tabs[idx + 1].focus(); }
                if (e.key === 'ArrowLeft' && idx > 0) { e.preventDefault(); tabs[idx - 1].focus(); }
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.target.click(); }
            }
            if (e.key === 'Escape') {
                document.querySelectorAll('.dlp-rule-detail-content.show').forEach(function(d) { d.classList.remove('show'); });
                document.querySelectorAll('.dlp-rule-detail-row.expanded').forEach(function(r) { r.classList.remove('expanded'); });
                document.querySelectorAll('.message-view-body.show').forEach(function(d) { d.classList.remove('show'); });
            }
        });

        // Data Loss Prevention Tab Functions
        function parseAllDLPRulesData() {
            const results = [];
            rawData.forEach((msg, idx) => {
                if (!msg.custom_data) return;
                const ruleMatches = parseDLPRulesFromCustomData(msg.custom_data);
                ruleMatches.forEach(rule => {
                    const bInfo = getBifurcationInfo(msg.message_id, msg.network_message_id);
                    results.push({
                        index: idx,
                        subject: msg.subject || 'No Subject',
                        sender: msg.sender || 'Unknown',
                        recipient: msg.recipient || 'Unknown',
                        networkMessageId: msg.network_message_id || '',
                        messageId: msg.message_id || '',
                        dateTime: msg.date_time,
                        directionality: msg.directionality || '',
                        originalCustomData: msg.custom_data || '',
                        ruleId: rule.ruleId,
                        mgtRuleId: rule.mgtRuleId,
                        policyId: rule.policyId,
                        timestamp: rule.timestamp,
                        predicates: rule.predicates,
                        actions: rule.actions,
                        matched: rule.actions.length > 0,
                        totalTimeSpent: rule.totalTimeSpent,
                        raw: rule.raw,
                        isBifurcated: bInfo.isBifurcated,
                        isForkedExternal: bInfo.isForkedExternal,
                        otherForks: bInfo.otherForks
                    });
                });
            });
            return results;
        }

        function parseDLPRulesFromCustomData(customData) {
            const results = [];
            // Match full S:DPA=DPR entries - they can span until next S: or semicolon/end
            // Format: S:DPA=DPR|ruleId=<GUID>|[mgtRuleId=<GUID>|][policyId=<GUID>|]st=<timestamp>|predicate=...|timeSpent=...|[action=...|timeSpent=...]...
            // Use a more robust regex that captures until the next S: section or semicolon
            const dprEntries = customData.match(/S:DPA=DPR\|[^;]*(?:;|$)/g) || [];

            dprEntries.forEach(entry => {
                // Extract ruleId
                const ruleIdMatch = entry.match(/ruleId=([a-f0-9-]+)/i);
                const mgtRuleIdMatch = entry.match(/mgtRuleId=([a-f0-9-]+)/i);
                const policyIdMatch = entry.match(/policyId=([a-f0-9-]+)/i);
                const stMatch = entry.match(/st=([^|;]+)/);

                // Extract all predicates (predicate=Name|timeSpent=N)
                const predicates = [];
                const predicateRegex = /predicate=([^|;]+)\|timeSpent=(-?\d+)/g;
                let predMatch;
                while ((predMatch = predicateRegex.exec(entry)) !== null) {
                    // Skip AndCondition as it's just a container
                    if (predMatch[1] !== 'AndCondition') {
                        predicates.push({
                            name: predMatch[1],
                            timeSpent: parseInt(predMatch[2])
                        });
                    }
                }

                // Extract all actions (action=Name|timeSpent=N)
                const actions = [];
                const actionRegex = /action=([^|;]+)\|timeSpent=(-?\d+)/g;
                let actMatch;
                while ((actMatch = actionRegex.exec(entry)) !== null) {
                    actions.push({
                        name: actMatch[1],
                        timeSpent: parseInt(actMatch[2])  // -1 means executed later
                    });
                }

                // Calculate total time spent
                let totalTimeSpent = 0;
                predicates.forEach(p => { if (p.timeSpent > 0) totalTimeSpent += p.timeSpent; });
                actions.forEach(a => { if (a.timeSpent > 0) totalTimeSpent += a.timeSpent; });

                if (ruleIdMatch) {
                    results.push({
                        ruleId: ruleIdMatch[1],
                        mgtRuleId: mgtRuleIdMatch ? mgtRuleIdMatch[1] : '',
                        policyId: policyIdMatch ? policyIdMatch[1] : '',
                        timestamp: stMatch ? stMatch[1] : '',
                        predicates: predicates,
                        actions: actions,
                        totalTimeSpent: totalTimeSpent,
                        raw: entry.trim()
                    });
                }
            });
            return results;
        }

        function filterDLPRulesTable() {
            const allFilter = document.getElementById('dlpRulesFilterAll').value.toLowerCase();
            const ruleNameFilter = document.getElementById('dlpRulesFilterRuleName').value;
            const policyNameFilter = document.getElementById('dlpRulesFilterPolicyName').value;
            const matchFilter = document.getElementById('dlpRulesFilterMatch').value;
            const modeFilter = document.getElementById('dlpRulesFilterMode').value;
            filteredDLPRulesData = allDLPRulesData.filter(function(item) {
                const predicatesStr = item.predicates.map(p => p.name).join(' ').toLowerCase();
                const actionsStr = item.actions.map(a => a.name).join(' ').toLowerCase();
                const ruleName = getRuleName(item.ruleId);
                const ruleNameLower = ruleName.toLowerCase();

                const matchAll = !allFilter || (
                    (item.subject && item.subject.toLowerCase().includes(allFilter)) ||
                    (item.sender && item.sender.toLowerCase().includes(allFilter)) ||
                    (item.recipient && item.recipient.toLowerCase().includes(allFilter)) ||
                    (item.ruleId && item.ruleId.toLowerCase().includes(allFilter)) ||
                    (ruleNameLower && ruleNameLower.includes(allFilter)) ||
                    (item.networkMessageId && item.networkMessageId.toLowerCase().includes(allFilter)) ||
                    (item.messageId && item.messageId.toLowerCase().includes(allFilter)) ||
                    (item.policyId && item.policyId.toLowerCase().includes(allFilter)) ||
                    predicatesStr.includes(allFilter) ||
                    actionsStr.includes(allFilter) ||
                    (item.dateTime && item.dateTime.toLowerCase().includes(allFilter))
                );
                const matchRuleName = !ruleNameFilter || ruleName === ruleNameFilter;
                const ri = getRuleInfo(item.ruleId);
                const policyName = (ri && ri.ParentPolicyName) ? ri.ParentPolicyName : '';
                const matchPolicy = !policyNameFilter || policyName === policyNameFilter;
                let matchStatus = true;
                if (matchFilter === 'matched') {
                    matchStatus = item.matched === true;
                } else if (matchFilter === 'notmatched') {
                    matchStatus = item.matched === false;
                }
                const matchMode = !modeFilter || (() => {
                    const mode = (ri && (ri.PolicyMode || ri.Mode)) || '';
                    return mode.includes(modeFilter);
                })();
                const bifurcatedFilter = document.getElementById('dlpRulesFilterBifurcated').value;
                let matchBifurcated = true;
                if (bifurcatedFilter === 'yes') matchBifurcated = item.isForkedExternal;
                else if (bifurcatedFilter === 'no') matchBifurcated = !item.isForkedExternal;
                return matchAll && matchRuleName && matchPolicy && matchStatus && matchMode && matchBifurcated;
            });

            pageState.dlpRules.page = 1;
            renderDLPRulesTable();
            updateDLPRulesPagination();
        }

        function resetFilters(filterIds, filterFn) {
            filterIds.forEach(function(id) { document.getElementById(id).value = ''; });
            filterFn();
        }
        function resetDLPRulesFilters() {
            resetFilters(['dlpRulesFilterAll','dlpRulesFilterRuleName','dlpRulesFilterPolicyName','dlpRulesFilterMatch','dlpRulesFilterMode','dlpRulesFilterBifurcated'], filterDLPRulesTable);
        }

        function populateDropdown(dropdownId, data, extractFn, cfg) {
            const dropdown = document.getElementById(dropdownId);
            const uniqueValues = new Set();
            const naValue = cfg.naValue || 'N/A';
            data.forEach(item => {
                if (cfg.splitComma) {
                    const val = extractFn(item);
                    if (val && val !== naValue) val.split(', ').forEach(v => uniqueValues.add(v));
                } else {
                    const val = extractFn(item);
                    if (val && val !== naValue) uniqueValues.add(val);
                }
            });
            const sorted = Array.from(uniqueValues).sort((a, b) => a.localeCompare(b));
            dropdown.innerHTML = '<option value="">' + cfg.allLabel + '</option>';
            if (cfg.unmappedLabel) {
                const hasUnmapped = data.some(item => { const v = extractFn(item); return !v || v === naValue; });
                if (hasUnmapped) {
                    const opt = document.createElement('option');
                    opt.value = naValue;
                    opt.textContent = cfg.unmappedLabel;
                    dropdown.appendChild(opt);
                }
            }
            const tLen = cfg.truncateLen || 40;
            sorted.forEach(name => {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name.length > tLen ? name.substring(0, tLen - 3) + '...' : name;
                opt.title = name;
                dropdown.appendChild(opt);
            });
        }

        function populateSSAMRuleNameDropdown(data) {
            populateDropdown('ssamFilterRuleName', data, item => getSSAMRuleName(item.ruleId), {allLabel:'All Rule Names', unmappedLabel:'N/A (Unmapped Rules)', truncateLen:40});
        }
        function populateSSAMPolicyNameDropdown(data) {
            populateDropdown('ssamFilterPolicyName', data, item => getSSAMPolicyName(item.ruleId), {allLabel:'All Policy Names', unmappedLabel:'N/A (Unmapped Policies)', truncateLen:40});
        }
        function populateRuleNameDropdown(data) {
            populateDropdown('dlpRulesFilterRuleName', data, item => getRuleName(item.ruleId), {allLabel:'All Rule Names', unmappedLabel:'N/A (Unmapped Rules)', truncateLen:40});
        }
        function populateSITNameDropdown(data) {
            populateDropdown('dlpFilterSITName', data, item => item.sitName, {allLabel:'All SIT Names', unmappedLabel:'N/A (Unmapped DCIDs)', truncateLen:50});
        }
        function populateLabelNameDropdown(data) {
            populateDropdown('labelsFilterLabelName', data, item => item.labelName, {allLabel:'All Label Names', unmappedLabel:'N/A (Unmapped Labels)', truncateLen:50});
        }
        function populateDLPPolicyNameDropdown(data) {
            populateDropdown('dlpFilterPolicyName', data, item => item.policyName, {allLabel:'All Policy Names', unmappedLabel:'N/A (No Policy)', truncateLen:50, splitComma:true});
        }
        function populatePolicyNameDropdown(data) {
            populateDropdown('dlpRulesFilterPolicyName', data, item => { const ri = getRuleInfo(item.ruleId); return (ri && ri.ParentPolicyName) ? ri.ParentPolicyName : ''; }, {allLabel:'All Policies', truncateLen:45});
        }

        function dlpRulesPreviousPage() { pgPrev('dlpRules'); }
        function dlpRulesNextPage() { pgNext('dlpRules'); }
        function updateDLPRulesPagination() { pgUpdate('dlpRules'); }

        function exportDLPRulesToCSV() {
            if (filteredDLPRulesData.length === 0) {
                alert('No data to export');
                return;
            }
            const nl = String.fromCharCode(10);
            let csv = 'Subject,Sender,Recipient,Execution Rule ID,Rule Name,Policy,Priority,Workload,Disabled,Mode,When Changed (UTC),When Created,Created By,Last Modified By,Rule GUID,Network Message ID,Message ID,Policy ID,Status,Actions,Predicates,Total Time (ms),Timestamp,Date/Time' + nl;
            filteredDLPRulesData.forEach(function(item) {
                const actionsStr = item.actions.map(a => expandActionName(a.name) + '(' + a.timeSpent + 'ms)').join('; ');
                const predicatesStr = item.predicates.map(p => expandPredicateName(p.name) + '(' + p.timeSpent + 'ms)').join('; ');
                const ruleName = getRuleName(item.ruleId);
                const ruleInfo = getRuleInfo(item.ruleId);
                csv += '"' + (item.subject || '').replace(/"/g, '""') + '",';
                csv += '"' + (item.sender || '').replace(/"/g, '""') + '",';
                csv += '"' + (item.recipient || '').replace(/"/g, '""') + '",';
                csv += '"' + (item.ruleId || '') + '",';
                csv += '"' + (ruleName || '').replace(/"/g, '""') + '",';
                csv += '"' + (ruleInfo && ruleInfo.ParentPolicyName ? ruleInfo.ParentPolicyName.replace(/"/g, '""') : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.Priority !== null ? ruleInfo.Priority : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.Workload ? ruleInfo.Workload : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.Disabled !== null ? (ruleInfo.Disabled ? 'Yes' : 'No') : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.Mode ? ruleInfo.Mode : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.WhenChangedUTC ? ruleInfo.WhenChangedUTC : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.WhenCreated ? ruleInfo.WhenCreated : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.CreatedBy ? ruleInfo.CreatedBy.replace(/"/g, '""') : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.LastModifiedBy ? ruleInfo.LastModifiedBy.replace(/"/g, '""') : '') + '",';
                csv += '"' + (ruleInfo && ruleInfo.GUID ? ruleInfo.GUID : '') + '",';
                csv += '"' + (item.networkMessageId || '') + '",';
                csv += '"' + (item.messageId || '') + '",';
                csv += '"' + (item.policyId || '') + '",';
                csv += '"' + (item.matched ? 'Matched' : 'Not Matched') + '",';
                csv += '"' + actionsStr.replace(/"/g, '""') + '",';
                csv += '"' + predicatesStr.replace(/"/g, '""') + '",';
                csv += '"' + (item.totalTimeSpent || '') + '",';
                csv += '"' + (item.timestamp || '') + '",';
                csv += '"' + (item.dateTime || '') + '"' + nl;
            });
            downloadCSV(csv, 'DLP_Policy_Rules_Report.csv');
        }

        // Consolidated rendering helpers
        let activeComplianceStatFilter = {};
        function renderSummaryStats(containerId, stats, panelType) {
            document.getElementById(containerId).innerHTML = stats.map(s => {
                const clickable = s.filter ? ' clickable' : '';
                const onclick = s.filter ? ' onclick="filterByComplianceStat(\'' + panelType + '\', \'' + s.filter + '\', this)"' : '';
                return '<div class="compliance-stat' + (s.type ? ' ' + s.type : '') + clickable + '"' + onclick + '><span class="compliance-stat-value">' + s.value + '</span><span class="compliance-stat-label">' + s.label + '</span></div>';
            }).join('');
        }

        function filterByComplianceStat(panelType, filterType, element) {
            const container = element.parentElement;
            container.querySelectorAll('.compliance-stat').forEach(card => card.classList.remove('active'));

            // If clicking the same filter, clear it
            if (activeComplianceStatFilter[panelType] === filterType) {
                activeComplianceStatFilter[panelType] = null;
                if (panelType === 'dlpRules') {
                    document.getElementById('dlpRulesFilterMatch').value = '';
                    document.getElementById('dlpRulesFilterRuleName').value = '';
                    filterDLPRulesTable();
                } else if (panelType === 'dlp') {
                    filterDLPTable();
                } else if (panelType === 'ssam') {
                    filterSSAMTable();
                } else if (panelType === 'labels') {
                    filterLabelsTable();
                }
                return;
            }

            activeComplianceStatFilter[panelType] = filterType;
            element.classList.add('active');

            // Apply filter based on panel type
            if (panelType === 'dlpRules') {
                switch(filterType) {
                    case 'all':
                        filteredDLPRulesData = [...allDLPRulesData];
                        break;
                    case 'matched':
                        filteredDLPRulesData = allDLPRulesData.filter(d => d.matched === true);
                        break;
                    case 'notmatched':
                        filteredDLPRulesData = allDLPRulesData.filter(d => d.matched === false);
                        break;
                    case 'uniquerules':
                        const seenRules = {};
                        filteredDLPRulesData = allDLPRulesData.filter(d => {
                            if (d.ruleId && !seenRules[d.ruleId]) { seenRules[d.ruleId] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquepolicies':
                        const seenPolicies = {};
                        filteredDLPRulesData = allDLPRulesData.filter(d => {
                            const ri = getRuleInfo(d.ruleId);
                            const policyKey = (ri && ri.ParentPolicyName) ? ri.ParentPolicyName : d.policyId;
                            if (policyKey && !seenPolicies[policyKey]) { seenPolicies[policyKey] = true; return true; }
                            return false;
                        });
                        break;
                    case 'forkedexternal':
                        const seenForkMsgs = {};
                        filteredDLPRulesData = allDLPRulesData.filter(d => {
                            if (!d.isForkedExternal) return false;
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenForkMsgs[key]) { seenForkMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquemessages':
                        const seenMsgs = {};
                        filteredDLPRulesData = allDLPRulesData.filter(d => {
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenMsgs[key]) { seenMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    default:
                        filteredDLPRulesData = [...allDLPRulesData];
                }
                pageState.dlpRules.page = 1;
                renderDLPRulesTable();
                updateDLPRulesPagination();
            } else if (panelType === 'dlp') {
                switch(filterType) {
                    case 'all':
                        filteredDLPData = [...allDLPData];
                        break;
                    case 'highconf':
                        filteredDLPData = allDLPData.filter(d => d.confidence >= 85);
                        break;
                    case 'medconf':
                        filteredDLPData = allDLPData.filter(d => d.confidence >= 65 && d.confidence < 85);
                        break;
                    case 'lowconf':
                        filteredDLPData = allDLPData.filter(d => d.confidence < 65);
                        break;
                    case 'uniquedcids':
                        const seenDCIDs = {};
                        filteredDLPData = allDLPData.filter(d => {
                            if (d.dcid && !seenDCIDs[d.dcid]) { seenDCIDs[d.dcid] = true; return true; }
                            return false;
                        });
                        break;
                    case 'forkedexternal':
                        const seenDLPForkMsgs = {};
                        filteredDLPData = allDLPData.filter(d => {
                            if (!d.isForkedExternal) return false;
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenDLPForkMsgs[key]) { seenDLPForkMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquemessages':
                        const seenDLPMsgs = {};
                        filteredDLPData = allDLPData.filter(d => {
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenDLPMsgs[key]) { seenDLPMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    default:
                        filteredDLPData = [...allDLPData];
                }
                pageState.dlp.page = 1;
                renderDLPTable();
                updateDLPPagination();
            } else if (panelType === 'ssam') {
                switch(filterType) {
                    case 'all':
                        filteredSSAMData = [...allSSAMData];
                        break;
                    case 'sit':
                        filteredSSAMData = allSSAMData.filter(d => d.predicate && d.predicate.includes('SensitiveInformation'));
                        break;
                    case 'uniquerules':
                        const seenSSAMRules = {};
                        filteredSSAMData = allSSAMData.filter(d => {
                            if (d.ruleId && !seenSSAMRules[d.ruleId]) { seenSSAMRules[d.ruleId] = true; return true; }
                            return false;
                        });
                        break;
                    case 'forkedexternal':
                        const seenSSAMForkMsgs = {};
                        filteredSSAMData = allSSAMData.filter(d => {
                            if (!d.isForkedExternal) return false;
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenSSAMForkMsgs[key]) { seenSSAMForkMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquemessages':
                        const seenSSAMMsgs = {};
                        filteredSSAMData = allSSAMData.filter(d => {
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenSSAMMsgs[key]) { seenSSAMMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    default:
                        filteredSSAMData = [...allSSAMData];
                }
                pageState.ssam.page = 1;
                renderSSAMTable();
                updateSSAMPagination();
            } else if (panelType === 'labels') {
                switch(filterType) {
                    case 'all':
                        filteredLabelsData = [...allLabelsData];
                        break;
                    case 'labeledmessages':
                        const seenMessages = {};
                        filteredLabelsData = allLabelsData.filter(d => {
                            if (d.index && !seenMessages[d.index]) { seenMessages[d.index] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquelabels':
                        const seenLabels = {};
                        filteredLabelsData = allLabelsData.filter(d => {
                            if (d.labelId && !seenLabels[d.labelId]) { seenLabels[d.labelId] = true; return true; }
                            return false;
                        });
                        break;
                    case 'forkedexternal':
                        const seenLabelForkMsgs = {};
                        filteredLabelsData = allLabelsData.filter(d => {
                            if (!d.isForkedExternal) return false;
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenLabelForkMsgs[key]) { seenLabelForkMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    case 'uniquemessages':
                        const seenLabelMsgs = {};
                        filteredLabelsData = allLabelsData.filter(d => {
                            const key = (d.messageId || '').toLowerCase().trim();
                            if (key && !seenLabelMsgs[key]) { seenLabelMsgs[key] = true; return true; }
                            return false;
                        });
                        break;
                    default:
                        filteredLabelsData = [...allLabelsData];
                }
                pageState.labels.page = 1;
                renderLabelsTable();
                updateLabelsPagination();
            }
        }

        function renderDLPRulesSummary(data) {
            const uniquePolicies = new Set(data.map(d => { const ri = getRuleInfo(d.ruleId); return ri && ri.ParentPolicyName ? ri.ParentPolicyName : (d.policyId || null); }).filter(p => p));
            const uniqueMessages = new Set(data.map(d => (d.messageId || '').toLowerCase().trim())).size;
            const forkedExtCount = new Set(data.filter(d => d.isForkedExternal).map(d => (d.messageId || '').toLowerCase().trim())).size;
            renderSummaryStats('dlpRulesSummary', [
                {value: data.length, label: 'Total DLP Events', filter: 'all'},
                {value: uniqueMessages, label: 'Unique Messages', filter: 'uniquemessages'},
                {value: new Set(data.map(d => d.ruleId)).size, label: 'Execution Unique Rules', filter: 'uniquerules'},
                {value: data.filter(d => d.matched).length, label: 'Execution Rules Matched', type: 'success', filter: 'matched'},
                {value: data.filter(d => !d.matched).length, label: 'Execution Rules Not Matched', type: 'warning', filter: 'notmatched'},
                {value: uniquePolicies.size, label: 'Unique Policies', filter: 'uniquepolicies'},
                {value: forkedExtCount, label: 'Bifurcated Messages', type: 'danger', filter: 'forkedexternal'}
            ], 'dlpRules');
        }

        // Helper functions for table rendering
        function detailItem(icon, label, value, opts) {
            opts = opts || {};
            const style = opts.mono ? ' style="font-family:monospace;font-size:0.85rem;"' : '';
            const fullWidth = opts.full ? ' style="grid-column:1/-1;"' : '';
            return '<div class="compliance-detail-item"' + fullWidth + '><div class="compliance-detail-label">' + icon + ' ' + label + '</div><div class="compliance-detail-value"' + style + '>' + value + '</div></div>';
        }
        function listPreview(items, itemClass, maxShow, expandFn) {
            if (!items || items.length === 0) return '-';
            let html = items.slice(0, maxShow).map(i => {
                const name = i.name || i;
                const displayName = expandFn ? expandFn(name) : name;
                return '<span class="' + itemClass + '">' + displayName + '</span>';
            }).join('');
            if (items.length > maxShow) html += '<span class="content-bits-badge">+' + (items.length - maxShow) + ' more</span>';
            return html;
        }
        function tableRow(rowClass, expandId, cells, toggleFn) {
            return '<tr class="' + rowClass + '" onclick="' + toggleFn + '(\'' + expandId + '\', this)"><td><span class="' + rowClass.replace('-row','') + '-expand-icon">&#9658;</span></td>' + cells.map(c => '<td' + (c.title ? ' title="' + c.title + '"' : '') + '>' + c.html + '</td>').join('') + '</tr>';
        }

        function renderDLPRulesTable() {
            const tbody = document.getElementById('dlpRulesTableBody');
            if (filteredDLPRulesData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="10" class="compliance-empty"><div class="compliance-empty-icon">&#128737;</div><p>No Data Loss Prevention events found matching your criteria.</p></td></tr>';
                return;
            }
            const start = (pageState.dlpRules.page - 1) * pageState.dlpRules.size;
            const end = Math.min(start + pageState.dlpRules.size, filteredDLPRulesData.length);
            let html = '';
            filteredDLPRulesData.slice(start, end).forEach(function(item, idx) {
                const gIdx = start + idx;
                const sc = item.matched ? 'matched' : 'not-matched', st = item.matched ? 'Matched' : 'Not Matched', si = item.matched ? '&#10004;' : '&#10060;';
                const ruleName = getRuleName(item.ruleId);
                const ruleInfo = getRuleInfo(item.ruleId);
                const policyName = (ruleInfo && ruleInfo.ParentPolicyName) ? ruleInfo.ParentPolicyName : 'N/A';
                // Build mode badge
                const ruleMode = (ruleInfo && (ruleInfo.PolicyMode || ruleInfo.Mode)) ? (ruleInfo.PolicyMode || ruleInfo.Mode) : '';
                let modeBadge = '';
                if (ruleMode) {
                    const modeClass = ruleMode.toLowerCase().includes('enforce') ? 'enforce' : (ruleMode.toLowerCase().includes('testwithnotif') ? 'test-notify' : 'test');
                    const modeLabel = ruleMode.replace('TestWithNotifications', 'Test+Notify').replace('TestWithoutNotifications', 'Test Only');
                    modeBadge = '<span class="mode-badge ' + modeClass + '">' + modeLabel + '</span>';
                } else {
                    modeBadge = '<span style="color:var(--text-secondary)">N/A</span>';
                }
                // Task 3.12 & 3.7: System/Journal badges for subject cell
                const _rawMsg = rawData.find(r => (r.network_message_id || '').toLowerCase().trim() === (item.networkMessageId || '').toLowerCase().trim()) || {};
                const sysMsg = isSystemMessage(_rawMsg);
                const journalMsg = isJournalMessage(_rawMsg);
                let subjectHtml = escapeHtml(truncateText(item.subject, 35));
                if (sysMsg) subjectHtml += ' <span class="badge-sm system-msg-badge">SYSTEM</span>';
                if (journalMsg) subjectHtml += ' <span class="badge-sm journal-badge">JOURNAL</span>';
                subjectHtml += '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + formatJourneyDate(item.dateTime) + '</div>';
                html += tableRow('dlp-rule-detail-row', 'dlprule-' + gIdx, [
                    {html: subjectHtml, title: escapeHtml(item.subject)},
                    {html: escapeHtml(truncateEmail(item.sender)), title: escapeHtml(item.sender)},
                    {html: escapeHtml(truncateEmail(item.recipient)), title: escapeHtml(item.recipient)},
                    {html: '<span title="' + escapeHtml(ruleName) + '">' + escapeHtml(truncateText(ruleName, 25)) + '</span>'},
                    {html: '<span title="' + escapeHtml(policyName) + '">' + escapeHtml(truncateText(policyName, 25)) + '</span>'},
                    {html: modeBadge},
                    {html: '<span class="dlp-rule-status ' + sc + '">' + si + ' ' + st + '</span>'},
                    {html: '<div class="dlp-actions-list">' + listPreview(item.actions, 'dlp-action-item', 2) + '</div>'}
                ], 'toggleDLPRuleDetail');
                // Expanded detail
                html += '<tr><td colspan="9" style="padding:0;"><div class="dlp-rule-detail-content" id="dlprule-' + gIdx + '"><div class="compliance-detail-grid">';
                html += detailItem('&#128737;', 'Rule Status', '<span class="dlp-rule-status ' + sc + '">' + si + ' ' + st + '</span>');
                html += detailItem('&#128373;', 'Execution Rule ID', item.ruleId, {mono:true});
                html += detailItem('&#128203;', 'Rule Name', ruleName || 'N/A');

                // Policy Details section
                if (ruleInfo && (ruleInfo.ParentPolicyName || ruleInfo.Workload || ruleInfo.Disabled !== null || ruleInfo.Mode)) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;margin-top:8px;"><div class="compliance-detail-label" style="font-size:0.9rem;border-bottom:1px solid var(--border-color);padding-bottom:4px;margin-bottom:6px;">&#128196; Policy Details</div><div class="compliance-detail-value"><div class="compliance-detail-grid" style="margin:0;">';
                    if (ruleInfo.ParentPolicyName) html += detailItem('&#128196;', 'Policy', ruleInfo.ParentPolicyName);
                    if (ruleInfo.Workload) html += detailItem('&#128188;', 'Workload', ruleInfo.Workload);
                    if (ruleInfo.Disabled !== null && ruleInfo.Disabled !== undefined) html += detailItem('&#128683;', 'Disabled', ruleInfo.Disabled ? 'Yes' : 'No');
                    if (ruleInfo.Mode) html += detailItem('&#9881;', 'Mode', ruleInfo.Mode);
                    html += '</div></div></div>';
                }

                // Rule Details section
                if (ruleInfo && (ruleInfo.GUID || ruleInfo.Priority !== null || ruleInfo.CreatedBy || ruleInfo.LastModifiedBy || ruleInfo.WhenChangedUTC || ruleInfo.WhenCreated)) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;margin-top:8px;"><div class="compliance-detail-label" style="font-size:0.9rem;border-bottom:1px solid var(--border-color);padding-bottom:4px;margin-bottom:6px;">&#128373; Rule Details</div><div class="compliance-detail-value"><div class="compliance-detail-grid" style="margin:0;">';
                    if (ruleInfo.GUID) html += detailItem('&#128273;', 'Rule GUID', ruleInfo.GUID, {mono:true});
                    if (ruleInfo.Priority !== null && ruleInfo.Priority !== undefined) html += detailItem('&#128200;', 'Priority', ruleInfo.Priority);
                    if (ruleInfo.CreatedBy) html += detailItem('&#128100;', 'Created By', ruleInfo.CreatedBy);
                    if (ruleInfo.LastModifiedBy) html += detailItem('&#128100;', 'Last Modified By', ruleInfo.LastModifiedBy);
                    if (ruleInfo.WhenChangedUTC) html += detailItem('&#128197;', 'When Changed (UTC)', ruleInfo.WhenChangedUTC);
                    if (ruleInfo.WhenCreated) html += detailItem('&#128197;', 'When Created', ruleInfo.WhenCreated);
                    html += '</div></div></div>';
                }

                html += detailItem('&#128233;', 'Network Message ID', item.networkMessageId || 'N/A', {mono:true});
                html += detailItem('&#128233;', 'Message ID', escapeHtml(item.messageId) || 'N/A', {mono:true});
                if (item.isBifurcated) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128260; Message Forked (External Recipients)</div><div class="compliance-detail-value">';
                    if (item.otherForks.length > 0) {
                        html += '<div style="margin-bottom:4px;">Other Network Message IDs for this message:</div><div class="dlp-actions-list" style="max-height:none;">';
                        item.otherForks.forEach(function(fk) { html += '<span class="dlp-action-item" style="font-family:monospace;font-size:0.8rem;">' + escapeHtml(fk) + '</span>'; });
                        html += '</div>';
                    } else {
                        html += 'This message was forked for external recipients. Rules were evaluated against each copy.';
                    }
                    html += '</div></div>';
                }
                if (item.policyId) html += detailItem('&#128203;', 'Policy ID', item.policyId, {mono:true});
                if (item.mgtRuleId) html += detailItem('&#128203;', 'Management Rule ID', item.mgtRuleId, {mono:true});
                html += detailItem('&#9202;', 'Total Processing Time', item.totalTimeSpent + ' ms');
                if (item.timestamp) html += detailItem('&#128197;', 'Rule Timestamp', item.timestamp);
                html += detailItem('&#128100;', 'Sender', escapeHtml(item.sender));
                html += detailItem('&#128101;', 'Recipient', escapeHtml(item.recipient));
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128221; Subject</div><div class="compliance-detail-value">' + escapeHtml(item.subject) + '</div></div>';
                if (item.actions.length > 0) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128736; Actions Taken (' + item.actions.length + ')</div><div class="compliance-detail-value"><div class="dlp-actions-list" style="max-height:none;">';
                    item.actions.forEach(a => {
                        html += '<span class="dlp-action-item">' + wrapAbbreviation(a.name) + (a.timeSpent === -1 ? ' (executed later)' : ' (' + a.timeSpent + 'ms)') + '</span>';
                        if (a.name === 'EQ' || a.name === 'BA' || a.name === 'QE') {
                            if (a.timeSpent === -1 || a.timeSpent === '-1') {
                                html += ' <span style="color:var(--accent-amber);font-size:0.7rem;">⚠️ timeSpent=-1: Verify execution</span>';
                            }
                        }
                    });
                    html += '</div></div></div>';
                }
                // Evaluation chain (Task 2.1)
                const msgNetId = (item.networkMessageId || item.messageId || '').toLowerCase().trim();
                const msgRules = allDLPRulesData.filter(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === msgNetId);
                if (msgRules.length > 1) {
                    msgRules.sort((a, b) => {
                        const aInfo = getRuleInfo(a.ruleId); const bInfo = getRuleInfo(b.ruleId);
                        const aPri = (aInfo && aInfo.Priority) || 999; const bPri = (bInfo && bInfo.Priority) || 999;
                        return aPri - bPri;
                    });
                    html += '<div style="margin:6px 0;"><strong>📋 Evaluation Order:</strong></div><div class="eval-chain">';
                    msgRules.forEach((r, i) => {
                        const rName = getRuleName(r.ruleId);
                        const cls = r.matched ? 'matched' : 'unmatched';
                        if (i > 0) html += '<span class="eval-arrow">→</span>';
                        html += '<span class="eval-step ' + cls + '">' + (r.matched ? '✅' : '❌') + ' ' + escapeHtml(truncateText(rName, 30)) + '</span>';
                    });
                    html += '</div>';
                }
                // Override tracking (Task 2.2)
                const overrides = parseOverridesFromCustomData(item.originalCustomData || '');
                if (overrides.length > 0) {
                    overrides.forEach(ovr => {
                        html += '<div class="override-banner">';
                        html += '<span class="override-type">⚠️ Override: ' + escapeHtml(ovr.overrideType) + '</span>';
                        if (ovr.justification) html += '<div style="font-size:0.8rem;margin-top:4px;color:var(--text-secondary);">Justification: "' + escapeHtml(ovr.justification) + '"</div>';
                        html += '</div>';
                    });
                }
                // DLP Notifications (Task 3.1)
                const notifs = parseNotificationsFromCustomData(item.originalCustomData || '');
                if (notifs.length > 0) {
                    html += '<div style="margin:6px 0;"><strong>🔔 Notifications Sent:</strong> ';
                    notifs.forEach(n => { html += '<span class="badge-sm notification-badge">' + escapeHtml(n.type) + '</span> '; });
                    html += '</div>';
                }
                // Incident Report Link (Task 3.2)
                const rInfo3 = getRuleInfo(item.ruleId);
                if (rInfo3 && rInfo3.ParentPolicyName) {
                    const policyGuid = item.policyId || rInfo3.GUID || '';
                    const incLink = buildIncidentLink(policyGuid, rInfo3.ParentPolicyName);
                    if (incLink) html += '<div style="margin:4px 0;">' + incLink + '</div>';
                }
                // Event flow (Task 2.4)
                const eventFlowHtml = buildEventFlow(msgNetId);
                if (eventFlowHtml) {
                    html += '<div style="margin:6px 0;"><strong>📬 Message Event Flow:</strong></div>' + eventFlowHtml;
                }
                if (item.predicates.length > 0) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#127919; Predicates Evaluated (' + item.predicates.length + ')</div><div class="compliance-detail-value"><div class="dlp-predicates-list" style="max-height:none;max-width:none;">';
                    item.predicates.forEach((p, pIdx) => {
                        let badge = '<span class="predicate-badge pass">&#10004;</span>';
                        let note = ' (' + p.timeSpent + 'ms)';
                        if (!item.matched && pIdx === item.predicates.length - 1 && item.predicates.length > 0) {
                            badge = '<span class="predicate-badge fail">&#10060;</span>';
                            note += ' <span style="color:#ef5350;font-size:0.7rem;font-weight:600;">(condition not met)</span>';
                        }
                        html += '<span class="dlp-predicate-item">' + badge + ' ' + wrapAbbreviation(p.name) + note;
                        // Task 3.11: Slow evaluation flag
                        if (isSlowEvaluation(p.timeSpent)) {
                            html += ' <span class="badge-sm slow-badge">SLOW (' + p.timeSpent + 'ms)</span>';
                        }
                        html += '</span>';
                    });
                    html += '</div></div></div>';
                    // Label-based DLP cross-reference (Task 3.13)
                    const labelPredicates = (item.predicates || []).filter(p => ['EILCR','ALP','CMLP','ALCL'].includes(p.name));
                    if (labelPredicates.length > 0) {
                        html += '<div style="margin:4px 0;"><span class="cross-ref-link" onclick="switchComplianceTab(\'labels\', document.querySelectorAll(\'.compliance-tab\')[3])">🏷️ This rule checks label conditions → View Labels tab for this message</span></div>';
                    }
                }
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128196; Raw Data</div><div class="compliance-detail-value" style="font-family:monospace;font-size:0.75rem;background:#2d2d2d;color:#f0f0f0;padding:10px;border-radius:6px;word-break:break-all;">' + escapeHtml(item.raw) + '</div></div>';
                // "Why Didn't DLP Fire?" decision tree (Task 2.11)
                if (!item.matched) {
                    const msgForTree = rawData.find(r => (r.network_message_id || '').toLowerCase().trim() === msgNetId);
                    if (msgForTree) {
                        const treeHtml = buildWhyNoDLPTree(msgForTree);
                        if (treeHtml) html += treeHtml;
                    }
                }
                html += '</div></div></td></tr>';
            });
            tbody.innerHTML = html;
        }

        function toggleDLPRuleDetail(id, row) {
            const detail = document.getElementById(id);
            const isShown = detail.classList.contains('show');

            // Close all other details
            document.querySelectorAll('.dlp-rule-detail-content.show').forEach(d => d.classList.remove('show'));
            document.querySelectorAll('.dlp-rule-detail-row.expanded').forEach(r => r.classList.remove('expanded'));

            if (!isShown) {
                detail.classList.add('show');
                row.classList.add('expanded');
            }
        }

        // SIT/DLP Tab Functions
        function filterDLPTable() {
            const allFilter = document.getElementById('dlpFilterAll').value.toLowerCase();
            const sitNameFilter = document.getElementById('dlpFilterSITName').value;
            const policyNameFilter = document.getElementById('dlpFilterPolicyName').value;

            filteredDLPData = allDLPData.filter(function(item) {
                const matchAll = !allFilter || (
                    (item.subject && item.subject.toLowerCase().includes(allFilter)) ||
                    (item.sender && item.sender.toLowerCase().includes(allFilter)) ||
                    (item.recipient && item.recipient.toLowerCase().includes(allFilter)) ||
                    (item.dcid && item.dcid.toLowerCase().includes(allFilter)) ||
                    (item.sitName && item.sitName.toLowerCase().includes(allFilter)) ||
                    (item.policyName && item.policyName.toLowerCase().includes(allFilter)) ||
                    (item.networkMessageId && item.networkMessageId.toLowerCase().includes(allFilter)) ||
                    (item.messageId && item.messageId.toLowerCase().includes(allFilter)) ||
                    (String(item.confidence).includes(allFilter)) ||
                    (item.dateTime && item.dateTime.toLowerCase().includes(allFilter))
                );
                const matchSITName = !sitNameFilter || (item.sitName && item.sitName === sitNameFilter);
                const matchPolicyName = !policyNameFilter || (item.policyName && item.policyName === policyNameFilter);
                const bifurcatedFilter = document.getElementById('dlpFilterBifurcated').value;
                let matchBifurcated = true;
                if (bifurcatedFilter === 'yes') matchBifurcated = item.isForkedExternal;
                else if (bifurcatedFilter === 'no') matchBifurcated = !item.isForkedExternal;
                return matchAll && matchSITName && matchPolicyName && matchBifurcated;
            });

            pageState.dlp.page = 1;
            renderDLPTable();
            updateDLPPagination();
        }

        function resetDLPFilters() {
            resetFilters(['dlpFilterAll','dlpFilterSITName','dlpFilterPolicyName','dlpFilterBifurcated'], filterDLPTable);
        }

        function dlpPreviousPage() { pgPrev('dlp'); }
        function dlpNextPage() { pgNext('dlp'); }
        function updateDLPPagination() { pgUpdate('dlp'); }

        function exportDLPToCSV() {
            exportTableToCSV(filteredDLPData, [
                {header: 'Subject', field: 'subject'}, {header: 'Sender', field: 'sender'},
                {header: 'Recipient', field: 'recipient'}, {header: 'DCID', field: 'dcid'},
                {header: 'SIT Name', getValue: function(d) { return d.sitName || 'N/A'; }},
                {header: 'Policy Name', getValue: function(d) { return d.policyName || 'N/A'; }},
                {header: 'Count', field: 'count'}, {header: 'Unique Count', field: 'uniqueCount'},
                {header: 'Confidence', field: 'confidence'},
                {header: 'Network Message ID', field: 'networkMessageId'},
                {header: 'Message ID', field: 'messageId'}, {header: 'Date/Time', field: 'dateTime'}
            ], 'SIT_Detection_Report.csv');
        }

        function filterLabelsTable() {
            const allFilter = document.getElementById('labelsFilterAll').value.toLowerCase();
            const labelNameFilter = document.getElementById('labelsFilterLabelName').value;

            filteredLabelsData = allLabelsData.filter(function(item) {
                const matchAll = !allFilter || (
                    (item.subject && item.subject.toLowerCase().includes(allFilter)) ||
                    (item.sender && item.sender.toLowerCase().includes(allFilter)) ||
                    (item.recipient && item.recipient.toLowerCase().includes(allFilter)) ||
                    (item.labelId && item.labelId.toLowerCase().includes(allFilter)) ||
                    (item.labelName && item.labelName.toLowerCase().includes(allFilter)) ||
                    (item.labelType && item.labelType.toLowerCase().includes(allFilter)) ||
                    (item.networkMessageId && item.networkMessageId.toLowerCase().includes(allFilter)) ||
                    (item.messageId && item.messageId.toLowerCase().includes(allFilter)) ||
                    (item.dateTime && item.dateTime.toLowerCase().includes(allFilter))
                );
                const matchLabelName = !labelNameFilter || (item.labelName && item.labelName === labelNameFilter);
                const bifurcatedFilter = document.getElementById('labelsFilterBifurcated').value;
                let matchBifurcated = true;
                if (bifurcatedFilter === 'yes') matchBifurcated = item.isForkedExternal;
                else if (bifurcatedFilter === 'no') matchBifurcated = !item.isForkedExternal;
                return matchAll && matchLabelName && matchBifurcated;
            });

            pageState.labels.page = 1;
            renderLabelsTable();
            updateLabelsPagination();
        }

        function resetLabelsFilters() {
            resetFilters(['labelsFilterAll','labelsFilterLabelName','labelsFilterBifurcated'], filterLabelsTable);
        }

        function labelsPreviousPage() { pgPrev('labels'); }
        function labelsNextPage() { pgNext('labels'); }
        function updateLabelsPagination() { pgUpdate('labels'); }

        function exportLabelsToCSV() {
            exportTableToCSV(filteredLabelsData, [
                {header: 'Subject', field: 'subject'}, {header: 'Sender', field: 'sender'},
                {header: 'Recipient', field: 'recipient'}, {header: 'Label ID', field: 'labelId'},
                {header: 'Label Name', getValue: function(d) { return d.labelName || 'N/A'; }},
                {header: 'Label Type', field: 'labelType'},
                {header: 'Network Message ID', field: 'networkMessageId'},
                {header: 'Message ID', field: 'messageId'},
                {header: 'Content Bits', getValue: function(d) { return decodeContentBits(d.contentBits).value || ''; }},
                {header: 'Content Bits Actions', getValue: function(d) { return decodeContentBits(d.contentBits).actions.join('; '); }},
                {header: 'Date/Time', field: 'dateTime'}
            ], 'Sensitivity_Labels_Report.csv');
        }

        function exportTableToCSV(data, columns, filename) {
            if (data.length === 0) { alert('No data to export'); return; }
            const nl = String.fromCharCode(10);
            let csv = columns.map(function(c) { return c.header; }).join(',') + nl;
            data.forEach(function(item) {
                csv += columns.map(function(c) {
                    let val = c.getValue ? c.getValue(item) : String(item[c.field] || '');
                    return '"' + val.replace(/"/g, '""') + '"';
                }).join(',') + nl;
            });
            downloadCSV(csv, filename);
        }

        function downloadCSV(csv, filename) {
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.click();
        }

        function parseAllDLPData() {
            const results = [];
            rawData.forEach((msg, idx) => {
                if (!msg.custom_data) return;
                const dcMatches = parseDCFromCustomData(msg.custom_data);
                if (dcMatches.length === 0) return;
                // Extract DPR rule IDs from the same message to get policy names
                const dprRuleIds = [];
                const dprRegex = /S:DPA=DPR\|ruleId=([a-f0-9-]+)/gi;
                let dprMatch;
                while ((dprMatch = dprRegex.exec(msg.custom_data)) !== null) {
                    dprRuleIds.push(dprMatch[1]);
                }
                // Get unique policy names from the rules on this message
                const policyNames = new Set();
                dprRuleIds.forEach(rid => {
                    const rInfo = getRuleInfo(rid);
                    if (rInfo && rInfo.ParentPolicyName) policyNames.add(rInfo.ParentPolicyName);
                });
                const policyNameStr = policyNames.size > 0 ? Array.from(policyNames).join(', ') : 'N/A';
                dcMatches.forEach(dc => {
                    const bInfo = getBifurcationInfo(msg.message_id, msg.network_message_id);
                    results.push({
                        index: idx,
                        subject: msg.subject || 'No Subject',
                        sender: msg.sender || 'Unknown',
                        recipient: msg.recipient || 'Unknown',
                        networkMessageId: msg.network_message_id || '',
                        messageId: msg.message_id || '',
                        dateTime: msg.date_time,
                        dcid: dc.dcid,
                        sitName: (typeof dcidNameMapping[dc.dcid] === 'object' ? dcidNameMapping[dc.dcid].Name : dcidNameMapping[dc.dcid]) || dc.dcid,
                        sitInfo: typeof dcidNameMapping[dc.dcid] === 'object' ? dcidNameMapping[dc.dcid] : null,
                        policyName: policyNameStr,
                        count: dc.count,
                        uniqueCount: dc.uniqueCount,
                        confidence: dc.confidence,
                        raw: dc.raw,
                        isBifurcated: bInfo.isBifurcated,
                        isForkedExternal: bInfo.isForkedExternal,
                        otherForks: bInfo.otherForks
                    });
                });
            });
            return results;
        }
        function parseAllSSAMData() {
            const results = [];
            rawData.forEach((msg, idx) => {
                if (!msg.custom_data) return;
                const mlaMatches = parseMLAFromCustomData(msg.custom_data);
                mlaMatches.forEach(mla => {
                    const bInfo = getBifurcationInfo(msg.message_id, msg.network_message_id);
                    results.push({
                        index: idx,
                        subject: msg.subject || 'No Subject',
                        sender: msg.sender || 'Unknown',
                        recipient: msg.recipient || 'Unknown',
                        networkMessageId: msg.network_message_id || '',
                        messageId: msg.message_id || '',
                        dateTime: msg.date_time,
                        ruleId: mla.ruleId,
                        mgtRuleId: mla.mgtRuleId || '',
                        predicate: mla.predicate,
                        timeSpent: mla.timeSpent,
                        timestamp: mla.timestamp,
                        type: mla.type,
                        raw: mla.raw,
                        isBifurcated: bInfo.isBifurcated,
                        isForkedExternal: bInfo.isForkedExternal,
                        otherForks: bInfo.otherForks
                    });
                });
            });
            return results;
        }
        // Parse S:DPA=DC entries for SIT detections (exclude label DC entries that have labelId)
        function parseDCFromCustomData(customData) {
            const results = [];
            const dcRegex = /S:DPA=DC\|([^;]+)/gi;
            let match;
            while ((match = dcRegex.exec(customData)) !== null) {
                const entry = match[1];
                // Skip label DC entries (they contain labelId)
                if (/labelId=/i.test(entry)) continue;
                const dcidMatch = entry.match(/dcid=([a-f0-9-]+)/i);
                const countMatch = entry.match(/count=(\d+)/i);
                const ucountMatch = entry.match(/ucount=(\d+)/i);
                const confMatch = entry.match(/conf=(\d+)/i);
                if (dcidMatch) {
                    results.push({
                        dcid: dcidMatch[1],
                        count: countMatch ? parseInt(countMatch[1]) : 0,
                        uniqueCount: ucountMatch ? parseInt(ucountMatch[1]) : 0,
                        confidence: confMatch ? parseInt(confMatch[1]) : 0,
                        raw: match[0]
                    });
                }
            }
            return results;
        }
        // Parse S:MLA=MLR entries for Server Side Auto Labeling
        function parseMLAFromCustomData(customData) {
            const results = [];
            const mlaRegex = /S:MLA=MLR\|ruleId=([a-f0-9-]+)\|mgtRuleId=([a-f0-9-]+)\|st=([^|]+)\|predicate=([^|]+)\|timeSpent=(\d+)(?:\|predicate=([^|]+)\|timeSpent=(\d+))?;?/gi;
            let match;
            while ((match = mlaRegex.exec(customData)) !== null) {
                results.push({
                    type: 'Server Side Auto Labeling',
                    ruleId: match[1],
                    mgtRuleId: match[2],
                    timestamp: match[3],
                    predicate: match[4] + (match[6] ? ', ' + match[6] : ''),
                    timeSpent: parseInt(match[5]) + (match[7] ? parseInt(match[7]) : 0),
                    raw: match[0]
                });
            }
            return results;
        }
        const PREDICATE_MAP = {
            'ECCSIP': 'ExContentContainsSensitiveInformationPredicate',
            'EEP': 'ExEqualPredicate',
            'EIECR': 'ExIsEncryptionChangeRequested',
            'EIERR': 'ExIsEncryptionRemoveRequested',
            'EILCR': 'ExIsLabelChangeRequested',
            'EIMOCGP': 'ExIsMemberOfCustomGroupsPredicate',
            'EIMOP': 'ExIsMemberOfPredicate',
            'EIP': 'ExIsPredicate',
            'ENBASP': 'ExNonBifurcatingAccessScopePredicate',
            'ERADAP': 'ExRecipientADAttributePredicate',
            'ETSP': 'ExTextScanPredicate',
            'CPE': 'CcsiPredicateEvaluators',
            'CC': 'ClassificationConfigurations',
            'ALP': 'ApplyLabelPredicate',
            'AOP': 'AuditOperationsPredicate',
            'CCP': 'ContainsClassificationPredicate',
            'CMLP': 'ContainsMachineLearningPredicate',
            'CCSIP': 'ContentContainsSensitiveInformationPredicate',
            'CMCP': 'ContentMetadataContainsPredicate',
            'EP': 'EqualPredicate/ExistsPredicate',
            'GTOEP': 'GreaterThanOrEqualPredicate',
            'GTP': 'GreaterThanPredicate',
            'IAP': 'IsAllPredicate',
            'IEP': 'IsEmptyPredicate',
            'IMOCGP': 'IsMemberOfCustomGroupsPredicate',
            'IMOP': 'IsMemberOfPredicate',
            'IP': 'IsPredicate',
            'LTOEP': 'LessThanOrEqualPredicate',
            'LTP': 'LessThanPredicate',
            'NVPCP': 'NameValuesPairConfigurationPredicate',
            'NEP': 'NotEqualPredicate/NotExistsPredicate',
            'NMP': 'NumericMatchPredicate',
            'PC': 'PredicateCondition',
            'PCC': 'PredicateConditionCommon',
            'PTSP': 'ProtectionTextScanPredicate',
            'QP': 'QueryPredicate',
            'TQP': 'TextQueryPredicate',
            'TSP': 'TextScanPredicate',
            'AC': 'AndCondition',
            'AndCondition': 'Compound Condition',
            'SensitiveInformationType': 'Sensitive Information Type Detection',
            'ContentContainsSensitiveInformation': 'Content Contains SIT',
            'FromMemberOf': 'Sender Group Membership',
            'SentTo': 'Recipient Check',
            'SubjectContainsWords': 'Subject Keyword Match'
        };
        const ACTION_MAP = {
            'BA': 'BlockAccess',
            'EAMARE': 'ExAddManagerAsRecipientExecutor',
            'EAR': 'ExAddRecipients',
            'EAREB': 'ExAddRecipientsExecutorBase',
            'EATRE': 'ExAddToRecipientsExecutor',
            'EABT': 'ExApplyBrandingTemplate',
            'EACM': 'ExApplyContentMarking',
            'EAHD': 'ExApplyHtmlDisclaimer',
            'EBCTRE': 'ExBlindCopyToRecipientsExecutor',
            'ECTRE': 'ExCopyToRecipientsExecutor',
            'EE': 'ExEncrypt',
            'EGAA': 'ExGenerateAlertAction',
            'ELE': 'ExLabelEncrypt',
            'EM': 'ExModerate',
            'EMS': 'ExModifySubject',
            'ENU': 'ExNotifyUser',
            'EPS': 'ExPrependSubject',
            'EQ': 'ExQuarantine',
            'ERMT': 'ExRedirectMessageTo',
            'ERH': 'ExRemoveHeader',
            'ERLE': 'ExRemoveLabelEncryption',
            'ERRMST': 'ExRemoveRMSTemplate',
            'ESH': 'ExSetHeader',
            'ESLA': 'ExStampLabelAction',
            'ARA': 'AddRecipientsAction',
            'ACMA': 'ApplyContentMarkingAction',
            'ALA': 'ApplyLabelAction',
            'AOA': 'ApplyOverrideAction',
            'ATA': 'ApplyTagAction',
            'BAA': 'BlockAccessAction',
            'BRAA': 'BrowserRestrictAccessAction',
            'CMP': 'ContentMarkingParam',
            'DCA': 'DisableConfigurationAction',
            'EA': 'EncryptAction',
            'GAA': 'GenerateAlertAction',
            'GIRA': 'GenerateIncidentReportAction',
            'GIR': 'GenerateIncidentReportAction',
            'HA': 'HaltAction/HoldAction',
            'LA': 'LabelAction',
            'MRAA': 'MipRestrictAccessAction',
            'NOA': 'NoOpAction',
            'NAB': 'NotifyActionBase',
            'NUA': 'NotifyUserAction',
            'NU': 'NotifyUserAction',
            'REA': 'RetentionExpireAction',
            'RRA': 'RetentionRecycleAction',
            'SRA': 'SelectivelyRetroactiveAction',
            'SLA': 'StampLabelAction',
            'TPAFA': 'TriggerPowerAutomateFlowAction'
        };
        function expandName(name, map) {
            if (!name) return name;
            if (map[name]) return name + ' (' + map[name] + ')';
            let expanded = name;
            Object.keys(map).forEach(function(key) {
                if (expanded.indexOf(key) !== -1) {
                    expanded = expanded.split(key).join(key + ' (' + map[key] + ')');
                }
            });
            return expanded;
        }
        function expandPredicateName(predicate) { return expandName(predicate, PREDICATE_MAP); }
        function expandActionName(action) { return expandName(action, ACTION_MAP); }

        function decodeContentBits(bits) {
            if (bits === undefined || bits === null || bits === '') return { value: '', actions: [] };
            const num = parseInt(bits);
            if (isNaN(num)) return { value: bits, actions: ['Unknown'] };
            if (num === 0) return { value: '0', actions: ['No action applied'] };
            const actions = [];
            if (num & 1) actions.push('Header marking');
            if (num & 2) actions.push('Footer marking');
            if (num & 4) actions.push('Watermark');
            if (num & 8) actions.push('Encryption');
            return { value: num.toString(), actions: actions.length > 0 ? actions : ['Unknown (' + num + ')'] };
        }
        function parseAllLabelData() {
            const results = [];
            rawData.forEach((msg, idx) => {
                if (!msg.custom_data) return;
                const labelMatches = parseLabelsFromCustomData(msg.custom_data);
                labelMatches.forEach(label => {
                    const bInfo = getBifurcationInfo(msg.message_id, msg.network_message_id);
                    results.push({
                        index: idx,
                        subject: msg.subject || 'No Subject',
                        sender: msg.sender || 'Unknown',
                        recipient: msg.recipient || 'Unknown',
                        networkMessageId: msg.network_message_id || '',
                        messageId: msg.message_id || '',
                        dateTime: msg.date_time,
                        labelId: label.labelId,
                        labelName: (typeof labelNameMapping[label.labelId] === 'object' ? labelNameMapping[label.labelId].Name : labelNameMapping[label.labelId]) || label.labelId,
                        labelInfo: typeof labelNameMapping[label.labelId] === 'object' ? labelNameMapping[label.labelId] : null,
                        labelType: label.labelType || '',
                        contentBits: label.contentBits || '',
                        raw: label.raw,
                        isBifurcated: bInfo.isBifurcated,
                        isForkedExternal: bInfo.isForkedExternal,
                        otherForks: bInfo.otherForks
                    });
                });
            });
            return results;
        }
        function parseLabelsFromCustomData(customData) {
            const results = [];
            // Match S:DPA=DC|labelId=<GUID>|labelType=<type>|contentBits=<num>
            const regex = /S:DPA=DC\|labelId=([a-f0-9-]+)\|labelType=([^|;]+)\|contentBits=(\d+);?/gi;
            let match;
            while ((match = regex.exec(customData)) !== null) {
                results.push({
                    labelId: match[1],
                    labelType: match[2],
                    contentBits: match[3],
                    raw: match[0]
                });
            }
            return results;
        }

        function renderDLPSummary(data) {
            const totalCount = data.reduce((sum, d) => sum + (d.count || 0), 0);
            const highConf = data.filter(d => d.confidence >= 85).length;
            const medConf = data.filter(d => d.confidence >= 65 && d.confidence < 85).length;
            const lowConf = data.filter(d => d.confidence < 65).length;
            const uniqueMessages = new Set(data.map(d => (d.messageId || '').toLowerCase().trim())).size;
            const forkedExtCount = new Set(data.filter(d => d.isForkedExternal).map(d => (d.messageId || '').toLowerCase().trim())).size;
            renderSummaryStats('dlpSummary', [
                {value: data.length, label: 'Total SIT Events', filter: 'all'},
                {value: uniqueMessages, label: 'Unique Messages', filter: 'uniquemessages'},
                {value: new Set(data.map(d => d.dcid)).size, label: 'Unique DCIDs', filter: 'uniquedcids'},
                {value: highConf, label: 'High Confidence (85+)', type: 'success', filter: 'highconf'},
                {value: medConf, label: 'Medium Confidence (65-84)', type: 'warning', filter: 'medconf'},
                {value: lowConf, label: 'Low Confidence (<65)', type: 'danger', filter: 'lowconf'},
                {value: forkedExtCount, label: 'Bifurcated Messages', type: 'danger', filter: 'forkedexternal'}
            ], 'dlp');
        }

        function renderDLPTable() {
            const tbody = document.getElementById('dlpTableBody');
            if (filteredDLPData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="compliance-empty"><div class="compliance-empty-icon">&#128373;</div><p>No Sensitive Information Type events found matching your criteria.</p></td></tr>';
                return;
            }
            const start = (pageState.dlp.page - 1) * pageState.dlp.size;
            let html = '';
            filteredDLPData.slice(start, start + pageState.dlp.size).forEach(function(item, idx) {
                const gIdx = start + idx;
                const cc = item.confidence >= 85 ? 'confidence-high' : (item.confidence >= 65 ? 'confidence-medium' : 'confidence-low');
                html += tableRow('compliance-detail-row', 'dlp-' + gIdx, [
                    {html: escapeHtml(truncateText(item.subject, 40)) + '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + formatJourneyDate(item.dateTime) + '</div>', title: escapeHtml(item.subject)},
                    {html: escapeHtml(truncateEmail(item.sender)), title: escapeHtml(item.sender)},
                    {html: escapeHtml(truncateEmail(item.recipient)), title: escapeHtml(item.recipient)},
                    {html: '<span class="sit-id" title="' + item.dcid + '">' + truncateText(item.dcid, 20) + '</span>'},
                    {html: escapeHtml(truncateText(item.sitName || 'N/A', 30)), title: escapeHtml(item.sitName || 'N/A')},
                    {html: escapeHtml(truncateText(item.policyName || 'N/A', 30)), title: escapeHtml(item.policyName || 'N/A')},
                    {html: item.count},
                    {html: '<span class="confidence-badge ' + cc + '">' + item.confidence + '%</span>'}
                ], 'toggleComplianceDetail');
                html += '<tr><td colspan="9" style="padding:0;"><div class="compliance-detail-content" id="dlp-' + gIdx + '"><div class="compliance-detail-grid">';
                html += detailItem('&#128270;', 'DCID', item.dcid, {mono:true});
                const sitInfo = getSITInfo(item.dcid);
                const sitDisplayName = getSITDisplayName(item.dcid);
                const customBadge = (sitInfo && sitInfo.IsCustom) ? '<span class="badge-sm custom-sit-badge">CUSTOM</span>' : '';
                const recConf = (sitInfo && sitInfo.RecommendedConfidence) ? '<span style="font-size:0.7rem;color:var(--text-secondary);"> (Recommended: ' + sitInfo.RecommendedConfidence + '%)</span>' : '';
                html += detailItem('&#128203;', 'SIT Name', escapeHtml(item.sitName || 'N/A') + customBadge + recConf);
                html += detailItem('&#128196;', 'Policy Name', escapeHtml(item.policyName || 'N/A'));
                html += detailItem('&#128200;', 'Count', item.count);
                html += detailItem('&#128200;', 'Unique Count', item.uniqueCount);
                const confClass = item.confidence >= 85 ? 'confidence-high' : (item.confidence >= 65 ? 'confidence-medium' : 'confidence-low');
                html += detailItem('&#127919;', 'Confidence', '<span class="confidence-badge ' + confClass + '">' + item.confidence + '%</span>');
                // False positive risk (Task 3.3)
                const fpReasons = assessFPRisk(item);
                if (fpReasons.length > 0) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-value"><span class="badge-sm fp-risk-badge" title="' + escapeHtml(fpReasons.join('; ')) + '">⚠ FP Risk</span> <span style="font-size:0.8rem;color:var(--text-secondary);">' + escapeHtml(fpReasons.join('; ')) + '</span></div></div>';
                }
                // Count interpretation (Task 3.4)
                if (item.count > 1 && item.uniqueCount > 0 && (item.count / item.uniqueCount) > 3) {
                    html += '<div class="info-note">ℹ️ Count (' + item.count + ') >> UniqueCount (' + item.uniqueCount + ') — Same value detected multiple times. Possible template, signature, or repeated pattern.</div>';
                }
                html += detailItem('&#128233;', 'Network Message ID', item.networkMessageId || 'N/A', {mono:true});
                html += detailItem('&#128233;', 'Message ID', escapeHtml(item.messageId) || 'N/A', {mono:true});
                if (item.isBifurcated) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128260; Message Forked (External Recipients)</div><div class="compliance-detail-value">';
                    if (item.otherForks.length > 0) {
                        html += '<div style="margin-bottom:4px;">Other Network Message IDs for this message:</div><div class="dlp-actions-list" style="max-height:none;">';
                        item.otherForks.forEach(function(fk) { html += '<span class="dlp-action-item" style="font-family:monospace;font-size:0.8rem;">' + escapeHtml(fk) + '</span>'; });
                        html += '</div>';
                    } else {
                        html += 'This message was forked for external recipients. Rules were evaluated against each copy.';
                    }
                    html += '</div></div>';
                }
                html += detailItem('&#128100;', 'Sender', escapeHtml(item.sender));
                html += detailItem('&#128101;', 'Recipient', escapeHtml(item.recipient));
                html += detailItem('&#128221;', 'Subject', escapeHtml(item.subject));
                // SIT detection location note (Task 3.5)
                html += '<div class="info-note">ℹ️ Detection location (subject/body/attachment) is not available in message traces. Use <strong>DLP Activity Explorer</strong> or <strong>Unified Audit Log</strong>: <code>Search-UnifiedAuditLog -Operations DlpRuleMatch -StartDate {date} -EndDate {date}</code></div>';
                // Encryption impact (Task 3.14)
                const msgForEnc = rawData.find(r => (r.network_message_id || '').toLowerCase().trim() === (item.networkMessageId || '').toLowerCase().trim());
                if (msgForEnc) {
                    const labelEvts = allLabelsData.filter(l => (l.networkMessageId || l.messageId || '').toLowerCase().trim() === (item.networkMessageId || '').toLowerCase().trim());
                    const hasEncryption = labelEvts.some(l => { const cb = decodeContentBits(l.contentBits); return cb.actions && cb.actions.some(a => a.toLowerCase().includes('encrypt')); });
                    if (hasEncryption && item.confidence < 50) {
                        html += '<div class="info-note">🔒 Encrypted message with low confidence detection — DLP scanning of encrypted content depends on tenant configuration.</div>';
                    }
                }
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128196; Raw Data</div><div class="compliance-detail-value" style="font-family:monospace;font-size:0.8rem;background:#2d2d2d;color:#f0f0f0;padding:10px;border-radius:6px;">' + escapeHtml(item.raw) + '</div></div>';
                html += '</div></div></td></tr>';
            });
            tbody.innerHTML = html;
        }
        function renderSSAMSummary(data) {
            const uniqueMessages = new Set(data.map(d => (d.messageId || '').toLowerCase().trim())).size;
            const forkedExtCount = new Set(data.filter(d => d.isForkedExternal).map(d => (d.messageId || '').toLowerCase().trim())).size;
            renderSummaryStats('ssamSummary', [
                {value: data.length, label: 'Total Auto-Label Events', filter: 'all'},
                {value: uniqueMessages, label: 'Unique Messages', filter: 'uniquemessages'},
                {value: new Set(data.map(d => d.ruleId)).size, label: 'Unique Rules', filter: 'uniquerules'},
                {value: data.filter(d => d.predicate && d.predicate.includes('SensitiveInformation')).length, label: 'SIT Detections', type: 'danger', filter: 'sit'},
                {value: forkedExtCount, label: 'Bifurcated Messages', type: 'danger', filter: 'forkedexternal'}
            ], 'ssam');
        }
        function filterSSAMTable() {
            const allSearch = document.getElementById('ssamFilterAll').value.toLowerCase();
            const ruleNameFilter = document.getElementById('ssamFilterRuleName').value;
            const policyNameFilter = document.getElementById('ssamFilterPolicyName').value;

            filteredSSAMData = allSSAMData.filter(function(d) {
                const allFields = [d.subject, d.sender, d.recipient, d.ruleId, d.type, d.predicate, d.raw, d.timestamp].join(' ').toLowerCase();
                if (allSearch && !allFields.includes(allSearch)) return false;
                if (ruleNameFilter) {
                    const ruleName = getSSAMRuleName(d.ruleId);
                    if (ruleName !== ruleNameFilter) return false;
                }
                if (policyNameFilter) {
                    const policyName = getSSAMPolicyName(d.ruleId);
                    if (policyName !== policyNameFilter) return false;
                }
                const bifurcatedFilter = document.getElementById('ssamFilterBifurcated').value;
                if (bifurcatedFilter === 'yes' && !d.isForkedExternal) return false;
                if (bifurcatedFilter === 'no' && d.isForkedExternal) return false;
                return true;
            });

            renderSSAMSummary(filteredSSAMData);
            pageState.ssam.page = 1;
            renderSSAMTable();
            updateSSAMPagination();
        }

        function renderSSAMTable() {
            const tbody = document.getElementById('ssamTableBody');
            if (filteredSSAMData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="compliance-empty"><div class="compliance-empty-icon">&#127991;</div><p>No Server Side Auto Labeling events found matching your criteria.</p></td></tr>';
                return;
            }
            const start = (pageState.ssam.page - 1) * pageState.ssam.size;
            let html = '';
            filteredSSAMData.slice(start, start + pageState.ssam.size).forEach(function(item, idx) {
                const gIdx = start + idx;
                const ssamRuleName = getSSAMRuleName(item.ruleId);
                html += tableRow('compliance-detail-row', 'ssam-' + gIdx, [
                    {html: escapeHtml(truncateText(item.subject, 40)) + '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + formatJourneyDate(item.dateTime) + '</div>', title: escapeHtml(item.subject)},
                    {html: escapeHtml(truncateEmail(item.sender)), title: escapeHtml(item.sender)},
                    {html: escapeHtml(truncateEmail(item.recipient)), title: escapeHtml(item.recipient)},
                    {html: '<span title="' + escapeHtml(ssamRuleName) + '">' + escapeHtml(truncateText(ssamRuleName, 25)) + '</span>'},
                    {html: '<span class="sit-id" title="' + item.ruleId + '">' + truncateText(item.ruleId, 20) + '</span>'},
                    {html: '<div class="dlp-predicates-list"><span class="dlp-predicate-item">' + wrapAbbreviation(item.predicate) + ' (' + item.timeSpent + 'ms)</span></div>'}
                ], 'toggleComplianceDetail');
                html += '<tr><td colspan="7" style="padding:0;"><div class="compliance-detail-content" id="ssam-' + gIdx + '"><div class="compliance-detail-grid">';
                html += detailItem('&#127991;', 'Rule Type', '<span class="confidence-badge confidence-medium">Server Side Auto Labeling</span>');
                html += detailItem('&#128203;', 'Rule Name', ssamRuleName || 'N/A');
                html += detailItem('&#128373;', 'MIP Label Rule ID', item.ruleId || 'N/A', {mono:true});

                // Add additional rule properties from SSAM lookup
                const ssamRuleInfo = getSSAMRuleInfo(item.ruleId);
                if (ssamRuleInfo) {
                    if (ssamRuleInfo.ParentPolicyName) html += detailItem('&#128196;', 'Policy', ssamRuleInfo.ParentPolicyName);
                    if (ssamRuleInfo.Priority !== null && ssamRuleInfo.Priority !== undefined) html += detailItem('&#128200;', 'Priority', ssamRuleInfo.Priority);
                    if (ssamRuleInfo.Workload) html += detailItem('&#128188;', 'Workload', ssamRuleInfo.Workload);
                    if (ssamRuleInfo.Disabled !== null && ssamRuleInfo.Disabled !== undefined) html += detailItem('&#128683;', 'Disabled', ssamRuleInfo.Disabled ? 'Yes' : 'No');
                    if (ssamRuleInfo.Mode) html += detailItem('&#9881;', 'Mode', ssamRuleInfo.Mode);
                    if (ssamRuleInfo.WhenChangedUTC) html += detailItem('&#128197;', 'When Changed (UTC)', ssamRuleInfo.WhenChangedUTC);
                    if (ssamRuleInfo.WhenCreated) html += detailItem('&#128197;', 'When Created', ssamRuleInfo.WhenCreated);
                    if (ssamRuleInfo.CreatedBy) html += detailItem('&#128100;', 'Created By', ssamRuleInfo.CreatedBy);
                    if (ssamRuleInfo.LastModifiedBy) html += detailItem('&#128100;', 'Last Modified By', ssamRuleInfo.LastModifiedBy);
                    if (ssamRuleInfo.GUID) html += detailItem('&#128273;', 'Rule GUID', ssamRuleInfo.GUID, {mono:true});
                }
                // SSAM simulation mode warning (Task 2.18)
                const ssamInfo = ssamRuleNameMapping[item.ruleId];
                if (ssamInfo && ssamInfo.SimulationMode) {
                    html += '<div class="ssam-simulation-banner">⚠️ <strong>Simulation Mode</strong> — This auto-labeling policy is in simulation mode. Labels will NOT be applied to actual messages.</div>';
                }
                if (ssamInfo && ssamInfo.PolicyMode) {
                    html += '<div style="font-size:0.8rem;color:var(--text-secondary);margin:4px 0;">Policy Mode: <strong>' + escapeHtml(ssamInfo.PolicyMode) + '</strong> | Enabled: ' + (ssamInfo.PolicyEnabled ? '✅' : '❌') + '</div>';
                }

                html += detailItem('&#128233;', 'Network Message ID', item.networkMessageId || 'N/A', {mono:true});
                html += detailItem('&#128233;', 'Message ID', escapeHtml(item.messageId) || 'N/A', {mono:true});
                if (item.isBifurcated) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128260; Message Forked (External Recipients)</div><div class="compliance-detail-value">';
                    if (item.otherForks.length > 0) {
                        html += '<div style="margin-bottom:4px;">Other Network Message IDs for this message:</div><div class="dlp-actions-list" style="max-height:none;">';
                        item.otherForks.forEach(function(fk) { html += '<span class="dlp-action-item" style="font-family:monospace;font-size:0.8rem;">' + escapeHtml(fk) + '</span>'; });
                        html += '</div>';
                    } else {
                        html += 'This message was forked for external recipients. Rules were evaluated against each copy.';
                    }
                    html += '</div></div>';
                }
                if (item.mgtRuleId) html += detailItem('&#128203;', 'Management Rule ID', item.mgtRuleId, {mono:true});
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#127919; Predicate Evaluated (1)</div><div class="compliance-detail-value"><div class="dlp-predicates-list" style="max-height:none;max-width:none;"><span class="dlp-predicate-item"><span class="predicate-badge pass">&#10004;</span> ' + wrapAbbreviation(item.predicate) + ' (' + item.timeSpent + 'ms)</span></div></div></div>';
                html += detailItem('&#128197;', 'Rule Timestamp', item.timestamp || 'N/A');
                html += detailItem('&#128100;', 'Sender', escapeHtml(item.sender));
                html += detailItem('&#128101;', 'Recipient', escapeHtml(item.recipient));
                html += detailItem('&#128221;', 'Subject', escapeHtml(item.subject));
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128196; Raw Data</div><div class="compliance-detail-value" style="font-family:monospace;font-size:0.8rem;background:#2d2d2d;color:#f0f0f0;padding:10px;border-radius:6px;">' + escapeHtml(item.raw) + '</div></div>';
                html += '</div></div></td></tr>';
            });
            tbody.innerHTML = html;
        }

        function updateSSAMPagination() { pgUpdate('ssam'); }
        function ssamPreviousPage() { pgPrev('ssam'); }
        function ssamNextPage() { pgNext('ssam'); }

        function resetSSAMFilters() {
            resetFilters(['ssamFilterAll','ssamFilterRuleName','ssamFilterPolicyName','ssamFilterBifurcated'], filterSSAMTable);
        }

        function exportSSAMToCSV() {
            exportTableToCSV(filteredSSAMData, [
                {header: 'Subject', field: 'subject'}, {header: 'Sender', field: 'sender'},
                {header: 'Recipient', field: 'recipient'}, {header: 'Rule ID', field: 'ruleId'},
                {header: 'Type', field: 'type'}, {header: 'Predicate', field: 'predicate'},
                {header: 'Confidence', field: 'confidence'},
                {header: 'Network Message ID', field: 'networkMessageId'},
                {header: 'Message ID', field: 'messageId'}, {header: 'Timestamp', field: 'timestamp'},
                {header: 'Date/Time', field: 'dateTime'}
            ], 'server_side_auto_labeling_events.csv');
        }

        function renderLabelsSummary(data) {
            const uniqueMessages = new Set(data.map(d => (d.messageId || '').toLowerCase().trim())).size;
            const forkedExtCount = new Set(data.filter(d => d.isForkedExternal).map(d => (d.messageId || '').toLowerCase().trim())).size;
            renderSummaryStats('labelsSummary', [
                {value: data.length, label: 'Total Label Events', filter: 'all'},
                {value: uniqueMessages, label: 'Unique Messages', filter: 'uniquemessages'},
                {value: new Set(data.map(d => d.index)).size, label: 'Labeled Messages', filter: 'labeledmessages'},
                {value: new Set(data.map(d => d.labelId)).size, label: 'Unique Labels', type: 'success', filter: 'uniquelabels'},
                {value: new Set(data.map(d => d.labelType)).size, label: 'Unique Label Types', filter: 'uniquetypes'},
                {value: forkedExtCount, label: 'Bifurcated Messages', type: 'danger', filter: 'forkedexternal'}
            ], 'labels');
        }

        function renderLabelsTable() {
            const tbody = document.getElementById('labelsTableBody');
            if (filteredLabelsData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="compliance-empty"><div class="compliance-empty-icon">&#127991;</div><p>No Sensitivity Labels found matching your criteria.</p></td></tr>';
                return;
            }
            const start = (pageState.labels.page - 1) * pageState.labels.size;
            let html = '';
            filteredLabelsData.slice(start, start + pageState.labels.size).forEach(function(item, idx) {
                const gIdx = start + idx;
                const cb = decodeContentBits(item.contentBits);
                html += tableRow('compliance-detail-row', 'label-' + gIdx, [
                    {html: escapeHtml(truncateText(item.subject, 40)) + '<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">' + formatJourneyDate(item.dateTime) + '</div>', title: escapeHtml(item.subject)},
                    {html: escapeHtml(truncateEmail(item.sender)), title: escapeHtml(item.sender)},
                    {html: escapeHtml(truncateEmail(item.recipient)), title: escapeHtml(item.recipient)},
                    {html: '<span class="sit-id" title="' + item.labelId + '">' + truncateText(item.labelId, 20) + '</span>'},
                    {html: escapeHtml(truncateText(item.labelName || 'N/A', 30)), title: escapeHtml(item.labelName || 'N/A')},
                    {html: escapeHtml(item.labelType || 'N/A')},
                    {html: cb.value ? '<span title="' + cb.actions.join(', ') + '">' + cb.value + '</span>' : 'N/A'}
                ], 'toggleComplianceDetail');
                html += '<tr><td colspan="8" style="padding:0;"><div class="compliance-detail-content" id="label-' + gIdx + '"><div class="compliance-detail-grid">';
                html += detailItem('&#127991;', 'Label ID', item.labelId, {mono:true});
                html += detailItem('&#127991;', 'Label Name', escapeHtml(item.labelName || 'N/A'));
                html += detailItem('&#127991;', 'Label Type', item.labelType || 'N/A');
                html += detailItem('&#128204;', 'Content Bits', cb.value ? cb.value + ' - ' + cb.actions.join(', ') : 'N/A');
                // Label source (Task 2.8)
                const netId = (item.networkMessageId || item.messageId || '').toLowerCase().trim();
                const isAutoLabeled = allSSAMData.some(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId);
                const isDLPLabeled = allDLPRulesData.some(d => (d.networkMessageId || d.messageId || '').toLowerCase().trim() === netId && d.actions && d.actions.some(a => a.name === 'ESLA' || a.name === 'ALA'));
                let labelSourceBadge = '';
                if (isAutoLabeled) labelSourceBadge = '<span class="badge-md label-source-badge auto">🤖 Server Auto-Label</span>';
                else if (isDLPLabeled) labelSourceBadge = '<span class="badge-md label-source-badge auto">📋 DLP Rule Applied</span>';
                else labelSourceBadge = '<span class="badge-md label-source-badge manual">👤 Manual/Client</span>';
                html += detailItem('&#128204;', 'Label Source', labelSourceBadge);
                // Label hierarchy info (Task 2.6)
                const lInfo = getLabelInfo(item.labelId);
                let labelHierarchyHtml = '';
                if (lInfo) {
                    if (lInfo.ParentLabelId) {
                        const parentName = getLabelDisplayName(lInfo.ParentLabelId);
                        labelHierarchyHtml = '<div style="font-size:0.8rem;color:var(--text-secondary);">Parent: ' + escapeHtml(parentName) + ' (Priority: ' + (lInfo.Priority || 'N/A') + ')</div>';
                    }
                    // Protection settings verification (Task 2.9)
                    const expectedProtections = [];
                    if (lInfo.EncryptionEnabled) expectedProtections.push('Encryption');
                    if (lInfo.ContentMarkingHeaderEnabled) expectedProtections.push('Header');
                    if (lInfo.ContentMarkingFooterEnabled) expectedProtections.push('Footer');
                    if (lInfo.WatermarkEnabled) expectedProtections.push('Watermark');
                    if (expectedProtections.length > 0) {
                        const cbCheck = decodeContentBits(item.contentBits);
                        const applied = cbCheck.actions || [];
                        const missing = expectedProtections.filter(p => !applied.some(a => a.toLowerCase().includes(p.toLowerCase())));
                        if (missing.length > 0) {
                            labelHierarchyHtml += '<div style="color:var(--accent-red);font-size:0.8rem;">⚠️ Expected protection NOT applied: ' + missing.join(', ') + '</div>';
                        } else {
                            labelHierarchyHtml += '<div style="color:var(--accent-green);font-size:0.8rem;">✅ All configured protections applied</div>';
                        }
                    }
                }
                if (labelHierarchyHtml) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">🏷️ Label Details</div><div class="compliance-detail-value">' + labelHierarchyHtml + '</div></div>';
                }
                // Label changes (Task 2.7)
                const labelChanges = detectLabelChanges(netId);
                if (labelChanges.length > 0) {
                    let labelChangeHtml = '';
                    labelChanges.forEach(c => {
                        labelChangeHtml += '<div class="label-change-indicator ' + c.direction + '">';
                        labelChangeHtml += (c.direction === 'downgrade' ? '⬇️' : '⬆️') + ' Label ' + c.direction + ': ';
                        labelChangeHtml += escapeHtml(c.from) + ' → ' + escapeHtml(c.to);
                        if (c.direction === 'downgrade') labelChangeHtml += ' <strong>⚠️ Compliance Alert</strong>';
                        labelChangeHtml += '</div>';
                    });
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">🔄 Label Changes</div><div class="compliance-detail-value">' + labelChangeHtml + '</div></div>';
                    // Justification note (Task 3.6)
                    if (labelChanges.some(c => c.direction === 'downgrade')) {
                        html += '<div class="info-note">ℹ️ Label downgrade justification is recorded in the Unified Audit Log, not message traces. Query: <code>Search-UnifiedAuditLog -Operations SensitivityLabelChanged -StartDate {date}</code></div>';
                    }
                }
                // "Why Was This Label Applied?" guide (Task 2.12)
                const labelMsg = rawData.find(r => (r.network_message_id || '').toLowerCase().trim() === netId);
                if (labelMsg) {
                    const whyLabelHtml = buildWhyLabelGuide(labelMsg, item);
                    if (whyLabelHtml) html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-value">' + whyLabelHtml + '</div></div>';
                }
                html += detailItem('&#128233;', 'Network Message ID', item.networkMessageId || 'N/A', {mono:true});
                html += detailItem('&#128233;', 'Message ID', escapeHtml(item.messageId) || 'N/A', {mono:true});
                if (item.isBifurcated) {
                    html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128260; Message Forked (External Recipients)</div><div class="compliance-detail-value">';
                    if (item.otherForks.length > 0) {
                        html += '<div style="margin-bottom:4px;">Other Network Message IDs for this message:</div><div class="dlp-actions-list" style="max-height:none;">';
                        item.otherForks.forEach(function(fk) { html += '<span class="dlp-action-item" style="font-family:monospace;font-size:0.8rem;">' + escapeHtml(fk) + '</span>'; });
                        html += '</div>';
                    } else {
                        html += 'This message was forked for external recipients. Rules were evaluated against each copy.';
                    }
                    html += '</div></div>';
                }
                html += detailItem('&#128100;', 'Sender', escapeHtml(item.sender));
                html += detailItem('&#128101;', 'Recipient', escapeHtml(item.recipient));
                html += detailItem('&#128221;', 'Subject', escapeHtml(item.subject));
                html += '<div class="compliance-detail-item" style="grid-column:1/-1;"><div class="compliance-detail-label">&#128196; Raw Data</div><div class="compliance-detail-value" style="font-family:monospace;font-size:0.8rem;background:#2d2d2d;color:#f0f0f0;padding:10px;border-radius:6px;">' + escapeHtml(item.raw) + '</div></div>';
                html += '</div></div></td></tr>';
            });
            tbody.innerHTML = html;
        }

        // Message View
        let allMessageViewData = [];
        let filteredMessageViewData = [];

        function buildMessageViewData() {
            const messageMap = {};
            rawData.forEach((msg, idx) => {
                const netId = (msg.network_message_id || msg.message_id || 'msg-' + idx).toLowerCase().trim();
                if (!messageMap[netId]) {
                    messageMap[netId] = {
                        netId: netId,
                        subject: msg.subject || 'No Subject',
                        sender: msg.sender || 'Unknown',
                        recipient: msg.recipient || 'Unknown',
                        dateTime: msg.date_time,
                        directionality: msg.directionality || '',
                        custom_data: msg.custom_data || '',
                        source_context: msg.source_context || '',
                        eventId: msg.event_id || '',
                        dlpRules: [],
                        sitDetections: [],
                        ssamEvents: [],
                        labelEvents: [],
                        messageInfo: msg.message_info || '',
                        recipientStatus: msg.recipient_status || '',
                        sourceContext: msg.source_context || ''
                    };
                }
            });

            allDLPRulesData.forEach(d => {
                const key = (d.networkMessageId || d.messageId || '').toLowerCase().trim();
                if (messageMap[key]) messageMap[key].dlpRules.push(d);
            });
            allDLPData.forEach(d => {
                const key = (d.networkMessageId || d.messageId || '').toLowerCase().trim();
                if (messageMap[key]) messageMap[key].sitDetections.push(d);
            });
            allSSAMData.forEach(d => {
                const key = (d.networkMessageId || d.messageId || '').toLowerCase().trim();
                if (messageMap[key]) messageMap[key].ssamEvents.push(d);
            });
            allLabelsData.forEach(d => {
                const key = (d.networkMessageId || d.messageId || '').toLowerCase().trim();
                if (messageMap[key]) messageMap[key].labelEvents.push(d);
            });

            allMessageViewData = Object.values(messageMap).filter(m =>
                m.dlpRules.length > 0 || m.sitDetections.length > 0 || m.ssamEvents.length > 0 || m.labelEvents.length > 0
            );
            allMessageViewData.sort((a, b) => (b.dateTime || '').localeCompare(a.dateTime || ''));
        }

        function filterMessageView() {
            const search = document.getElementById('messageViewFilter').value.toLowerCase();
            filteredMessageViewData = allMessageViewData.filter(m => {
                if (!search) return true;
                return (m.subject && m.subject.toLowerCase().includes(search)) ||
                       (m.sender && m.sender.toLowerCase().includes(search)) ||
                       (m.recipient && m.recipient.toLowerCase().includes(search)) ||
                       (m.netId && m.netId.includes(search));
            });
            pageState.mv.page = 1;
            renderMessageView();
            updateMVPagination();
        }

        function renderMessageView() {
            const container = document.getElementById('messageViewContent');
            if (filteredMessageViewData.length === 0) {
                container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-secondary);">No messages with compliance events found.</div>';
                return;
            }
            const start = (pageState.mv.page - 1) * pageState.mv.size;
            const page = filteredMessageViewData.slice(start, start + pageState.mv.size);
            let html = '';
            page.forEach((msg, idx) => {
                const gIdx = start + idx;
                const totalEvents = msg.dlpRules.length + msg.sitDetections.length + msg.ssamEvents.length + msg.labelEvents.length;
                const matchedDLP = msg.dlpRules.filter(d => d.matched).length;

                html += '<div class="message-view-card">';
                html += '<div class="message-view-header" onclick="toggleMessageView(\'mv-' + gIdx + '\')">';
                html += '<div><strong>' + escapeHtml(truncateText(msg.subject, 60)) + '</strong>';

                html += '<div style="font-size:0.8rem;color:var(--text-secondary);">' + escapeHtml(msg.sender) + ' \u2192 ' + escapeHtml(msg.recipient) + '</div></div>';
                html += '<div style="text-align:right;font-size:0.8rem;">';
                if (msg.dlpRules.length > 0) html += '<span class="mode-badge enforce" style="margin:2px;">' + msg.dlpRules.length + ' DLP</span>';
                if (msg.sitDetections.length > 0) html += '<span class="mode-badge test" style="margin:2px;">' + msg.sitDetections.length + ' SIT</span>';
                if (msg.ssamEvents.length > 0) html += '<span class="mode-badge test-notify" style="margin:2px;">' + msg.ssamEvents.length + ' SSAM</span>';
                if (msg.labelEvents.length > 0) html += '<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.75rem;font-weight:600;background:rgba(179,157,219,0.2);color:#b39ddb;margin:2px;">' + msg.labelEvents.length + ' Label</span>';
                html += '<div style="color:var(--text-secondary);margin-top:4px;">' + formatJourneyDate(msg.dateTime) + '</div>';
                html += '</div></div>';

                html += '<div class="message-view-body" id="mv-' + gIdx + '">';
                html += '<div class="message-timeline">';
                // Event flow
                const evFlow = buildEventFlow(msg.netId);
                if (evFlow) html += '<div style="margin-bottom:12px;"><strong>📬 Event Flow:</strong> ' + evFlow + '</div>';
                // Anti-spam/malware check
                const sfa = parseSFAFromCustomData(msg.custom_data);
                const ama = parseAMAFromCustomData(msg.custom_data);
                if (sfa && (sfa.action === 'quarantine' || sfa.action === 'block')) {
                    html += '<div class="override-banner">🛡️ <strong>Anti-Spam:</strong> ' + escapeHtml(sfa.action) + ' (Reason: ' + escapeHtml(sfa.reason) + ', SCL: ' + escapeHtml(sfa.scl) + ')</div>';
                }
                if (ama && (ama.action === 'quarantine' || ama.action === 'block')) {
                    html += '<div class="override-banner">🛡️ <strong>Anti-Malware:</strong> ' + escapeHtml(ama.action) + '</div>';
                }
                // DL expansion (Task 3.8)
                const hasExpand = rawData.some(r => (r.network_message_id || '').toLowerCase().trim() === msg.netId && (r.event_id || '').toUpperCase() === 'EXPAND');
                if (hasExpand) {
                    html += '<div class="info-note">📨 Distribution list expansion detected — DLP evaluated each expanded recipient separately.</div>';
                }
                // Connector info (Task 3.10)
                const scInfo = parseSourceContext(msg.sourceContext);
                if (scInfo && (scInfo.protocol || scInfo.connector)) {
                    let connHtml = '<div style="font-size:0.8rem;color:var(--text-secondary);margin:4px 0;">🔌 ';
                    if (scInfo.protocol) connHtml += 'Protocol: <strong>' + escapeHtml(scInfo.protocol) + '</strong> ';
                    if (scInfo.connector) connHtml += '| Connector: <strong>' + escapeHtml(scInfo.connector) + '</strong>';
                    connHtml += '</div>';
                    html += connHtml;
                }

                msg.dlpRules.forEach(d => {
                    const ruleName = getRuleName(d.ruleId);
                    const ruleInfo = getRuleInfo(d.ruleId);
                    const mode = (ruleInfo && (ruleInfo.PolicyMode || ruleInfo.Mode)) || '';
                    const status = d.matched ? '\u2705 Matched' : '\u274C Not Matched';
                    const actionsStr = d.actions.map(a => expandActionName(a.name)).join(', ');
                    html += '<div class="timeline-item"><div class="timeline-dot dlp"></div>';
                    html += '<div class="timeline-type" style="color:var(--accent-blue);">DLP Rule Evaluation</div>';
                    html += '<div class="timeline-content"><strong>' + escapeHtml(ruleName) + '</strong> \u2014 ' + status;
                    if (mode) html += ' <span class="mode-badge ' + (mode.toLowerCase().includes('enforce') ? 'enforce' : 'test') + '">' + mode + '</span>';
                    if (actionsStr) html += '<div class="timeline-detail">Actions: ' + actionsStr + '</div>';
                    // Override check for this DLP rule
                    const ruleOverrides = parseOverridesFromCustomData(msg.custom_data).filter(o => o.ruleId === d.ruleId);
                    if (ruleOverrides.length > 0) {
                        html += '<div class="timeline-detail" style="color:var(--accent-amber);">⚠️ Override: ' + escapeHtml(ruleOverrides[0].overrideType) + (ruleOverrides[0].justification ? ' — "' + escapeHtml(ruleOverrides[0].justification) + '"' : '') + '</div>';
                    }
                    html += '</div></div>';
                });
                msg.sitDetections.forEach(d => {
                    const confClass = d.confidence >= 85 ? 'confidence-high' : (d.confidence >= 65 ? 'confidence-medium' : 'confidence-low');
                    html += '<div class="timeline-item"><div class="timeline-dot sit"></div>';
                    html += '<div class="timeline-type" style="color:var(--accent-amber);">SIT Detection</div>';
                    html += '<div class="timeline-content"><strong>' + escapeHtml(d.sitName || d.dcid) + '</strong>';
                    html += ' \u2014 <span class="confidence-badge ' + confClass + '">' + d.confidence + '%</span>';
                    html += ' (Count: ' + d.count + ', Unique: ' + d.uniqueCount + ')';
                    html += '</div></div>';
                });
                msg.ssamEvents.forEach(d => {
                    const ssamName = getSSAMRuleName(d.ruleId);
                    html += '<div class="timeline-item"><div class="timeline-dot ssam"></div>';
                    html += '<div class="timeline-type" style="color:var(--accent-purple);">Server Side Auto Labeling</div>';
                    html += '<div class="timeline-content"><strong>' + escapeHtml(ssamName) + '</strong>';
                    html += '<div class="timeline-detail">Predicate: ' + expandPredicateName(d.predicate) + ' (' + d.timeSpent + 'ms)</div>';
                    html += '</div></div>';
                });
                msg.labelEvents.forEach(d => {
                    const cb = decodeContentBits(d.contentBits);
                    const isAutoLabel = msg.ssamEvents.length > 0;
                    const sourceTag = isAutoLabel ? '🤖 Server Auto-Label' : '👤 Manual/Client';
                    html += '<div class="timeline-item"><div class="timeline-dot label"></div>';
                    html += '<div class="timeline-type" style="color:var(--accent-green);">Sensitivity Label Applied</div>';
                    html += '<div class="timeline-content"><strong>' + escapeHtml(d.labelName || d.labelId) + '</strong>';
                    html += ' (Type: ' + (d.labelType || 'N/A') + ')';
                    if (cb.actions.length > 0) html += '<div class="timeline-detail">Protection: ' + cb.actions.join(', ') + '</div>';
                    html += '<div class="timeline-detail">Source: ' + sourceTag + '</div>';
                    html += '</div></div>';
                });
                if (msg.messageInfo) {
                    html += '<div style="margin-top:12px;padding:10px;background:var(--bg-elevated);border-radius:6px;font-size:0.8rem;">';
                    html += '<strong>\uD83D\uDCCB Message Info:</strong> ' + escapeHtml(truncateText(msg.messageInfo, 200));
                    html += '</div>';
                }
                if (msg.recipientStatus && msg.recipientStatus.length > 10) {
                    html += '<div style="margin-top:8px;padding:10px;background:var(--bg-elevated);border-radius:6px;font-size:0.8rem;">';
                    html += '<strong>\uD83D\uDCEC Recipient Status:</strong> ' + escapeHtml(truncateText(msg.recipientStatus, 200));
                    html += '</div>';
                }
                html += '</div></div></div>';
            });
            container.innerHTML = html;
        }
        function toggleMessageView(id) {
            const body = document.getElementById(id);
            body.classList.toggle('show');
        }
        function mvPreviousPage() { pgPrev('mv'); }
        function mvNextPage() { pgNext('mv'); }
        function updateMVPagination() { pgUpdate('mv'); }
        function switchComplianceTab(tab, btn) {
            document.querySelectorAll('.compliance-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.compliance-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tab + 'Panel').classList.add('active');
        }

        function toggleComplianceDetail(id, row) {
            const detail = document.getElementById(id);
            const isShown = detail.classList.contains('show');

            // Close all other details
            document.querySelectorAll('.compliance-detail-content.show').forEach(d => d.classList.remove('show'));
            document.querySelectorAll('.compliance-detail-row.expanded').forEach(r => r.classList.remove('expanded'));
            if (!isShown) {
                detail.classList.add('show');
                row.classList.add('expanded');
            }
        }
        function truncateText(text, maxLen) {
            if (!text) return '';
            return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
        }
        function formatJourneyDate(dateStr) {
            if (!dateStr) return 'Unknown';
            try {
                const d = new Date(dateStr);
                return d.toLocaleString('en-US', {
                    year: 'numeric', month: 'short', day: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                    hour12: false
                });
            } catch(e) {
                return dateStr;
            }
        }
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        function truncateEmail(email) {
            if (!email) return 'Unknown';
            if (email.length > 25) {
                return email.substring(0, 22) + '...';
            }
            return email;
        }
    </script>
</body>
</html>
"@

    return $htmlTemplate
}
#endregion
#region Main Script Execution
Invoke-MessageTraceReport -CsvFilePath $CsvPath -OutputFilePath $OutputPath -AdminUPN $AdminUPN -SkipDlpLookup $SkipDlpLookup
# SIG # Begin signature block
# MIIF5QYJKoZIhvcNAQcCoIIF1jCCBdICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU76tCgK6iFZoFM6Nps3W4DITo
# OiigggNYMIIDVDCCAjygAwIBAgIQfH4v5Aowb69J4PkKDNS+8zANBgkqhkiG9w0B
# AQsFADBCMUAwPgYDVQQDDDdBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nQ29tcGxp
# YW5jZU1lc3NhZ2VUcmFjZUFuYWx5emVyMB4XDTI2MDQxNDE0MTgzNloXDTI3MDQx
# NDE0MzgzNlowQjFAMD4GA1UEAww3QWJkdWxsYWhabWFpbGlDb2RlU2lnbmluZ0Nv
# bXBsaWFuY2VNZXNzYWdlVHJhY2VBbmFseXplcjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMl6OC2+Ew7G4aIOmASzjRZJbBF7dj9up4zzP/rURXW4+md8
# kgBSuHnaWoY8HaorO4MT8QVmIIxNuak4nFlfyYc3Pp1Q32W+XV+j7hK6bfH/5To8
# XgVRX3/0vRWOJaf82aSaRDlG7MwqBj3cIxRKZTpydz5EMj6kXdw2h/As0oOwYIfu
# NdaFeTwh7YvgKUfUdabI1vSQry+FkwccrLnVvzBLajG83VuHS3t54RdrUd6V2Mci
# atB/Vnioaf8mUuXaAoX3vSEA3LsLbsz2Dal1/UmLNobMmtY/KGd6I2zi2AaMc436
# HPF8A5OWWbOJbRt7VFMIJsWVVffjuzQCOLRzGjkCAwEAAaNGMEQwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQ88zsyU15huWV4
# i/iDEt15MgRVQzANBgkqhkiG9w0BAQsFAAOCAQEAr8+uxBsyLT9u574CLOYL7ub0
# 73z4qsJ7pWujNW6rVaW+udwxph5Z/Z10Cl6/RjBZmlwOO3vlzRLgi0lhyiJk534M
# xCEY7Uj6KXkAJA3qKS5rzIrRMnns/YONuorBvjpIsnWo2Mt+H8A1xPU04bGCgZ2l
# SRDgN/xt1EkX7nxTDgancurE/RtU/10oW+piKmSQPwCBtDoZxlQla1lJIIt5D1RR
# k1Lh7/zAPEtgkUkfBTicDeEW7+lZL+7heAIoc2RdfOCaRkjEtNgnJ82uTgGn/xCe
# e84AuiLGFKajiri2ifqB/tSJU4YIKPee82lqzE1wDBpt2LSJxSosbDG8SYOHsTGC
# AfcwggHzAgEBMFYwQjFAMD4GA1UEAww3QWJkdWxsYWhabWFpbGlDb2RlU2lnbmlu
# Z0NvbXBsaWFuY2VNZXNzYWdlVHJhY2VBbmFseXplcgIQfH4v5Aowb69J4PkKDNS+
# 8zAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAjBgkqhkiG9w0BCQQxFgQUCDPoCn3PLlc0gnsDg8VERqFFh/owDQYJKoZIhvcN
# AQEBBQAEggEAOH4UH24FrwjPecA8O7OVIpmhuU+04xWAXAHu1CqHKSUMU6DS82OM
# zRq7Z0OFV10Kj3AsNVGiLtwoP3EcETHEuMJGvJiEes8D6fMo6o7YXgerGSg/wo5+
# 2OrSJCxO2aLE1k9u2Yb7kqdPm09DA93S0LbEMBvIIrM8AM3Q0hQK1jU5bI6zGgXP
# Zny5yiu3jukRM1pEyHGiy++4b54RCtPrKN/rabaH6vrhdF5LLFAKlczIkOLxWZdL
# 6yKU5UGYK6xmBk4Ltm3r5lEGhjaDjzMwGq5ql+E70CfSTkodAauzFvKzN/ahwxyN
# 437K4DIfebWBDtWhkNU2b5AvdvJrrBcuMQ==
# SIG # End signature block
