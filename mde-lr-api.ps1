param(
    [Parameter(Position=0)]
    [ValidateSet('help','run','result')]
    [string]$Command = 'help',     # DEFAULT -> if no args, show Help

    # RUN parameters (you can pass or be prompted)
    [string]$MachineListPath = 'machines.txt',
    [string]$ScriptName = 'ps1',
    [string]$Args       = '',
    [string]$Reason     = 'live response via api',

    # Logs
    [string]$ActionLogPath  = '.\run-log.csv',     # RUN log: MachineId,ActionId,ScriptName,Args,Submitted,SubmitStatus,ApiStage,ErrorType,ErrorMessage,ErrorCategory,HttpStatusCode,HttpReason,HttpBodySnippet
    [string]$ResultsLogPath = '.\results-log.csv', # RESULTS log: MachineId,ActionId,Submitted,Status,ExitCode,ScriptName,Args,Retrieved,ScriptErrors,ScriptOutput,ApiStage,ErrorType,ErrorMessage,ErrorCategory,HttpStatusCode,HttpReason,HttpBodySnippet

    # Throttle (seconds) applied in both run and result loops
    [int]$ThrottleSeconds = 2,

    # Auth/session handling (merged)
    [switch]$Ephemeral     # Force fresh login, do not persist context, cleanup after run/result
)

# Snapshot of arguments passed inline at the top level (to detect if a param was explicitly provided)
$script:TopBound = $PSBoundParameters

# Script-scoped token (never written to terminal)
$script:DefenderToken = $null

# -------------------------
# Helper: current UTC timestamp in yyyy-MM-ddTHH:mm:ssZ
# -------------------------
function Get-NowStamp {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss'Z'")
}

# -------------------------
# Helper: Prompt for missing values (prompt iff NOT supplied inline), always show default in brackets
# -------------------------
function Prompt-IfMissing {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Prompt,
        [string]$Default = $null,
        [ValidateSet('Text','Path','Int')] [string]$Type = 'Text',
        [switch]$MustExist
    )

    # If this parameter was supplied inline, do not prompt—return the current value
    if ($script:TopBound -and $script:TopBound.ContainsKey($Name)) {
        try {
            return (Get-Variable -Name $Name -ValueOnly -ErrorAction Stop)
        } catch {
            return $Default
        }
    }

    # Not supplied inline -> prompt (always show default in brackets, including empty string)
    $suffixDefault = switch ($true) {
        { $null -eq $Default } { " [null]"; break }
        { $Default -eq '' }    { " ['']";   break }
        default                { " [$Default]" }
    }

    while ($true) {
        $answer = Read-Host "$Prompt$suffixDefault"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }

        switch ($Type) {
            'Int' {
                $out = 0
                if ([int]::TryParse($answer, [ref]$out)) { return $out }
                Write-Warning "Please enter a whole number."
                continue
            }
            'Path' {
                if ($MustExist -and -not (Test-Path -LiteralPath $answer)) {
                    Write-Warning "File not found: $answer"
                    continue
                }
                return $answer
            }
            default { return $answer }
        }
    }
}

# -------------------------
# Helper: Show chosen values and confirm
# -------------------------
function Show-SelectionConfirm {
    param(
        [Parameter(Mandatory)][string]$Operation,            # RUN
        [Parameter(Mandatory)][hashtable]$Values,            # keys in desired order
        [string]$DefaultAnswer = 'Y'
    )
    Write-Host ""
    Write-Host "Selected $Operation parameters:" -ForegroundColor Yellow
    foreach ($k in $Values.Keys) {
        $v = $Values[$k]
        if ($null -eq $v -or "$v" -eq '') { $v = "''" }
        Write-Host ("  {0}: {1}" -f $k, $v)
    }
    $prompt = "Proceed with $Operation? (Y/N)"
    if ($DefaultAnswer) { $prompt += " [$DefaultAnswer]" }
    $resp = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $DefaultAnswer }
    $ok = ($resp.Trim().ToUpper().StartsWith('Y'))
    if (-not $ok) { Write-Host "[$($Operation.ToLower())] Cancelled by user." -ForegroundColor DarkGray }
    return $ok
}

# -------------------------
# Help (short)
# -------------------------
function Show-Help {
    $n = if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { '.\mde-lr-api-2.ps1' }
@"

USAGE
  $n run     [-MachineListPath <path>] [-ScriptName <string>] [-Args <string>] [-Reason <text>] [-ThrottleSeconds <N>] [-Ephemeral]
  $n result  [-ActionLogPath <path>] [-ResultsLogPath <path>] [-ThrottleSeconds <N>] [-Ephemeral]

EXAMPLES
  1) Run live response command (interactive):
     $n run

  2) Retrieve command output:
     $n result

  3) Run live response command (non-interactive):
     $n run -MachineListPath .\machines.txt -ScriptName test.ps1

NOTES
  - You can use the "run" and "result" commands multiple times to refresh failed calls.
  - Ephemeral arg forces a fresh auth (no persistence), then cleans up context after the command completes.
  
"@ | Write-Host
}

# -------------------------
# Auth — reuse session when possible; or Ephemeral (fresh login + no persist)
# -------------------------
function Do-Auth {
    Import-Module Az.Accounts -ErrorAction Stop

    if ($Ephemeral) {
        # Ephemeral mode: process-scoped, no autosave, force interactive login, cleanup later
        try { Disable-AzContextAutosave -Scope Process | Out-Null } catch {}
        try { Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        Write-Host "[auth] Ephemeral: forcing interactive login (no persistence)..." -ForegroundColor Cyan
        try { Update-AzConfig -EnableLoginByWam $false | Out-Null } catch {}
        Connect-AzAccount | Out-Null
    }
    else {
        # Normal mode: allow autosave, try reuse; fall back to interactive
        try { Enable-AzContextAutosave -Scope CurrentUser | Out-Null } catch {}
        $ctx = $null
        try { $ctx = Get-AzContext -ErrorAction Stop } catch {}
        if ($ctx -and $ctx.Account) {
            try {
                $accessToken = Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com" -AsSecureString -ErrorAction Stop
                $ssPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
                $script:DefenderToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                Write-Host "[auth] Reusing existing Azure session." -ForegroundColor Green
                return
            } catch {
                # fall through to interactive
            }
        }
        Write-Host "[auth] No reusable session found; starting interactive login..." -ForegroundColor Cyan
        try { Update-AzConfig -EnableLoginByWam $false | Out-Null } catch {}
        Connect-AzAccount | Out-Null
    }

    # Acquire token post-login (kept in-memory only)
    $accessToken = Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com" -AsSecureString
    $ssPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
    $script:DefenderToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
    Write-Host "[auth] Authentication complete." -ForegroundColor Green
}

# -------------------------
# API helpers
# -------------------------
function Submit-LiveResponse {
    param(
        [Parameter(Mandatory=$true)][string]$Token,
        [Parameter(Mandatory=$true)][string]$MachineId,
        [Parameter(Mandatory=$true)][string]$ScriptName,
        [Parameter(Mandatory=$false)][string]$Args,
        [Parameter(Mandatory=$true)][string]$Reason
    )

    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    $apiUrl  = "https://api.securitycenter.microsoft.com/api/machines/$MachineId/runLiveResponse"

    # Build params: always include ScriptName; include Args only when non-empty
    $paramsList = @(
        @{ key = "ScriptName"; value = $ScriptName }
    )
    if (-not [string]::IsNullOrWhiteSpace($Args)) {
        $paramsList += @{ key = "Args"; value = $Args.Trim() }
    }

    $body = @{
        Commands = @(
            @{
                type   = "RunScript"
                params = $paramsList
            }
        )
        Comment = $Reason
    }

    $jsonBody = $body | ConvertTo-Json -Depth 6
    $response = Invoke-RestMethod -Uri $apiUrl -Method POST -Headers $headers -Body $jsonBody
    $response.id
}

function Get-LiveResponseResult {
    param(
        [Parameter(Mandatory=$true)][string]$Token,
        [Parameter(Mandatory=$true)][string]$ActionId
    )

    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    $url = "https://api.security.microsoft.com/api/machineactions/$ActionId/GetLiveResponseResultDownloadLink(index=0)"

    $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
	
	# HTML decode if needed
    Add-Type -AssemblyName System.Web
    $downloadUrl = $response.value
    do {
        $prev = $downloadUrl
        $downloadUrl = [System.Web.HttpUtility]::HtmlDecode($downloadUrl)
    } while ($downloadUrl -ne $prev)

    $blob = Invoke-RestMethod -Method GET -Uri $downloadUrl

    # Clean output: strip NULs and skip the transcript header line
    $cleanLines = (($blob.script_output -replace "`0","") -split "\r?\n") | Select-Object -Skip 1
    $cleanText  = $cleanLines -join "`r`n"

    # Compute status
    $status = if ($blob.exit_code -eq 0 -and [string]::IsNullOrWhiteSpace($blob.script_errors)) { 'Success' } else { 'Failed' }

    [pscustomobject]@{
        ActionId      = $ActionId
        Status        = $status
        ExitCode      = $blob.exit_code
        ScriptName    = $blob.script_name
        Retrieved     = Get-NowStamp
        ScriptErrors  = $blob.script_errors
        ScriptOutput  = $cleanText
    }
}

# -------------------------
# Error diagnostics (works on PS 5.1 and 7+)
# -------------------------
function Get-ErrorDiagnostics {
    param(
        [Parameter(Mandatory)] $ErrorRecord,
        [string]$ApiStage = ''
    )

    $ex = $ErrorRecord.Exception
    $errType     = $ex.GetType().FullName
    $errMessage  = $ex.Message
    $errCategory = "$($ErrorRecord.CategoryInfo.Category)"

    $httpStatus = $null
    $httpReason = $null
    $httpBody   = $null

    try {
        $resp = $null
        if ($ex.PSObject.Properties['Response']) { $resp = $ex.Response }

        if ($resp) {
            # PowerShell 7+: HttpResponseMessage
            if ($resp -is [System.Net.Http.HttpResponseMessage]) {
                try { $httpStatus = [int]$resp.StatusCode } catch {}
                try { $httpReason = [string]$resp.ReasonPhrase } catch {}
                try { $httpBody   = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() } catch {}
            }
            # Windows PowerShell 5.1: WebResponse/HttpWebResponse
            elseif ($resp -is [System.Net.WebResponse]) {
                try { $httpStatus = [int]$resp.StatusCode } catch {}
                try { $httpReason = [string]$resp.StatusDescription } catch {}
                try {
                    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
                    $httpBody = $sr.ReadToEnd()
                    $sr.Close()
                } catch {}
            }
            else {
                # Fallback: try common properties
                if ($resp.PSObject.Properties['StatusCode'])      { try { $httpStatus = [int]$resp.StatusCode } catch {} }
                if ($resp.PSObject.Properties['StatusDescription']){ try { $httpReason = [string]$resp.StatusDescription } catch {} }
                if ($resp.PSObject.Properties['Content'])         { try { $httpBody   = ($resp.Content | Out-String) } catch {} }
            }
        }
    } catch {}

    # Normalize / truncate response body
    if ($httpBody) {
        $httpBody = $httpBody -replace "`0",""
        $max = 2000
        if ($httpBody.Length -gt $max) { $httpBody = $httpBody.Substring(0,$max) }
    }

    [pscustomobject]@{
        ApiStage        = $ApiStage
        ErrorType       = $errType
        ErrorMessage    = $errMessage
        ErrorCategory   = $errCategory
        HttpStatusCode  = $httpStatus
        HttpReason      = $httpReason
        HttpBodySnippet = $httpBody
    }
}

# -------------------------
# Ensure/upgrade action log schema (split + case-insensitive check) — QUIET
# -------------------------
function Ensure-ActionLog {
    param([string]$Path)

    $columns = 'MachineId','ActionId','ScriptName','Args','Submitted','SubmitStatus','ApiStage','ErrorType','ErrorMessage','ErrorCategory','HttpStatusCode','HttpReason','HttpBodySnippet'

    if (-not (Test-Path -LiteralPath $Path)) {
        ($columns -join ',') | Out-File -LiteralPath $Path -Encoding utf8
        return
    }

    $header = Get-Content -LiteralPath $Path -TotalCount 1
    if (-not $header) {
        ($columns -join ',') | Out-File -LiteralPath $Path -Encoding utf8
        return
    }

    $headerColsLower = ($header -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() }
    $missing = @()
    foreach ($c in $columns) {
        if (-not ($headerColsLower -contains $c.ToLowerInvariant())) { $missing += $c }
    }

    if ($missing.Count -gt 0) {
        # Quiet upgrade (no stdout message)
        $rows = Import-Csv -LiteralPath $Path
        foreach ($r in $rows) {
            foreach ($c in $missing) {
                if (-not $r.PSObject.Properties[$c]) { $r | Add-Member -NotePropertyName $c -NotePropertyValue '' }
            }
        }
        $rows | Select-Object $columns |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        # No "upgraded" message to stdout
    }
}

# -------------------------
# Ensure/upgrade results log schema (split + case-insensitive check) — QUIET
# -------------------------
function Ensure-ResultsLog {
    param([string]$Path)

    $columns = 'MachineId','ActionId','Submitted','Status','ExitCode','ScriptName','Args','Retrieved','ScriptErrors','ScriptOutput','ApiStage','ErrorType','ErrorMessage','ErrorCategory','HttpStatusCode','HttpReason','HttpBodySnippet'

    if (-not (Test-Path -LiteralPath $Path)) {
        ($columns -join ',') | Out-File -LiteralPath $Path -Encoding utf8
        return
    }

    $header = Get-Content -LiteralPath $Path -TotalCount 1
    if (-not $header) {
        ($columns -join ',') | Out-File -LiteralPath $Path -Encoding utf8
        return
    }

    $headerColsLower = ($header -split ',') | ForEach-Object { $_.Trim().ToLowerInvariant() }
    $missing = @()
    foreach ($c in $columns) {
        if (-not ($headerColsLower -contains $c.ToLowerInvariant())) { $missing += $c }
    }

    if ($missing.Count -gt 0) {
        # Quiet upgrade (no stdout message)
        $rows = Import-Csv -LiteralPath $Path
        foreach ($r in $rows) {
            foreach ($c in $missing) {
                if (-not $r.PSObject.Properties[$c]) { $r | Add-Member -NotePropertyName $c -NotePropertyValue '' }
            }
        }
        $rows | Select-Object $columns |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        # No "upgraded" message to stdout
    }
}

# -------------------------
# Timestamp parsing helper for sorting/dedup
# -------------------------
function Get-ComparableTime {
    param(
        [string]$Retrieved,
        [string]$Submitted
    )
    $fmts = @("yyyy-MM-ddTHH:mm:ss'Z'","yyyy-MM-ddTHH:mm:ss")
    foreach ($s in @($Retrieved, $Submitted)) {
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        foreach ($f in $fmts) {
            try {
                $dt = [datetime]::ParseExact($s, $f, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                if ($dt) { return $dt.ToUniversalTime() }
            } catch {}
        }
        try {
            $dt = [datetime]::Parse($s)
            if ($dt) { return $dt.ToUniversalTime() }
        } catch {}
    }
    return [datetime]::MinValue
}

# -------------------------
# Cleanup helper for -Ephemeral
# -------------------------
function Cleanup-IfEphemeral {
    if ($Ephemeral) {
        try {
            Clear-AzContext -Force -ErrorAction SilentlyContinue | Out-Null
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        } catch {}
        $script:DefenderToken = $null
        Write-Host "[cleanup] Ephemeral: Azure context cleared." -ForegroundColor DarkGray
        Write-Host ""   # extra blank line after cleanup message
    }
}

# -------------------------
# Decide Silent vs Interactive for RUN only
# -------------------------
# NOTE: ActionLogPath intentionally excluded (never prompted; default or inline used)
# Silent mode requires only MachineListPath and ScriptName. Args, Reason, and ThrottleSeconds are optional and defaulted.
$runSilentRequired = @('MachineListPath','ScriptName')

# All required keys must be explicitly passed inline (present in the top-level bound set)
function Test-IsSilentRun {
    foreach ($k in $runSilentRequired) {
        if (-not ($script:TopBound -and $script:TopBound.ContainsKey($k))) { return $false }
    }
    return $true
}

$isSilentRun = ($Command -eq 'run') -and (Test-IsSilentRun)

# -------------------------
# Router
# -------------------------
switch ($Command) {
    'help' {
        Show-Help
        break
    }

    'run' {
        try {
            if (-not $isSilentRun) {
                # Prompt for any RUN inputs not supplied inline
                $MachineListPath = Prompt-IfMissing -Name 'MachineListPath' -Prompt 'MachineListPath' -Type 'Path' -MustExist -Default $MachineListPath
                $ScriptName      = Prompt-IfMissing -Name 'ScriptName'      -Prompt 'ScriptName' -Default $ScriptName
                $Args            = Prompt-IfMissing -Name 'Args'            -Prompt 'Args' -Default $Args
                $Reason          = Prompt-IfMissing -Name 'Reason'          -Prompt 'Reason' -Default $Reason
                $ThrottleSeconds = Prompt-IfMissing -Name 'ThrottleSeconds' -Prompt 'Throttle (seconds)' -Default $ThrottleSeconds -Type 'Int'
                # Do NOT prompt for ActionLogPath — use inline or default

                # Show selection + confirm — ActionLogPath hidden from summary
                $confirmValues = [ordered]@{
                    Operation       = 'RUN'
                    MachineListPath = $MachineListPath
                    ScriptName      = $ScriptName
                    Args            = $Args
                    Reason          = $Reason
                    ThrottleSeconds = $ThrottleSeconds
                    Ephemeral       = [bool]$Ephemeral
                }
                if (-not (Show-SelectionConfirm -Operation 'RUN' -Values $confirmValues -DefaultAnswer 'Y')) { return }
            }

            # Load raw lines (IDs only; no comments or names)
            $raw = Get-Content -LiteralPath $MachineListPath -ErrorAction Stop |
                   ForEach-Object { $_.Trim() } |
                   Where-Object { $_ -ne '' }

            # Validate: only 40-hex IDs allowed
            $invalid = $raw | Where-Object { $_ -notmatch '^[A-Fa-f0-9]{40}$' } | Select-Object -Unique
            if ($invalid) {
                throw "Invalid MachineId entries (must be exactly 40 hex chars, no names/comments):`n$($invalid -join "`n")"
            }

            $machineIds = $raw | Select-Object -Unique
            if (-not $machineIds -or $machineIds.Count -eq 0) { throw "No valid machine IDs found in: $MachineListPath" }

            # --------- Eligibility filter for re-runs ----------
            # If the action log exists, only submit for machines whose most recent entry shows
            # SubmitStatus='SubmitFailed' AND missing/empty ActionId. Machines with no history are included.
            $eligibleIds = $machineIds

            if (Test-Path -LiteralPath $ActionLogPath) {
                $existing = Import-Csv -LiteralPath $ActionLogPath -ErrorAction SilentlyContinue
                if (-not $existing) { $existing = @() }

                if ($existing.Count -gt 0) {
                    # Build latest row per MachineId by Submitted timestamp
                    $latestByMid = @{}
                    foreach ($row in $existing) {
                        if (-not $row.MachineId) { continue }
                        $t = Get-ComparableTime -Retrieved $null -Submitted $row.Submitted
                        if (-not $latestByMid.ContainsKey($row.MachineId)) {
                            $latestByMid[$row.MachineId] = @{ Time = $t; Row = $row }
                        } else {
                            if ($t -ge $latestByMid[$row.MachineId].Time) {
                                $latestByMid[$row.MachineId] = @{ Time = $t; Row = $row }
                            }
                        }
                    }

                    $eligibleIds = @()
                    foreach ($mid in $machineIds) {
                        if (-not $latestByMid.ContainsKey($mid)) {
                            # No prior history -> include
                            $eligibleIds += $mid
                        } else {
                            $last = $latestByMid[$mid].Row
                            $noAid = [string]::IsNullOrWhiteSpace($last.ActionId)
                            if ($last.SubmitStatus -eq 'SubmitFailed' -and $noAid) {
                                $eligibleIds += $mid
                            } else {
                                # Intentionally silent for skipped machines
                            }
                        }
                    }
                }
            }

            if (-not $eligibleIds -or $eligibleIds.Count -eq 0) {
                Write-Host "[run] Nothing to submit: no eligible machine IDs (only 'SubmitFailed' + missing ActionId are retried)." -ForegroundColor DarkGray
                return
            }

            Do-Auth
            Ensure-ActionLog -Path $ActionLogPath   # ensure file exists/header present

            $results = [System.Collections.Generic.List[object]]::new()

            # Buffer new action rows; we'll merge + de-dup once after the loop
            $actionNewRows  = [System.Collections.Generic.List[object]]::new()
            $actionColumns  = 'MachineId','ActionId','ScriptName','Args','Submitted','SubmitStatus','ApiStage','ErrorType','ErrorMessage','ErrorCategory','HttpStatusCode','HttpReason','HttpBodySnippet'

            foreach ($mid in $eligibleIds) {
                Write-Host "[run] Submitting to $mid ..." -ForegroundColor Cyan
                try {
                    $actionId = Submit-LiveResponse -Token $script:DefenderToken -MachineId $mid -ScriptName $ScriptName -Args $Args -Reason $Reason
                    if (-not $actionId) { throw "No ActionId returned." }

                    $now = Get-NowStamp
                    $record = [pscustomobject]@{
                        MachineId       = $mid
                        ActionId        = $actionId
                        ScriptName      = $ScriptName
                        Args            = $Args
                        Submitted       = $now
                        SubmitStatus    = 'Submitted'
                        ApiStage        = ''
                        ErrorType       = ''
                        ErrorMessage    = ''
                        ErrorCategory   = ''
                        HttpStatusCode  = $null
                        HttpReason      = ''
                        HttpBodySnippet = ''
                    }
                    # buffer; do not write yet
                    $actionNewRows.Add($record) | Out-Null

                    Write-Host "[run] $mid -> ActionId: $actionId" -ForegroundColor Green
                    $results.Add([pscustomobject]@{ MachineId=$mid; ActionId=$actionId; Submitted=$now })
                }
                catch {
                    $now = Get-NowStamp
                    $diag = Get-ErrorDiagnostics -ErrorRecord $_ -ApiStage 'SubmitLiveResponse'
                    Write-Warning "[run] $mid submit failed: $($diag.ErrorMessage)"

                    $record = [pscustomobject]@{
                        MachineId       = $mid
                        ActionId        = $null
                        ScriptName      = $ScriptName
                        Args            = $Args
                        Submitted       = $now
                        SubmitStatus    = 'SubmitFailed'
                        ApiStage        = $diag.ApiStage
                        ErrorType       = $diag.ErrorType
                        ErrorMessage    = $diag.ErrorMessage
                        ErrorCategory   = $diag.ErrorCategory
                        HttpStatusCode  = $diag.HttpStatusCode
                        HttpReason      = $diag.HttpReason
                        HttpBodySnippet = $diag.HttpBodySnippet
                    }
                    # buffer; do not write yet
                    $actionNewRows.Add($record) | Out-Null

                    # Keep the in-terminal summary object consistent
                    $results.Add([pscustomobject]@{ MachineId=$mid; ActionId=$null; Error=$_.Exception.Message; Submitted=$now })
                }

                # Throttle between RUN submissions
                if ($ThrottleSeconds -gt 0) { Start-Sleep -Seconds $ThrottleSeconds }
            }

            # -------------------------
            # Merge + De-dup run log
            # Keep ONLY the latest SubmitFailed per MachineId; retain all 'Submitted'
            # -------------------------
            $existingRows = @()
            if (Test-Path -LiteralPath $ActionLogPath) {
                $existingRows = Import-Csv -LiteralPath $ActionLogPath -ErrorAction SilentlyContinue
                if (-not $existingRows) { $existingRows = @() }
            }

            $combined = @()
            if ($existingRows) { $combined += $existingRows }
            if ($actionNewRows) { $combined += $actionNewRows }

            $latestFailedByMid = @{}
            $nonFailedRows = New-Object System.Collections.Generic.List[object]

            foreach ($row in $combined) {
                if ($row.SubmitStatus -eq 'SubmitFailed' -and $row.MachineId) {
                    $t = Get-ComparableTime -Retrieved $null -Submitted $row.Submitted
                    if (-not $latestFailedByMid.ContainsKey($row.MachineId)) {
                        $latestFailedByMid[$row.MachineId] = @{ Time = $t; Row = $row }
                    } else {
                        if ($t -ge $latestFailedByMid[$row.MachineId].Time) {
                            $latestFailedByMid[$row.MachineId] = @{ Time = $t; Row = $row }
                        }
                    }
                } else {
                    $nonFailedRows.Add($row) | Out-Null
                }
            }

            $dedupedRows = @()
            $dedupedRows += $nonFailedRows
            $dedupedRows += ($latestFailedByMid.Values | ForEach-Object { $_.Row })

            # Sort deterministically
            $sortedRows = $dedupedRows | Sort-Object `
                -Property @{ Expression = { Get-ComparableTime -Retrieved $null -Submitted $_.Submitted }; Ascending = $true }, `
                          @{ Expression = 'MachineId'; Ascending = $true }, `
                          @{ Expression = 'ActionId'; Ascending = $true }

            # Overwrite the file with the de-duplicated set
            $sortedRows | Select-Object $actionColumns |
                Export-Csv -LiteralPath $ActionLogPath -NoTypeInformation -Encoding UTF8

            # Return the rows we processed this run (not the whole file)
            $results
        }
        finally {
            Cleanup-IfEphemeral
        }
        break
    }

    'result' {
        try {
            # RESULT path: no prompts; use provided values or defaults as-is
            if (-not (Test-Path -LiteralPath $ActionLogPath)) { throw "Action log not found: $ActionLogPath" }

            Do-Auth
            Ensure-ActionLog  -Path $ActionLogPath   # upgrade if an old schema (quiet)
            Ensure-ResultsLog -Path $ResultsLogPath  # ensure header / upgrade to include Args + error columns (quiet)

            # Read mapping from action-log (ActionId -> {MachineId,Submitted,ScriptName,Args})
            $entries = Import-Csv -LiteralPath $ActionLogPath
            if (-not $entries) { throw "No entries in action log: $ActionLogPath" }

            $aidInfo = @{}
            foreach ($e in $entries) {
                if ($e.ActionId) {
                    $aidInfo[$e.ActionId] = [pscustomobject]@{
                        MachineId  = $e.MachineId
                        Submitted  = $e.Submitted
                        ScriptName = $e.ScriptName
                        Args       = $e.Args
                    }
                }
            }

            $actionIds = $aidInfo.Keys
            if (-not $actionIds -or $actionIds.Count -eq 0) { throw "No ActionIds found in log: $ActionLogPath" }

            # --- Idempotent behavior prep: read existing results and decide targets
            $existingRows = @()
            if (Test-Path -LiteralPath $ResultsLogPath) {
                $existingRows = Import-Csv -LiteralPath $ResultsLogPath
            }

            # ActionIds that already have a fetched result (Success OR Failed) should be skipped.
            # 'FetchFailed' rows indicate previous retrieval failures and are eligible for retry.
            $fetchedSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($r in $existingRows) {
                if ($r.ActionId -and ($r.Status -eq 'Success' -or $r.Status -eq 'Failed')) {
                    [void]$fetchedSet.Add($r.ActionId)
                }
            }

            $targetActionIds = @()
            foreach ($aid in $actionIds) {
                if (-not $fetchedSet.Contains($aid)) {
                    $targetActionIds += $aid
                }
            }

            if ($targetActionIds.Count -eq 0) {
                Write-Host "[result] Nothing to do: all action IDs already have fetched results (Success/Failed)." -ForegroundColor DarkGray
                return
            } else {
                Write-Host "[result] Will attempt $($targetActionIds.Count) ActionId(s) (no prior result or prior FetchFailed)..." -ForegroundColor Cyan
            }

            # Process target ActionIds
            $newRows = [System.Collections.Generic.List[object]]::new()
            $resultsColumns = 'MachineId','ActionId','Submitted','Status','ExitCode','ScriptName','Args','Retrieved','ScriptErrors','ScriptOutput','ApiStage','ErrorType','ErrorMessage','ErrorCategory','HttpStatusCode','HttpReason','HttpBodySnippet'

            foreach ($aid in $targetActionIds) {
                $machineId  = $aidInfo[$aid].MachineId
                $submitted  = $aidInfo[$aid].Submitted
                $argsUsed   = $aidInfo[$aid].Args
                Write-Host "[result] Fetching result for $aid (MachineId: $machineId) ..." -ForegroundColor Cyan
                try {
                    $res = Get-LiveResponseResult -Token $script:DefenderToken -ActionId $aid

                    # Success: remove any prior FetchFailed rows for this ActionId
                    if ($existingRows) {
                        $existingRows = $existingRows | Where-Object { $_.ActionId -ne $aid -or $_.Status -ne 'FetchFailed' }
                    }

                    $newRows.Add([pscustomobject]@{
                        MachineId      = $machineId
                        ActionId       = $res.ActionId
                        Submitted      = $submitted
                        Status         = $res.Status                 # Success | Failed (script failure)
                        ExitCode       = $res.ExitCode
                        ScriptName     = $res.ScriptName
                        Args           = $argsUsed
                        Retrieved      = $res.Retrieved
                        ScriptErrors   = $res.ScriptErrors
                        ScriptOutput   = $res.ScriptOutput
                        ApiStage       = ''                          # empty -> fetch success
                        ErrorType      = ''
                        ErrorMessage   = ''
                        ErrorCategory  = ''
                        HttpStatusCode = $null
                        HttpReason     = ''
                        HttpBodySnippet= ''
                    })
                }
                catch {
                    $diag = Get-ErrorDiagnostics -ErrorRecord $_ -ApiStage 'GetLiveResponseResult'
                    Write-Warning "[result] $aid fetch failed: $($diag.ErrorMessage)"

                    $newRows.Add([pscustomobject]@{
                        MachineId      = $machineId
                        ActionId       = $aid
                        Submitted      = $submitted
                        Status         = 'FetchFailed'
                        ExitCode       = $null
                        ScriptName     = $null
                        Args           = $argsUsed
                        Retrieved      = Get-NowStamp
                        ScriptErrors   = $_.Exception.Message
                        ScriptOutput   = $null
                        ApiStage       = $diag.ApiStage
                        ErrorType      = $diag.ErrorType
                        ErrorMessage   = $diag.ErrorMessage
                        ErrorCategory  = $diag.ErrorCategory
                        HttpStatusCode = $diag.HttpStatusCode
                        HttpReason     = $diag.HttpReason
                        HttpBodySnippet= $diag.HttpBodySnippet
                    })
                }

                # Throttle between RESULT fetches
                if ($ThrottleSeconds -gt 0) { Start-Sleep -Seconds $ThrottleSeconds }
            }

            # Merge and deduplicate FetchFailed rows (keep only most recent per ActionId)
            $finalRows = @()
            if ($existingRows) { $finalRows += $existingRows }
            if ($newRows)      { $finalRows += $newRows }

            # Build dictionary of most recent FetchFailed per ActionId
            $latestFetchFailed = @{}
            $nonFailedRows = New-Object System.Collections.Generic.List[object]

            foreach ($row in $finalRows) {
                if ($row.Status -eq 'FetchFailed' -and $row.ActionId) {
                    $t = Get-ComparableTime -Retrieved $row.Retrieved -Submitted $row.Submitted
                    if (-not $latestFetchFailed.ContainsKey($row.ActionId)) {
                        $latestFetchFailed[$row.ActionId] = @{ Time = $t; Row = $row }
                    } else {
                        if ($t -ge $latestFetchFailed[$row.ActionId].Time) {
                            $latestFetchFailed[$row.ActionId] = @{ Time = $t; Row = $row }
                        }
                    }
                } else {
                    $nonFailedRows.Add($row) | Out-Null
                }
            }

            $dedupedRows = @()
            $dedupedRows += $nonFailedRows
            $dedupedRows += ($latestFetchFailed.Values | ForEach-Object { $_.Row })

            # Sort by Submitted (then ActionId)
            $sortedRows = $dedupedRows | Sort-Object `
                -Property @{ Expression = { Get-ComparableTime -Retrieved $_.Retrieved -Submitted $_.Submitted }; Ascending = $true }, `
                          @{ Expression = 'ActionId'; Ascending = $true }

            # Always write full file to ensure determinism and consistent column order
            $sortedRows | Select-Object $resultsColumns |
                Export-Csv -LiteralPath $ResultsLogPath -NoTypeInformation -Encoding UTF8

            # Return the rows we processed this run (not the whole file)
            $newRows | Format-Table -Property MachineId, ActionId, Submitted, Status, Retrieved
        }
        finally {
            Cleanup-IfEphemeral
        }
        break
    }
}
