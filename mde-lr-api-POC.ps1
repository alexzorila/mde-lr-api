<#
Title: PS Script to run Live Response Command agains multiple systems
Date: 2026-01-29
References:
- https://medium.com/@gberdzik/running-microsoft-defender-live-response-with-powershell-a7bb60b34995
- https://github.com/alexzorila/mde-run-arbitrary-commands

Setup (Local Admin):
Install-Module -Name Az.Accounts
#>

# Import module (Account with MS Defender rights)
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
Import-Module Az.Accounts

# Connect AzAccount
Update-AzConfig -EnableLoginByWam $false
Connect-AzAccount

# Store Auth data
$accessToken = Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com" -AsSecureString
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
$token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)

# Live Response Exec Variables
$MachineId = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
$ScriptName = "ps1"
$Args = "whoami"
$LiveResponseReason = "testing"

# Live Response API Args
$apiUrl = "https://api.securitycenter.microsoft.com/api/machines/$MachineId/runLiveResponse"
$headers = @{Authorization = "Bearer $token"; "Content-Type" = "application/json"}
$body = @{
    Commands = @(
        @{
            type   = "RunScript"
            params = @(
                @{
                    key   = "ScriptName"
                    value = $ScriptName
                },
                @{
                    key   = "Args"
                    value = $Args
                })
        })
    Comment = $LiveResponseReason
}
$jsonBody = $body | ConvertTo-Json

# Call API to Execute Response Action
$response = Invoke-RestMethod -Uri $apiUrl -Method POST -Headers $headers -Body $jsonBody

# Get Result
$MachineActionId = $response.id
$Url = "https://api.security.microsoft.com/api/machineactions/$MachineActionId/GetLiveResponseResultDownloadLink(index=0)"
$Headers = @{Authorization = "Bearer $token"; "Content-Type" = "application/json"}
$response = Invoke-RestMethod -Method GET -Uri $Url -Headers $Headers
$downloadUrl = $response.value -replace '&amp;', '&'
$blob = Invoke-RestMethod -Method GET -Uri $downloadUrl
$blob.script_output = ($blob.script_output -replace "`0","") -split "\r?\n" | Select-Object -Skip 1 | Out-String
$blob | Format-List -Property *
