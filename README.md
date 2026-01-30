# MDE Live Response: Run script against multiple systems
Powershell script enabling Microsoft Defender Live Response use against multiple machines via API.
* Adds functionality where a script from MDE Live Response library can be executed against a list of Device IDs.
* Commands are called via API with authentication via Connect-AzAccount.

## Setup
```
Install-Module -Name Az.Accounts
```

## Usage
* `machines.txt` is a text file to be populated with a list of Device IDs separated by new line.
* `run` command initiates a response action against the list of machines. Output stored in `.\run-log.csv`.
* `result` command retrieves the output of the command. Output is stored in `.\results-log.csv`.
* Run either command multiple times to update the stored output incrementally.
* Successful API calls / results are kept. Only failed fetch runs again.
  
```
> .\mde-lr-api.ps1

USAGE
  mde-lr-api.ps1 run     [-MachineListPath <path>] [-ScriptName <string>] [-Args <string>] [-Reason <text>] [-ThrottleSeconds <N>] [-Ephemeral]
  mde-lr-api.ps1 result  [-ActionLogPath <path>] [-ResultsLogPath <path>] [-ThrottleSeconds <N>] [-Ephemeral]

EXAMPLES
  1) Run live response command (interactive):
     mde-lr-api.ps1 run

  2) Retrieve command output:
     mde-lr-api.ps1 result

  3) Run live response command (non-interactive):
     mde-lr-api.ps1 run -MachineListPath .\machines.txt -ScriptName ps1 -Args "whoami" -Reason "test" -ThrottleSeconds 2

NOTES
  - You can use the "run" and "result" commands multiple times to refresh failed calls.
  - Ephemeral arg forces a fresh auth (no persistence), then cleans up context after the command completes.
```
## References
* MDE LR with PowerShell: https://medium.com/@gberdzik/running-microsoft-defender-live-response-with-powershell-a7bb60b34995
* MDE LR Arbitrary Cmd: https://github.com/alexzorila/mde-run-arbitrary-commands
* Graph Auth: https://learn.microsoft.com/en-us/graph/auth-v2-user
* MDE API Docs: https://learn.microsoft.com/en-us/defender-endpoint/api/get-live-response-result 
* M365 Copilot: https://m365.cloud.microsoft/chat
