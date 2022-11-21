### Powershell script to collect event log with selected headers,  with removal of unnecessary lines and/or headers,
### together with the conversion from evtx to csv

# Get Path to input event logs
$input_path = Read-Host -Prompt "Give Full Path of Event Logs Location to be Extracted"

# Get Path to output csv file to
$output_path = Read-Host -Prompt "Give Full Path of to output CSV File together with the filename `n(Example, C:\Users\User1\Desktop\Output.csv)"

# Retrieval of Security Logs
$logs = Get-WinEvent -Path $input_path


# Selection of Content based on object headers from Security Logs
$selected_logs = $logs | Select-Object -Property TimeCreated, Id, ProviderName, LogName, ProcessId, ThreadId, MachineName, LevelDisplayName, OpcodeDisplayName, TaskDisplayName, Message

# Selection of RDP Related Event ID Logs
$filtered_logs = $selected_logs | Where-Object -Property Id -eq -Value 4688


# Ouput of filtered log as csv to path specified by user
$filtered_logs | Export-CSV -Path $output_path -NoClobber -Force -NoTypeInformation

