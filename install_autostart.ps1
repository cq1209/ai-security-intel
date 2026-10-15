# Register a boot-time task (runs before login, as SYSTEM).
# Must be run from an elevated PowerShell (Run as administrator).
$action = New-ScheduledTaskAction -Execute "D:\Codex\2026-09-26\new-chat\ai-security-intel\start_service.bat"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "AISecurityIntelService" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Write-Output "Registered boot-time task: AISecurityIntelService"
