# Copy the hidden startup script to the Startup folder (no admin required).
$src = "D:\Codex\2026-09-26\new-chat\ai-security-intel\start_service.vbs"
$startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
$dst = Join-Path $startup "start_service.vbs"

if (-not (Test-Path $startup)) {
    New-Item -ItemType Directory -Path $startup -Force | Out-Null
}

if ((Resolve-Path $src).Path -eq $dst) {
    Write-Output "Source and destination are the same file, skip."
} else {
    Copy-Item -Path $src -Destination $dst -Force
    Write-Output "Copied to Startup folder: $dst"
}
