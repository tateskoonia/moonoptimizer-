# ===============================================
# Windows 11 Safe Debloat Script (Fixed & Safe)
# ===============================================

# Sprawdź uprawnienia administratora
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Run this script as Administrator!" -ForegroundColor Red
    exit
}

Write-Host "`n[RESTORE] Creating system restore point..." -ForegroundColor Cyan

# Włącz przywracanie systemu jeśli wyłączone
Try {
    Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description 'Before_W11_Debloat' -RestorePointType 'MODIFY_SETTINGS'
    Write-Host "[RESTORE] Restore point created" -ForegroundColor Green
} Catch {
    Write-Host "[RESTORE] Failed to create restore point. Check System Restore settings." -ForegroundColor Yellow
}

# ===============================================
# 1. Disable Consumer Features
# ===============================================
Write-Host "[1/21] Disabling consumer features..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableConsumerFeatures -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Value 1 -Force

# ===============================================
# 2. Disable Telemetry
# ===============================================
Write-Host "[2/21] Disabling telemetry..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DisableDiagnosticDataViewer -Value 1 -Force

# Stop telemetry services safely (bez WaaSMedicSvc)
$services = "DiagTrack","dmwappushservice"
foreach ($s in $services) {
    if (Get-Service $s -ErrorAction SilentlyContinue) {
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        Set-Service -Name $s -StartupType Disabled
    }
}

# ===============================================
# 3. Disable Activity History
# ===============================================
Write-Host "[3/21] Disabling activity history..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableActivityFeed -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name PublishUserActivities -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name UploadUserActivities -Value 0 -Force

# ===============================================
# 4. Disable Widgets & Copilot
# ===============================================
Write-Host "[4/21] Disabling widgets and Copilot..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarWidgets -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name TurnOffWindowsCopilot -Value 1 -Force

# ===============================================
# 5. Disable Ads & Suggestions
# ===============================================
Write-Host "[5/21] Disabling ads & suggestions..." -ForegroundColor Cyan
$cdmPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
    "HKCU:\Software\Microsoft\Siuf\Rules",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
)
Set-ItemProperty -Path $cdmPaths[0] -Name "SubscribedContent-338387Enabled" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[0] -Name "SubscribedContent-338388Enabled" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[0] -Name "RotatingLockScreenEnabled" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[0] -Name "SystemPaneSuggestionsEnabled" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[1] -Name "NumberOfSIUFInPeriod" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[1] -Name "PeriodInNanoSeconds" -Value 0 -Force
Set-ItemProperty -Path $cdmPaths[2] -Name "ShowSyncProviderNotifications" -Value 0 -Force

# ===============================================
# 6. Remove OneDrive
# ===============================================
Write-Host "[6/21] Removing OneDrive..." -ForegroundColor Cyan
Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
$odPath64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
$odPath32 = "$env:SystemRoot\System32\OneDriveSetup.exe"
if (Test-Path $odPath64) { Start-Process $odPath64 -ArgumentList "/uninstall" -Wait } 
elseif (Test-Path $odPath32) { Start-Process $odPath32 -ArgumentList "/uninstall" -Wait }
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSyncNGSC -Value 1 -Force

# ===============================================
# 7. Remove Microsoft Bloat Apps (bez Paint, BT, NVIDIA)
# ===============================================
Write-Host "[7/21] Removing Microsoft bloat apps..." -ForegroundColor Cyan
$bloatApps = @(
    "Microsoft.XboxGamingOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.GetHelp",
    "Microsoft.3DBuilder",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MixedReality.Portal"
)
foreach ($app in $bloatApps) {
    Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

# ===============================================
# 8. Disable Cortana & Web Search
# ===============================================
Write-Host "[8/21] Disabling Cortana & Web Search..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Value 1 -Force

# ===============================================
# 9. Disable Background Apps
# ===============================================
Write-Host "[9/21] Disabling background apps..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name GlobalUserDisabled -Value 1 -Force

# ===============================================
# 10. Disable unnecessary services
# ===============================================
Write-Host "[10/21] Disabling unnecessary services..." -ForegroundColor Cyan
$servicesToDisable = "SysMain","WSearch","Fax","MapsBroker","RetailDemo","wisvc"
foreach ($s in $servicesToDisable) {
    if (Get-Service $s -ErrorAction SilentlyContinue) {
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        Set-Service -Name $s -StartupType Disabled
    }
}

# ===============================================
# 11. Disable Location
# ===============================================
Write-Host "[11/21] Disabling location services..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Value 1 -Force

# ===============================================
# 12. Disable Delivery Optimization
# ===============================================
Write-Host "[12/21] Disabling Delivery Optimization..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Value 0 -Force

# ===============================================
# 13. Disable Game Bar
# ===============================================
Write-Host "[13/21] Disabling Game Bar..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name AllowAutoGameMode -Value 0 -Force

# ===============================================
# 14. Disable Windows Tips
# ===============================================
Write-Host "[14/21] Disabling Windows Tips..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent-353694Enabled -Value 0 -Force

# ===============================================
# 15. Power Throttling
# ===============================================
Write-Host "[15/21] Disabling power throttling..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name PowerThrottlingOff -Value 1 -Force

# ===============================================
# 16. Disable Last Access Update (NTFS)
# ===============================================
Write-Host "[16/21] Optimizing NTFS..." -ForegroundColor Cyan
fsutil behavior set DisableLastAccess 1

# ===============================================
# 17. Disable Hibernation
# ===============================================
Write-Host "[17/21] Disabling hibernation..." -ForegroundColor Cyan
powercfg -h off

# ===============================================
# 18. Disable Error Reporting
# ===============================================
Write-Host "[18/21] Disabling error reporting..." -ForegroundColor Cyan
$errServices = "WerSvc"
foreach ($s in $errServices) {
    if (Get-Service $s -ErrorAction SilentlyContinue) {
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        Set-Service -Name $s -StartupType Disabled
    }
}

# ===============================================
# 19. Clean Temp Files
# ===============================================
Write-Host "[19/21] Cleaning temp files..." -ForegroundColor Cyan
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# ===============================================
# 20. Restart Explorer
# ===============================================
Write-Host "[20/21] Restarting Explorer..." -ForegroundColor Cyan
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Process explorer

Write-Host "`n[21/21] Debloat completed successfully!" -ForegroundColor Green
Write-Host "Restart recommended." -ForegroundColor Yellow
