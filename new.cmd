@echo off
title Windows 11 Ultimate Safe Optimization
color 07

:: ==========================
:: ADMIN CHECK
:: ==========================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo         .--.
    echo        ^| o_o^|
    echo        ^| :_/^|
    echo       //   \ \
    echo      ^(      ^) ^)
    echo      /'\_   _/'\
    echo      \___^)^(___/
    echo.
    echo Run as Administrator
    pause
    exit /b
)

:: ==========================
:: PINGWIN
:: ==========================
echo         .--.
echo        ^| o_o^|
echo        ^| :_/^|
echo       //   \ \
echo      ^(      ^) ^)
echo      /'\_   _/'\
echo      \___^)^(___/
echo.

:: ==========================
:: 1/31 Disable consumer features
:: ==========================
echo [1/31] Disable consumer features
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >nul

:: ==========================
:: 2/31 Disable telemetry
:: ==========================
echo [2/31] Disable telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DisableDiagnosticDataViewer /t REG_DWORD /d 1 /f >nul
for %%S in ("DiagTrack" "dmwappushservice") do (
    sc query %%~S >nul 2>&1
    if not errorlevel 1 (
        sc stop %%~S >nul 2>&1
        sc config %%~S start= disabled >nul 2>&1
    )
)

:: ==========================
:: 3/31 Disable activity history
:: ==========================
echo [3/31] Disable activity history
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f >nul

:: ==========================
:: 4/31 Disable widgets and Copilot
:: ==========================
echo [4/31] Disable widgets and Copilot
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarWidgets /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul

:: ==========================
:: 5/31 Disable ads and suggestions
:: ==========================
echo [5/31] Disable ads and suggestions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f

:: ==========================
:: 6/31 Remove OneDrive
:: ==========================
echo [6/31] Remove OneDrive
taskkill /f /im OneDrive.exe >nul 2>&1
if exist "%SystemRoot%\SysWOW64\OneDriveSetup.exe" (
    "%SystemRoot%\SysWOW64\OneDriveSetup.exe" /uninstall >nul 2>&1
) else (
    "%SystemRoot%\System32\OneDriveSetup.exe" /uninstall >nul 2>&1
)
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

:: ==========================
:: 7/31 Remove UWP apps
:: ==========================
echo [7/31] Remove UWP apps
powershell -NoProfile -Command "Get-AppxPackage -AllUsers -Name 'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.MicrosoftOfficeHub','Microsoft.People','Microsoft.SkypeApp','Microsoft.YourPhone','Microsoft.ZuneMusic','Microsoft.ZuneVideo' | Remove-AppxPackage -ErrorAction SilentlyContinue"

:: ==========================
:: 8/31 Disable Cortana and Web Search
:: ==========================
echo [8/31] Disable Cortana and Web Search
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
taskkill /f /im SearchUI.exe >nul 2>&1

:: ==========================
:: 9/31 Disable background apps
:: ==========================
echo [9/31] Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

:: ==========================
:: 10/31 Disable unnecessary services
:: ==========================
echo [10/31] Disable unnecessary services
for %%s in ("SysMain" "WSearch" "Fax" "MapsBroker" "RetailDemo" "wisvc") do (
    sc query %%~s >nul 2>&1
    if not errorlevel 1 (
        sc stop %%~s >nul 2>&1
        sc config %%~s start= disabled >nul 2>&1
    )
)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v Start /t REG_DWORD /d 4 /f

:: ==========================
:: 11/31 Disable location services
:: ==========================
echo [11/31] Disable location services
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f

:: ==========================
:: 12/31 Disable telemetry scheduled tasks
:: ==========================
echo [12/31] Disable telemetry scheduled tasks
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul 2>&1

:: ==========================
:: 13/31 Disable Delivery Optimization
:: ==========================
echo [13/31] Disable Delivery Optimization
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f

:: ==========================
:: 14/31 Disable Edge preload
:: ==========================
echo [14/31] Disable Edge preload
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v AllowTabPreloading /t REG_DWORD /d 0 /f

:: ==========================
:: 15/31 Disable Game DVR and Game Bar
:: ==========================
echo [15/31] Disable Game DVR and Game Bar
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f

:: ==========================
:: 16/31 Disable Windows Tips
:: ==========================
echo [16/31] Disable Windows Tips
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f

:: ==========================
:: 17/31 Power throttling optimizations
:: ==========================
echo [17/31] Power throttling optimizations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f

:: ==========================
:: 18/31 NTFS optimization
:: ==========================
echo [18/31] NTFS optimization
fsutil behavior set DisableLastAccess 1 >nul

:: ==========================
:: 19/31 Disable hibernation
:: ==========================
echo [19/31] Disable hibernation
powercfg -h off >nul

:: ==========================
:: 20/31 Disable error reporting
:: ==========================
echo [20/31] Disable error reporting
for %%S in ("WerSvc") do (
    sc query %%~S >nul 2>&1
    if not errorlevel 1 (
        sc stop %%~S >nul 2>&1
        sc config %%~S start= disabled >nul 2>&1
    )
)

:: ==========================
:: 21/31 Disable reserved storage
:: ==========================
echo [21/31] Disable reserved storage
dism /online /set-reservedstorage-state /state:disabled >nul

:: ==========================
:: 22/31 Clean temporary files
:: ==========================
echo [22/31] Clean temporary files
del /f /s /q "%TEMP%\*" >nul 2>&1
del /f /s /q "C:\Windows\Temp\*" >nul 2>&1

:: ==========================
:: 23/31 Network optimizations
:: ==========================
echo [23/31] Network optimizations
ipconfig /flushdns >nul
netsh int tcp set global autotuninglevel=normal >nul
netsh int tcp set global ecncapability=disabled >nul

:: ==========================
:: 24/31 Disable WPBT
:: ==========================
echo [24/31] Disable WPBT
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f

:: ==========================
:: 25/31 Disable Cortana indexing
:: ==========================
echo [25/31] Disable Cortana indexing
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableIndexingEncryptedStoresOrItems /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v PreventIndexingOutlook /t REG_DWORD /d 1 /f

:: ==========================
:: 26/31 Close all running UWP apps
:: ==========================
echo [26/31] Close all running UWP apps
powershell -NoProfile -Command "Get-Process | Where-Object {$_.Path -like '*WindowsApps*'} | Stop-Process -Force -ErrorAction SilentlyContinue"

:: ==========================
:: 27/31 Restart Explorer
:: ==========================
echo [27/31] Restart Explorer
taskkill /f /im explorer.exe >nul
timeout /t 2 >nul
start explorer.exe

:: ==========================
:: 28-31 Final cleanup & messages
:: ==========================
cls
echo         .--.
echo        ^| o_o^|
echo        ^| :_/^|
echo       //   \ \
echo      ^(      ^) ^)
echo      /'\_   _/'\
echo      \___^)^(___/
echo.
echo [29/31] All safe optimizations applied
echo [30/31] System optimized for responsiveness and low background load
echo [31/31] Restart recommended
pause
exit /b
