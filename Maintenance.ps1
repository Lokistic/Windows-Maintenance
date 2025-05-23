# ==============================================
#   Ultimate Windows Maintenance Script by Loki
#           youtube.com/Lokistic
# ==============================================
# Original environment: Windows 11, Version 23H2 (OS Build 22631.5039)
# The script should properly work on any windows version, relying on our automatic GUID retrieval.
# If you run into any issues, either don't run the power tweaks, or manually find the correct GUIDs using - 
# PowerSettingsExplorer for example, I've made it easy for you to import them manually.

# Global variables
$global:RestartRequired = $false
$global:IpResetFailedDetails = $null

function Ensure-Admin {
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $IsAdmin) {
        Write-Host "[!] Script requires admin privileges. Relaunching..." -ForegroundColor Yellow
        Start-Process powershell -Verb runAs -ArgumentList ("-ExecutionPolicy Bypass -File `"$PSCommandPath`"")
        exit
    }

    Log "Script running with administrator privileges."
}

# Insane visual line
function Divider($text = "") {
    Write-Host ""
    Write-Host "========== $text ==========" -ForegroundColor Cyan
}

# Basic "animation" dot loading
function StepAnimation($message) {
    Write-Host "$message" -NoNewline
    1..3 | ForEach-Object { Start-Sleep -Milliseconds 300; Write-Host "." -NoNewline }
    Write-Host ""
}

# Logging (only shows in terminal; expand if needed)
function Log($message) {
    Write-Host "[+] $message" -ForegroundColor Green
}

# ////// Maintenance Functions \\\\\\ #

function Clear-TempFiles {
    Divider "Clearing Temp Files"
    StepAnimation "Cleaning system TEMP"
    Get-ChildItem -Path "C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    StepAnimation "Cleaning user TEMP"
    Get-ChildItem -Path "$env:TEMP" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    StepAnimation "Cleaning prefetch"
    Get-ChildItem -Path "C:\Windows\Prefetch" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Log "Temp files and cache cleared."
}

function Run-CleanMgr {
    Divider "Running Disk Cleanup (cleanmgr)"
    StepAnimation "Configuring common Disk Cleanup categories"

    $sageNumber = 1
    $sageFlagsKey = "StateFlags" + $sageNumber.ToString("0000") # Forms "StateFlags0001"

    # We will only attempt to set flags for categories that are commonly present.
    $safeCategories = @(
        "Temporary Files",
        "Recycle Bin",
        "Downloaded Program Files",
        "Delivery Optimization Files"
    )

    $volumeCachesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

    foreach ($category in $safeCategories) {
        $categoryPath = Join-Path -Path $volumeCachesPath -ChildPath $category
        
        # Only attempt to set the flag if the category's registry key exists.
        # I tried creating the missing keys, but cleanmgr could have ignored them.. too much hassle.. DISM will do the work anyways - Loki
        if (Test-Path $categoryPath) {
            Set-ItemProperty -LiteralPath $categoryPath -Name $sageFlagsKey -Value 2 -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "    [!] Disk Cleanup category '$category' not found or not registered for cleanup. Skipping." -ForegroundColor DarkYellow
        }
    }
    Log "Disk Cleanup categories configured."

    StepAnimation "Executing Disk Cleanup (may briefly flash a window)"
    # Note: cleanmgr.exe is a GUI application. While /sagerun *should* be silent,
    # Windows may (AND WILL) still display a progress window or flash it.
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:$sageNumber" -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
    Log "Disk Cleanup completed."
}

function Reset-NetworkStack {
    Divider "Resetting Network Stack"
    StepAnimation "Flushing DNS"
    ipconfig /flushdns | Out-Null

    StepAnimation "Resetting Winsock"
    netsh winsock reset *> $null
    $winsockExitCode = $LASTEXITCODE

    if ($winsockExitCode -eq 0) {
        Log "Winsock Catalog reset successfully."
        $global:RestartRequired = $true
    } else {
        Write-Host "[!] Winsock Catalog reset failed (exit code: $winsockExitCode)." -ForegroundColor Red
        Write-Host "    Consider restarting or manually running 'netsh winsock reset' if issues persist." -ForegroundColor DarkYellow
    }

    StepAnimation "Resetting IP Interface"
    $ipResetOutput = netsh int ip reset 2>&1
    $ipResetExitCode = $LASTEXITCODE

    if ($ipResetExitCode -eq 0) {
        Log "IP Interface reset successfully."
        $global:RestartRequired = $true
    } else {
        $global:IpResetFailedDetails = $ipResetOutput | Where-Object { $_ -match "failed\." }
        Write-Host "[!] IP Interface reset completed with some components failing. Details will follow." -ForegroundColor Yellow
        $global:RestartRequired = $true
    }

    Log "Network stack reset process initiated."
}

function Repair-System {
    Divider "System Repair & Component Cleanup"
    $sfcLog = "$env:TEMP\sfc_log.txt"
    $dismLog = "$env:TEMP\dism_log.txt"
    $dismCleanupLog = "$env:TEMP\dism_cleanup_log.txt"

    StepAnimation "Running SFC (logging to $sfcLog)"
    sfc /scannow | Out-File -FilePath $sfcLog -Encoding UTF8 -Force

    StepAnimation "Running DISM (logging to $dismLog)"
    DISM /Online /Cleanup-Image /RestoreHealth | Out-File -FilePath $dismLog -Encoding UTF8 -Force

    StepAnimation "Clearing Windows Update Cache (DISM Component Cleanup - logging to $dismCleanupLog)"
    DISM /Online /Cleanup-Image /StartComponentCleanup | Out-File -FilePath $dismCleanupLog -Encoding UTF8 -Force
    Log "Windows Update Cache cleared via DISM."

    Log "System check, repair, and update cache cleanup completed. Check logs for details."
}

function Optimize-Drives {
    Divider "Optimizing Drives"
    StepAnimation "Running drive optimization for C:\"

    $OriginalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    # Handles TRIM for SSDs and defrag for HDDs
    Optimize-Volume -DriveLetter C

    $ProgressPreference = $OriginalProgressPreference

    Log "Drive optimization complete."
}

# ////// Privacy & Telemetry Functions \\\\\\ #

function Apply-TelemetryOptimization {
    Divider "Applying Telemetry Optimization"

    StepAnimation "Disabling Diagnostic Data & Telemetry Service (DiagTrack)"
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
    Log "Diagnostic Data & Telemetry Service disabled."

    StepAnimation "Disabling Connected User Experiences and Telemetry Service (dmwappushservice)"
    Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Log "Connected User Experiences and Telemetry Service disabled."

    StepAnimation "Disabling Windows CEIP Scheduled Tasks"
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Log "Windows CEIP Scheduled Tasks disabled."

    # AllowTelemetry to 0 in Registry
    StepAnimation "Adjusting general Telemetry settings via Registry"
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -LiteralPath $regPath -Name "AllowTelemetry" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath $regPath -Name "AllowDeviceNameInTelemetry" -Value 0 -Force -ErrorAction SilentlyContinue
    Log "Telemetry settings adjusted via Registry."

    Log "Telemetry optimization applied."
}

function Restore-TelemetryDefaults {
    Divider "Restoring Telemetry Defaults (Basic)"
    StepAnimation "Setting Diagnostic Data & Telemetry Service to Auto (DiagTrack)"
    Set-Service -Name "DiagTrack" -StartupType Auto -ErrorAction SilentlyContinue
    Start-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    Log "Diagnostic Data & Telemetry Service set to Auto."

    StepAnimation "Setting Connected User Experiences and Telemetry Service to Auto (dmwappushservice)"
    Set-Service -Name "dmwappushservice" -StartupType Auto -ErrorAction SilentlyContinue
    Start-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
    Log "Connected User Experiences and Telemetry Service set to Auto."

    StepAnimation "Enabling Windows CEIP Scheduled Tasks (if applicable)"
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -ErrorAction SilentlyContinue | Enable-ScheduledTask -ErrorAction SilentlyContinue
    Log "Windows CEIP Scheduled Tasks enabled (if found)."

    StepAnimation "Removing Telemetry policy settings from Registry"
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (Test-Path $regPath) {
        Remove-ItemProperty -LiteralPath $regPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        Remove-ItemProperty -LiteralPath $regPath -Name "AllowDeviceNameInTelemetry" -ErrorAction SilentlyContinue
    }
    Log "Telemetry policy settings removed from Registry."

    Log "Basic Telemetry Defaults restored."
}

function Manage-PrivacyAndTelemetry {
    while ($true) {
        Clear-Host
        Divider "Privacy & Telemetry Options"
        Write-Host "1. Apply Recommended Telemetry Optimization (Disable Data Collection)"
        Write-Host "2. Restore Basic Telemetry Defaults"
        Write-Host "3. Back to Main Menu"
        Write-Host ""
        $opt = Read-Host "Select an option (1-3)"

        switch ($opt) {
            '1' {
                Ensure-Admin
                Apply-TelemetryOptimization
                Prompt-ToContinue "Telemetry Optimization"
            }
            '2' {
                Ensure-Admin
                Restore-TelemetryDefaults
                Prompt-ToContinue "Telemetry Default Restoration"
            }
            '3' {
                return # Back to main menu
            }
            default {
                Write-Host "Invalid input. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}

# ////// Power Tweaks \\\\\\ #
# Use PowerSettingsExplorer to manually retrieve setting GUIDs.
# These optimizations are manually reviewed and tested to be worth changing.

function Get-PowerSettingInfo {
    # We directly read power scheme, subgroup, setting GUIDs and friendly names from the registry.
    $powerSettingsMap = @{
        "Schemes" = @{}
        "Subgroups" = @{}
        "Settings" = @{} # Stores settings as 'SubgroupFriendlyName/SettingFriendlyName' = @{Guid=...}
    }

    $powerSettingsRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings"
    $powerSchemesRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"

    # Enumerate Subgroups and their Settings from the central PowerSettings registry path
    # This ensures we get all defined settings, even the hidden ones.
    try {
        Get-ChildItem -Path $powerSettingsRoot -ErrorAction Stop | ForEach-Object {
            $subgroupGuid = $_.PSChildName
            $subgroupPath = $_.PSPath

            try {
                $subgroupFriendlyName = (Get-ItemProperty -LiteralPath $subgroupPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
                if (-not [string]::IsNullOrEmpty($subgroupFriendlyName)) {
                    $powerSettingsMap.Subgroups[$subgroupFriendlyName] = $subgroupGuid

                    # Now enumerate settings within this subgroup
                    Get-ChildItem -Path $subgroupPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $settingGuid = $_.PSChildName
                        $settingPath = $_.PSPath
                        try {
                            $settingFriendlyName = (Get-ItemProperty -LiteralPath $settingPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
                            if (-not [string]::IsNullOrEmpty($settingFriendlyName)) {
                                $compoundKey = "$subgroupFriendlyName/$settingFriendlyName"
                                $powerSettingsMap.Settings[$compoundKey] = @{
                                    Guid = $settingGuid
                                    SubgroupGuid = $subgroupGuid
                                    SubgroupFriendlyName = $subgroupFriendlyName
                                    FriendlyName = $settingFriendlyName
                                }
                            }
                        }
                        catch {
                            # Log "Registry: Could not read friendly name for setting '$settingGuid' in subgroup '$subgroupFriendlyName': $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                # Log "Registry: Could not read friendly name for subgroup '$subgroupGuid': $($_.Exception.Message)"
            }
        }
    }
    catch {
        # Log "ERROR: Could not enumerate PowerSettings registry root: $($_.Exception.Message)"
    }

    # Enumerate Power Schemes (less critical for individual settings but good for completeness)
    try {
        Get-ChildItem -Path $powerSchemesRoot -ErrorAction Stop | ForEach-Object {
            $schemeGuid = $_.PSChildName
            $schemePath = $_.PSPath
            try {
                $schemeFriendlyName = (Get-ItemProperty -LiteralPath $schemePath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
                if (-not [string]::IsNullOrEmpty($schemeFriendlyName)) {
                    $powerSettingsMap.Schemes[$schemeFriendlyName] = $schemeGuid
                    # Log "Registry: Found Power Scheme '$schemeFriendlyName' ($schemeGuid)"
                }
            }
            catch {
                # Log "Registry: Could not read friendly name for scheme '$schemeGuid': $($_.Exception.Message)"
            }
        }
    }
    catch {
        # Log "ERROR: Could not enumerate PowerSchemes registry root: $($_.Exception.Message)"
    }

    return $powerSettingsMap
}


function Backup-PowerSettings {
    Divider "Backing Up Power Plan Settings"
    $currentPlanOutput = powercfg /getactivescheme
    $currentPlanGUID = $null
    if ($currentPlanOutput -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') {
        $currentPlanGUID = $Matches[1]
    }

    if (-not $currentPlanGUID) {
        Write-Host "[!] Could not determine current power plan GUID. Skipping backup." -ForegroundColor Red
        return
    }

    $exportPath = "$env:USERPROFILE\powerplan-backup.pow"
    StepAnimation "Saving current plan"
    powercfg -export $exportPath $currentPlanGUID
    Log "Power plan backed up to: $exportPath"
}

# Eh, should be properly reversed.. *Let's hope it doesn't explode on Win10.
function Apply-PowerTweaks {
    Divider "Applying Power Tweaks"
    StepAnimation "Gathering power setting GUIDs..."

    # === MANUAL GUID OVERRIDES ===
    # If automatic detection fails for a specific setting, or if you want to force a GUID,
    # uncomment and set the GUID here. The key should be the *full friendly name of the setting*
    # (e.g., '@C:\WINDOWS\system32\powrprof.dll,-820,Maximum processor frequency').
    # These will take precedence over auto-detected GUIDs.
    $manualOverrides = @{
        # "@C:\WINDOWS\system32\powrprof.dll,-365,Minimum processor state" = "893dee8e-2bef-41e0-89c6-b55d0929964c"
        # "@C:\WINDOWS\system32\powrprof.dll,-363,Maximum processor state" = "bc5038f7-23e0-4960-96da-33abaf5935ec"
        # "@C:\WINDOWS\system32\powrprof.dll,-703,Processor idle disable" = "5d76a2ca-e8c0-402f-a133-2158492d58ad"
        # "@C:\WINDOWS\system32\powrprof.dll,-728,Processor performance boost mode" = "be337238-0d82-4146-a960-4f3749d470c7"
        # "@C:\WINDOWS\system32\powrprof.dll,-720,Processor performance boost policy" = "45bcc044-d885-43e2-8605-ee0ec6e96b59"
        # "@C:\WINDOWS\system32\powrprof.dll,-399,Processor performance time check interval" = "4d2b0152-7d5c-498b-88e2-34345392a2c5"
        # "@C:\WINDOWS\system32\powrprof.dll,-767,Processor performance core parking min cores" = "0cc5b647-c1df-4637-891a-dec35c318583"
        # "@C:\WINDOWS\system32\powrprof.dll,-765,Processor performance core parking max cores" = "ea062031-0e34-4ff1-9b6d-eb1059334028"
    }

    # Get all power setting info dynamically
    $powerSettings = Get-PowerSettingInfo
    
    if (-not $powerSettings) {
        Write-Host "[!] Failed to retrieve power setting information. Skipping power tweaks." -ForegroundColor Red
        Log "Failed to retrieve power setting information during Apply-PowerTweaks. Skipping."
        return
    }

    # Resolve the *actual* friendly name for the processor subgroup from the registry
    $subProcessorFriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-351,Processor power management'

    $subProcessorGUID = $powerSettings.Subgroups[$subProcessorFriendlyName]

    if (-not $subProcessorGUID) {
        Write-Host "[!] Could not find GUID for '$subProcessorFriendlyName'. Skipping power tweaks." -ForegroundColor Red
        Log "Please check if '$subProcessorFriendlyName'. exists on your system or provide a manual override."
        return
    } else {
        Log "Resolved GUID for '$subProcessorFriendlyName'."
    }

    $currentPlanOutput = powercfg /getactivescheme
    $schemeGUID = $null
    if ($currentPlanOutput -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') {
        $schemeGUID = $Matches[1]
    }

    if (-not $schemeGUID) {
        Write-Host "[!] Could not determine current power plan GUID. Skipping power tweaks." -ForegroundColor Red
        return
    }

    # Define settings to apply and their target values
    $settingsToApply = @(
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-365,Minimum processor state'; Value = 100 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-363,Maximum processor state'; Value = 100 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-703,Processor idle disable'; Value = 1 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-728,Processor performance boost mode'; Value = 2 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-720,Processor performance boost policy'; Value = 100 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-399,Processor performance time check interval'; Value = 5000 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-767,Processor performance core parking min cores'; Value = 100 },
        @{ FriendlyName = '@C:\WINDOWS\system32\powrprof.dll,-765,Processor performance core parking max cores'; Value = 100 }
    )

    StepAnimation "Applying advanced power options"
    foreach ($setting in $settingsToApply) {
        $settingFriendlyName = $setting.FriendlyName
        $targetValue = $setting.Value
        
        # Construct the compound key exactly as it's stored in $powerSettings.Settings
        $compoundKeyForLookup = "$subProcessorFriendlyName/$settingFriendlyName"

        $settingGUID = $null
        # Check manual overrides. The manual override keys must match the setting's friendly name string.
        if ($manualOverrides.ContainsKey($settingFriendlyName)) {
            $settingGUID = $manualOverrides[$settingFriendlyName]
            Log "Using manual override for '$settingFriendlyName': $settingGUID"
        }

        if (-not $settingGUID) {
            # Try to get it from the dynamically parsed settings using the correct compound key
            $settingInfo = $powerSettings.Settings[$compoundKeyForLookup]
            if ($settingInfo) {
                $settingGUID = $settingInfo.Guid
            }
        }

        if ($settingGUID) {
            # Write-Host "    Setting '$settingFriendlyName' to $targetValue..." -NoNewline
            powercfg -setacvalueindex $schemeGUID $subProcessorGUID $settingGUID $targetValue *> $null
            if ($LASTEXITCODE -eq 0) {
            #    Write-Host " OK" -ForegroundColor Green
                Log "Successfully set '$settingFriendlyName' to $targetValue."
            } else {
                Write-Host " FAILED (Error Code: $LASTEXITCODE)" -ForegroundColor Red
                Log "Failed to set '$settingFriendlyName' to $targetValue. Error Code: $LASTEXITCODE"
            }
        } else {
            Write-Host "[!] Could not find GUID for '$settingFriendlyName'. Skipping this setting." -ForegroundColor Yellow
            Write-Host "    Consider adding a manual override in the script if this setting is critical." -ForegroundColor DarkYellow
            Log "Could not find GUID for '$settingFriendlyName'. Skipping setting."
        }
    }

    # Note: Idle demote/promote thresholds and Performance increase/decrease thresholds
    # are not included as they are redundant when min/max processor state is 100%
    # and processor idle is disabled. - Loki

    powercfg -setactive $schemeGUID
    Log "Power tweaks applied to active plan."
}

function Enable-UltimatePlan {
    Divider "Ultimate Power Plan"
    StepAnimation "Checking for existing Ultimate Plan"

    $ultimateGUID = $null
    $ultimatePlanInfo = powercfg /list | ForEach-Object {
        if ($_ -match 'Ultimate Performance' -and $_ -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') {
            $Matches[1]
        }
    }

    if ($ultimatePlanInfo) {
        $ultimateGUID = $ultimatePlanInfo
        Log "Ultimate Performance plan already exists."
    } else {
        StepAnimation "Creating Ultimate Performance Plan"
        $duplicateOutput = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
        if ($duplicateOutput -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') {
            $ultimateGUID = $Matches[1]
        }
    }

    if ($ultimateGUID) {
        powercfg /setactive $ultimateGUID
        Log "Ultimate Performance plan activated."
    } else {
        Write-Host "[!] Failed to create or activate Ultimate plan." -ForegroundColor Red
    }
}

# ////// Main Menu + Logic \\\\\\ #

function Prompt-ToContinue ($actionName) {
    Clear-Host
    Divider "$actionName Complete"
    Write-Host "$actionName has finished." -ForegroundColor Green

    if ($global:IpResetFailedDetails) {
        Write-Host ""
        Write-Host "[!] Note: During Network Stack Reset, the following IP Interface components reported issues:" -ForegroundColor Yellow
        $global:IpResetFailedDetails | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor Red # Print the exact line that failed
        }
        Write-Host "    This is often normal for specific locked components and usually doesn't prevent general network functionality." -ForegroundColor DarkYellow

        $global:IpResetFailedDetails = $null
    }

    if ($global:RestartRequired) {
        Write-Host ""
        Write-Host "[!] A system restart is recommended to apply all changes (e.g., network stack resets)." -ForegroundColor Yellow
        $confirmRestart = Read-Host "Would you like to restart your computer now? (Y/N)"
        if ($confirmRestart -eq "Y") {
            Log "Restarting computer..."
            Restart-Computer -Force
        } else {
            Log "Please restart your computer manually at your convenience."
        }
    } else {
        Write-Host ""
        Log "No system restart is required for this action."
    }

    $global:RestartRequired = $false

    Write-Host ""
    Read-Host "Press Enter to return to the Main Menu..." | Out-Null
}

function Main-Menu {
    while ($true) {
        Clear-Host
        Divider "Windows Maintenance Toolkit by Loki"
        Write-Host "1. Run Full Maintenance (Recommended to be run weekly)"
        Write-Host "2. Run Power Tweaks (Cross-Version Support)"
        Write-Host "3. Optimize Privacy & Telemetry (Disable Data Collection)"
        Write-Host "4. Exit"
        Write-Host ""
        $opt = Read-Host "Select an option (1-4)"

        switch ($opt) {
            '1' {
                Run-Maintenance
            }
            '2' {
                Apply-FullTweaks
            }
            '3' {
                Manage-PrivacyAndTelemetry # Sub menu
            }
            '4' {
                Write-Host "Exiting..."
                exit
            }
            default {
                Write-Host "Invalid input. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}

# ////// Controller Functions \\\\\\ #

function Run-Maintenance {
    Ensure-Admin
    Clear-TempFiles
    Run-CleanMgr
    Reset-NetworkStack
    Repair-System
    Optimize-Drives
    Log "Full Maintenance tasks initiated."
    Prompt-ToContinue "Full Maintenance"
}

function Apply-FullTweaks {
    Ensure-Admin
    Backup-PowerSettings
    Enable-UltimatePlan
    Apply-PowerTweaks
    Log "Power tweaks initiated."
    Prompt-ToContinue "Power Tweaks"
}

# ////// Entry \\\\\\ #

Ensure-Admin
Main-Menu