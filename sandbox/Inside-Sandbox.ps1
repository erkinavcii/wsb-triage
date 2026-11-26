<#
    SafeBox sandbox monitor. Runs INSIDE Windows Sandbox or VirtualBox guest.
    C:\Analysis\input  (read-only)  extracted sample
    C:\Analysis\tools  (read-only)  this script, config.json, optional Procmon64.exe, stop.flag (written by host)
    C:\Analysis\output (writable)   live.json (every 5 s), behavior.json, capture.pcapng, timeline.log, procmon.pml

    Steps: honeyfiles + baseline snapshot -> start pktmon (+Procmon +4688 audit) -> run sample -> watch
           (new processes, TCP connections, DNS cache, quick persistence diff, LAN block check, screenshots)
           -> stop capture -> final snapshot + honeyfile check -> diff -> behavior.json + done.flag
#>
param(
    [string]$BasePath = 'C:\Analysis',
    [string]$WorkPath = 'C:\SandboxWork',
    [string]$InputDir = '',
    [string]$ToolsDir = '',
    [string]$OutputDir = '',
    [switch]$TestMode      # host self-test: small file scan, no capture tools
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
if (-not $InputDir)  { $InputDir  = Join-Path $BasePath 'input' }
if (-not $ToolsDir)  { $ToolsDir  = Join-Path $BasePath 'tools' }
if (-not $OutputDir) { $OutputDir = Join-Path $BasePath 'output' }
$SampleDir = Join-Path $WorkPath 'sample'
New-Item -ItemType Directory -Force -Path $WorkPath, $SampleDir, $OutputDir | Out-Null
$WorkPath = (Get-Item -LiteralPath $WorkPath).FullName
$SampleDir = (Get-Item -LiteralPath $SampleDir).FullName
$StopFlag = Join-Path $ToolsDir 'stop.flag'
$ScreenshotsDir = Join-Path $OutputDir 'screenshots'
$script:ShotCount = 0
$script:LastShot = [datetime]::MinValue
$script:ScreenWarned = $false
try { Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop } catch {}

# Live view for the host panel: a downscaled screenshot overwritten every ~5 s while observing.
# Written to the sandbox disk first and then copied, so the host rarely sees a half-written file.
$script:LiveScreenWarned = $false
function Capture-LiveScreen {
    if ($TestMode) { return }
    try {
        $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if (-not $bounds -or $bounds.Width -lt 10 -or $bounds.Height -lt 10) { return }
        if (-not (Test-Path -LiteralPath $ScreenshotsDir)) { New-Item -ItemType Directory -Force -Path $ScreenshotsDir | Out-Null }
        $full = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        $g = [System.Drawing.Graphics]::FromImage($full)
        try { $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size) } finally { $g.Dispose() }
        $scale = [Math]::Min(1.0, 1024.0 / $bounds.Width)
        $w = [int]($bounds.Width * $scale); $h = [int]($bounds.Height * $scale)
        $small = New-Object System.Drawing.Bitmap($w, $h)
        $g2 = [System.Drawing.Graphics]::FromImage($small)
        try {
            $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBilinear
            $g2.DrawImage($full, 0, 0, $w, $h)
            $tmp = Join-Path $WorkPath 'live_screen.png'
            $small.Save($tmp, [System.Drawing.Imaging.ImageFormat]::Png)
            Copy-Item -LiteralPath $tmp -Destination (Join-Path $ScreenshotsDir 'live.png') -Force
        } finally { $g2.Dispose(); $small.Dispose(); $full.Dispose() }
    } catch {
        if (-not $script:LiveScreenWarned) { $script:LiveScreenWarned = $true; Log "Live screen skipped: $($_.Exception.Message)" }
    }
}

function Capture-Screen {
    if ($TestMode -or $script:ShotCount -ge 24) { return }
    try {
        $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if (-not $bounds -or $bounds.Width -lt 10 -or $bounds.Height -lt 10) { return }
        if (-not (Test-Path -LiteralPath $ScreenshotsDir)) { New-Item -ItemType Directory -Force -Path $ScreenshotsDir | Out-Null }
        $script:ShotCount++
        $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
            $file = Join-Path $ScreenshotsDir ('scr_{0:D3}.png' -f $script:ShotCount)
            $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $g.Dispose()
            $bmp.Dispose()
        }
        $script:LastShot = Get-Date
    } catch {
        if (-not $script:ScreenWarned) {
            $script:ScreenWarned = $true
            Log "Screenshot skipped: $($_.Exception.Message)"
        }
    }
}
try { $Host.UI.RawUI.WindowTitle = 'Windows Update Service' } catch {}

$TimelineFile = Join-Path $OutputDir 'timeline.log'
function Log([string]$m) {
    $l = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $l
    Add-Content -LiteralPath $TimelineFile -Value $l
}
function Set-Status([string]$s) { Set-Content -LiteralPath (Join-Path $OutputDir 'status.txt') -Value $s }
function Write-JsonFile([string]$Name, $Obj, [int]$Depth = 6) {
    $tmp = Join-Path $OutputDir "$Name.tmp"
    [IO.File]::WriteAllText($tmp, ($Obj | ConvertTo-Json -Depth $Depth), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination (Join-Path $OutputDir $Name) -Force
}

$cfg = Get-Content -LiteralPath (Join-Path $ToolsDir 'config.json') -Raw | ConvertFrom-Json
$Duration = [int]$cfg.DurationSeconds
if ($Duration -lt 10) { $Duration = 600 }
$SimulateUser = [bool]($cfg.PSObject.Properties['SimulateUser'] -and $cfg.SimulateUser)
$FakeNet = [bool]($cfg.PSObject.Properties['FakeNet'] -and $cfg.FakeNet)
$SeedHoneyfiles = if ($cfg.PSObject.Properties['SeedHoneyfiles']) { [bool]$cfg.SeedHoneyfiles } else { $true }
$RunAsStandardUser = [bool]($cfg.PSObject.Properties['RunAsStandardUser'] -and $cfg.RunAsStandardUser)
$TargetArgs = if ($cfg.PSObject.Properties['TargetArgs'] -and $cfg.TargetArgs) { [string]$cfg.TargetArgs } else { '' }
$DllExport = if ($cfg.PSObject.Properties['DllExport'] -and $cfg.DllExport) { [string]$cfg.DllExport } else { '' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "Monitor started. admin=$isAdmin duration=${Duration}s simulateUser=$SimulateUser fakeNet=$FakeNet honey=$SeedHoneyfiles stdUser=$RunAsStandardUser"
Set-Status 'preparing'

$script:SimLast = [datetime]::MinValue
$script:SimRng = New-Object System.Random
$script:ClickedBtns = @{}
$script:AutoClicks = 0
$script:ClickedActions = New-Object System.Collections.ArrayList
$AutoClickBtnRx = '(?i)^(next|i.?leri|install|y.?kle|i\s*agree|accept|agree|kabul|devam|continue|finish|bitir|tamam|ok)(\s*>+)*$'
$AutoSkipBtnRx = '(?i)(cancel|iptal|decline|reddet|back|geri)'
$LicenseAcceptRx = '(?i)(i\s*accept|i\s*agree|accept\s+the\s+(agreement|terms|license)|kabul\s*ediyorum|lisans.*kabul|onayl.yorum)'
$AdwareSkipRx = '(?i)(toolbar|opera|avast|mcafee|norton|yandex|bing|yahoo|sponsor|optional|onerilen|recommended\s+offer)'
if ($SimulateUser -and -not $TestMode) {
    try {
        Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes -ErrorAction SilentlyContinue
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SafeBoxInput {
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT pt);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, UIntPtr dwExtraInfo);
}
"@ -ErrorAction SilentlyContinue
    } catch {}
}

function Add-ClickedAction([string]$Entry) {
    if ($script:ClickedActions.Count -lt 50) {
        [void]$script:ClickedActions.Add($Entry)
    }
}

function Invoke-FakeUser {
    if (-not $SimulateUser -or $TestMode) { return }
    if (((Get-Date) - $script:SimLast).TotalSeconds -lt 12) { return }
    $script:SimLast = Get-Date
    try {
        $pt = New-Object SafeBoxInput+POINT
        if ([SafeBoxInput]::GetCursorPos([ref]$pt)) {
            $dx = $script:SimRng.Next(-65, 66)
            $dy = $script:SimRng.Next(-45, 46)
            if ($dx -eq 0 -and $dy -eq 0) { $dx = 17; $dy = -11 }
            $maxW = 1200; $maxH = 760
            try {
                $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
                if ($vs.Width -gt 100 -and $vs.Height -gt 100) { $maxW = $vs.Width - 20; $maxH = $vs.Height - 20 }
            } catch {}
            $nx = [Math]::Min($maxW, [Math]::Max(20, $pt.X + $dx))
            $ny = [Math]::Min($maxH, [Math]::Max(20, $pt.Y + $dy))
            [void][SafeBoxInput]::SetCursorPos($nx, $ny)
        }
    } catch {}
    try {
        $root = [System.Windows.Automation.AutomationElement]::RootElement
        if (-not $root) { return }
        $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($w in $wins) {
            $wpid = [int]$w.Current.ProcessId
            if (-not $TreePids.ContainsKey($wpid)) { continue }

            $radioCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::RadioButton)
            $radios = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $radioCond)
            foreach ($r in $radios) {
                $rname = ([string]$r.Current.Name).Trim()
                if (-not $rname -or -not ($rname -match $LicenseAcceptRx) -or ($rname -match $AdwareSkipRx) -or -not $r.Current.IsEnabled -or $r.Current.IsOffscreen) { continue }
                $rtId = ($r.GetRuntimeId() -join '.')
                $key = "$wpid|radio|$rtId|$rname"
                if ($script:ClickedBtns.ContainsKey($key) -and ((Get-Date) - $script:ClickedBtns[$key]).TotalSeconds -lt 25) { continue }
                $selPat = $null
                if ($r.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$selPat)) {
                    if (-not $selPat.Current.IsSelected) {
                        $script:ClickedBtns[$key] = Get-Date
                        $script:AutoClicks++
                        $selPat.Select()
                        Add-ClickedAction "RadioButton: $rname (pid=$wpid)"
                        Log "AUTO-SELECT RadioButton '$rname' (pid=$wpid)"
                        return
                    }
                }
            }

            $chkCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::CheckBox)
            $chks = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $chkCond)
            foreach ($c in $chks) {
                $cname = ([string]$c.Current.Name).Trim()
                if (-not $cname -or -not ($cname -match $LicenseAcceptRx) -or ($cname -match $AdwareSkipRx) -or -not $c.Current.IsEnabled -or $c.Current.IsOffscreen) { continue }
                $rtId = ($c.GetRuntimeId() -join '.')
                $key = "$wpid|chk|$rtId|$cname"
                if ($script:ClickedBtns.ContainsKey($key) -and ((Get-Date) - $script:ClickedBtns[$key]).TotalSeconds -lt 25) { continue }
                $togPat = $null
                if ($c.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$togPat)) {
                    if ("$($togPat.Current.ToggleState)" -eq 'Off') {
                        $script:ClickedBtns[$key] = Get-Date
                        $script:AutoClicks++
                        $togPat.Toggle()
                        Add-ClickedAction "CheckBox: $cname (pid=$wpid)"
                        Log "AUTO-TOGGLE CheckBox '$cname' (pid=$wpid)"
                        return
                    }
                }
            }

            $btnCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
            $lnkCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Hyperlink)
            $actCond = New-Object System.Windows.Automation.OrCondition($btnCond, $lnkCond)
            $btns = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $actCond)
            foreach ($b in $btns) {
                $bname = ([string]$b.Current.Name).Trim()
                if (-not $bname -or -not ($bname -match $AutoClickBtnRx) -or ($bname -match $AutoSkipBtnRx) -or -not $b.Current.IsEnabled -or $b.Current.IsOffscreen) { continue }
                $rtId = ($b.GetRuntimeId() -join '.')
                $key = "$wpid|$rtId|$bname"
                if ($script:ClickedBtns.ContainsKey($key) -and ((Get-Date) - $script:ClickedBtns[$key]).TotalSeconds -lt 25) { continue }
                $clicked = $false
                $pat = $null
                if ($b.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pat)) {
                    $pat.Invoke()
                    $clicked = $true
                } else {
                    try {
                        $legPat = $null
                        if ($b.TryGetCurrentPattern([System.Windows.Automation.LegacyIAccessiblePattern]::Pattern, [ref]$legPat)) {
                            $legPat.DoDefaultAction()
                            $clicked = $true
                        }
                    } catch {}
                }
                if (-not $clicked) {
                    try {
                        $rect = $b.Current.BoundingRectangle
                        if (-not $rect.IsEmpty -and $rect.Width -gt 2 -and $rect.Height -gt 2) {
                            $cx = [int]($rect.Left + ($rect.Width / 2))
                            $cy = [int]($rect.Top + ($rect.Height / 2))
                            [void][SafeBoxInput]::SetCursorPos($cx, $cy)
                            [SafeBoxInput]::mouse_event(0x02, 0, 0, 0, [UIntPtr]::Zero)
                            [SafeBoxInput]::mouse_event(0x04, 0, 0, 0, [UIntPtr]::Zero)
                            $clicked = $true
                        }
                    } catch {}
                }
                if ($clicked) {
                    $script:ClickedBtns[$key] = Get-Date
                    $script:AutoClicks++
                    Add-ClickedAction "Button: $bname (pid=$wpid)"
                    Log "AUTO-CLICK '$bname' (pid=$wpid)"
                    return
                }
            }
        }
    } catch {}
}

# ------------------------------------------------------------------ honeyfiles (infostealer / ransomware decoys)
if (-not ('SafeBoxPriv' -as [type])) {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SafeBoxPriv {
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }
    public static bool EnablePrivilege(string privilegeName) {
        IntPtr hTok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out hTok)) return false;
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 0x00000002 };
            if (!AdjustTokenPrivileges(hTok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
            return Marshal.GetLastWin32Error() == 0;
        } finally {
            CloseHandle(hTok);
        }
    }
}
"@ -ErrorAction SilentlyContinue
    } catch {}
}

$script:Honeyfiles = @()
$script:HoneyMap = @{}
$script:HoneySeenReads = @{}
$script:HoneyReadAlerts = New-Object System.Collections.ArrayList
$script:HoneyLastPoll = [datetime]::MinValue
$HoneyBenignReaders = @(
    'msmpeng.exe', 'nissrv.exe', 'mpcmdrun.exe', 'securityhealthservice.exe',
    'searchprotocolhost.exe', 'searchindexer.exe', 'searchfilterhost.exe', 'system'
)
$HoneyShellDocReaders = @(
    'explorer.exe', 'dllhost.exe', 'backgroundtaskhost.exe', 'runtimebroker.exe', 'sihost.exe'
)

function Test-HoneyBenignReader([string]$ProcLeaf, [int]$EvPid, [bool]$IsVault) {
    if ($EvPid -gt 0 -and $TreePids.ContainsKey($EvPid)) { return $false }
    $leaf = ([string]$ProcLeaf).ToLower()
    if ($HoneyBenignReaders -contains $leaf) { return $true }
    if ((-not $IsVault) -and ($HoneyShellDocReaders -contains $leaf)) { return $true }
    return $false
}

function Record-HoneyRead([string]$ObjPath, [string]$ProcLeaf, [int]$EvPid) {
    if (-not $ObjPath -or $EvPid -eq $PID) { return }
    $objKey = $ObjPath.ToLower()
    if (-not $script:HoneyMap.ContainsKey($objKey) -or $script:HoneySeenReads.ContainsKey($objKey)) { return }
    $h = $script:HoneyMap[$objKey]
    $leaf = if ($ProcLeaf) { ([IO.Path]::GetFileName($ProcLeaf)).ToLower() } else { 'unknown' }
    if (Test-HoneyBenignReader $leaf $EvPid ([bool]$h.Vault)) { return }
    $script:HoneySeenReads[$objKey] = 1
    $msg = "ACCESSED (infostealer read by $leaf pid=$EvPid): $($h.Path)"
    [void]$script:HoneyReadAlerts.Add($msg)
    Log "HONEYFILE READ by $leaf pid=${EvPid}: $($h.Path)"
}

function Initialize-Honeyfiles {
    if (-not $SeedHoneyfiles -or $TestMode) { return }
    $privOk = $false
    try { $privOk = [SafeBoxPriv]::EnablePrivilege('SeSecurityPrivilege') } catch {}
    # Enable File System object access auditing via locale-independent subcategory GUID (Event ID 4663 / 4656)
    try { & auditpol.exe /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable 2>&1 | Out-Null } catch {}
    $specs = @(
        @{ P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"; V = $true; C = "SQLite format 3`0fake_login_data_canary" },
        @{ P = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"; V = $true; C = '{"os_crypt":{"encrypted_key":"RFBBUEkAAAA="}}' },
        @{ P = "$env:APPDATA\Mozilla\Firefox\Profiles\default.canary\logins.json"; V = $true; C = '{"nextId":2,"logins":[{"hostname":"https://canary.invalid","encryptedUsername":"canary"}]}' },
        @{ P = "$env:APPDATA\Mozilla\Firefox\Profiles\default.canary\cookies.sqlite"; V = $true; C = "SQLite format 3`0fake_cookie_canary" },
        @{ P = "$env:APPDATA\Exodus\exodus.wallet\seed.seco"; V = $true; C = "SECO_CANARY_WALLET_0001" },
        @{ P = "$env:APPDATA\Electrum\wallets\default_wallet"; V = $true; C = '{"seed_version":17,"use_encryption":false,"canary":true}' },
        @{ P = "$env:USERPROFILE\Documents\passwords_backup.txt"; V = $false; C = "bank_pin=4821`r`nseed=abandon ability able about above absent`r`n" },
        @{ P = "$env:USERPROFILE\Documents\finance_2026.docx"; V = $false; C = "PK_CANARY_FINANCE_DOCUMENT_2026" },
        @{ P = "$env:USERPROFILE\Desktop\wallet_keys.txt"; V = $false; C = "BTC_WIF=5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ`r`n" }
    )
    $everyoneSid = $null
    try { $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0') } catch {}
    $saclCount = 0
    $lastSaclErr = ''
    foreach ($sp in $specs) {
        try {
            $fp = $sp.P
            if (Test-Path -LiteralPath $fp) { continue }
            $parent = Split-Path -Parent $fp
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Force -Path $parent -ErrorAction Stop | Out-Null
            }
            [IO.File]::WriteAllText($fp, $sp.C, (New-Object System.Text.UTF8Encoding($false)))
            $sha = (Get-FileHash -LiteralPath $fp -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($everyoneSid) {
                try {
                    $acl = [IO.File]::GetAccessControl($fp, [System.Security.AccessControl.AccessControlSections]::Audit)
                    $auditRights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor [System.Security.AccessControl.FileSystemRights]::ExecuteFile
                    $auditFlags = [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
                    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                        $everyoneSid,
                        $auditRights,
                        [System.Security.AccessControl.InheritanceFlags]::None,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        $auditFlags
                    )
                    $acl.AddAuditRule($auditRule)
                    [IO.File]::SetAccessControl($fp, $acl)
                    $saclCount++
                } catch {
                    $lastSaclErr = $_.Exception.Message
                }
            }
            $hObj = [pscustomobject]@{
                Path = $fp
                Sha256 = $sha
                Vault = [bool]$sp.V
            }
            $script:Honeyfiles += $hObj
            $script:HoneyMap[$fp.ToLower()] = $hObj
        } catch {}
    }
    $script:HoneyLastPoll = Get-Date
    Log "Honeyfiles seeded: $($script:Honeyfiles.Count) (SACL active: $saclCount, SeSecurityPrivilege: $privOk)"
    if ($saclCount -eq 0 -and $lastSaclErr) { Log "Honeyfile SACL warning: $lastSaclErr" }
}

function Update-HoneyReads([datetime]$FloorTime) {
    if ($script:HoneyMap.Count -eq 0 -or $TestMode) { return }
    $from = if ($script:HoneyLastPoll -gt $FloorTime) { $script:HoneyLastPoll.AddSeconds(-3) } else { $FloorTime.AddSeconds(-2) }
    $pollTs = Get-Date
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4663, 4656); StartTime = $from } -MaxEvents 2500 -ErrorAction SilentlyContinue
        foreach ($ev in $evs) {
            try {
                $xml = [xml]$ev.ToXml()
                $d = @{}
                foreach ($node in $xml.Event.EventData.Data) { $d[$node.Name] = [string]$node.'#text' }
                $obj = ([string]$d['ObjectName']).Trim()
                if (-not $obj -or -not $script:HoneyMap.ContainsKey($obj.ToLower())) { continue }
                $rawMask = ([string]$d['AccessMask']).Trim()
                if ($rawMask) {
                    $maskVal = 0
                    if ($rawMask -match '^0x[0-9a-fA-F]+$') { $maskVal = [Convert]::ToInt64($rawMask, 16) }
                    elseif ($rawMask -match '^\d+$') { $maskVal = [int64]$rawMask }
                    if ($maskVal -gt 0 -and (($maskVal -band 0x21) -eq 0)) { continue }
                }
                $rawPid = ([string]$d['ProcessId']).Trim()
                $evPid = 0
                if ($rawPid -match '^0x[0-9a-fA-F]+$') { $evPid = [Convert]::ToInt32($rawPid, 16) }
                elseif ($rawPid -match '^\d+$') { $evPid = [int]$rawPid }
                if ($evPid -eq $PID) { continue }
                $procPath = ([string]$d['ProcessName']).Trim()
                Record-HoneyRead $obj $procPath $evPid
            } catch {}
        }
    } catch {}
    $script:HoneyLastPoll = $pollTs
}

function Check-Honeyfiles([datetime]$Since) {
    Update-HoneyReads $Since
    $alerts = @()
    foreach ($h in $script:Honeyfiles) {
        if (-not (Test-Path -LiteralPath $h.Path)) {
            $alerts += "DELETED: $($h.Path)"
            continue
        }
        try {
            $sha = (Get-FileHash -LiteralPath $h.Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($sha -ne $h.Sha256) {
                $alerts += "MODIFIED (ransomware/tamper): $($h.Path)"
            }
        } catch {
            $alerts += "UNREADABLE: $($h.Path)"
        }
    }
    foreach ($ra in $script:HoneyReadAlerts) {
        $alerts += [string]$ra
    }
    return @($alerts)
}

# ------------------------------------------------------------------ snapshot pieces
$RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)

function Get-RunEntries {
    foreach ($p in $RunKeyPaths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            if ($p -like '*Session Manager' -and $pr.Name -notin 'BootExecute', 'AppCertDlls') { continue }
            $val = $pr.Value
            if ($val -is [array]) { $val = $val -join ',' }
            "$p :: $($pr.Name) = $val"
        }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $d = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { "IFEO :: $($_.PSChildName) Debugger = $d" }
    }
}

function Get-DefenderState {
    try {
        $p = Get-MpPreference -ErrorAction Stop
        foreach ($x in @($p.ExclusionPath)) { if ($x) { "ExclusionPath: $x" } }
        foreach ($x in @($p.ExclusionProcess)) { if ($x) { "ExclusionProcess: $x" } }
        foreach ($x in @($p.ExclusionExtension)) { if ($x) { "ExclusionExtension: $x" } }
        foreach ($x in @($p.ExclusionIpAddress)) { if ($x) { "ExclusionIpAddress: $x" } }
        "DisableRealtimeMonitoring: $($p.DisableRealtimeMonitoring)"
        "DisableBehaviorMonitoring: $($p.DisableBehaviorMonitoring)"
        "DisableIOAVProtection: $($p.DisableIOAVProtection)"
    } catch { "Defender query failed" }
}

# Services are compared by NAME: a service that existed before and only changed (start mode / binary path) is
# reported separately from a newly installed one. Windows itself flips start modes (e.g. BITS -> Auto).
function Split-ServiceDiff($Before, $After) {
    $bmap = @{}
    foreach ($l in @($Before)) { $n = ([string]$l).Split('|')[0].Trim(); if ($n) { $bmap[$n] = [string]$l } }
    $new = @(); $changed = @()
    foreach ($l in @($After)) {
        $n = ([string]$l).Split('|')[0].Trim()
        if (-not $n) { continue }
        if (-not $bmap.ContainsKey($n)) { $new += [string]$l }
        elseif ($bmap[$n] -ne [string]$l) { $changed += "$($bmap[$n]) -> $l" }
    }
    [pscustomobject]@{ New = @($new); Changed = @($changed) }
}

function Get-ServiceList { @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) | $($_.StartMode) | $($_.PathName)" }) }
function Get-DriverList { @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) | $($_.PathName)" }) }
function Get-TaskList {
    @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $acts = @($_.Actions | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join '; '
        "$($_.TaskPath)$($_.TaskName) | $acts" })
}
function Get-StartupList { @(Get-ChildItem -Force -ErrorAction SilentlyContinue -LiteralPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | ForEach-Object { $_.FullName }) }
function Get-HostsLines { @(Get-Content -LiteralPath "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) }

function Get-WmiSubscriptionList {
    $out = @()
    foreach ($cls in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
        try {
            Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop | ForEach-Object {
                $detail = if ($_.CommandLineTemplate) { $_.CommandLineTemplate } elseif ($_.Query) { $_.Query } elseif ($_.Filter) { "$($_.Filter) -> $($_.Consumer)" } else { $_.Name }
                $out += "$cls | $($_.Name) | $detail"
            }
        } catch {}
    }
    return @($out)
}

function Get-ComHijackList {
    $out = @()
    $base = 'HKCU:\Software\Classes\CLSID'
    if (Test-Path -LiteralPath $base) {
        Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
            $clsid = $_.PSChildName
            foreach ($sub in 'InprocServer32', 'LocalServer32') {
                $sp = Join-Path $_.PSPath $sub
                if (Test-Path -LiteralPath $sp) {
                    $v = (Get-ItemProperty -LiteralPath $sp -ErrorAction SilentlyContinue).'(default)'
                    if ($v) { $out += "HKCU\CLSID\$clsid\$sub = $v" }
                }
            }
        }
    }
    return @($out)
}

function Get-AppInitList {
    $out = @()
    foreach ($rp in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        if (Test-Path -LiteralPath $rp) {
            $pr = Get-ItemProperty -LiteralPath $rp -ErrorAction SilentlyContinue
            if ($pr -and $pr.AppInit_DLLs) { $out += "$rp :: AppInit_DLLs = $($pr.AppInit_DLLs) (Load=$($pr.LoadAppInit_DLLs))" }
        }
    }
    if (Test-Path -LiteralPath 'HKCU:\Environment') {
        $envProps = Get-ItemProperty -LiteralPath 'HKCU:\Environment' -ErrorAction SilentlyContinue
        if ($envProps -and $envProps.UserInitMprLogonScript) {
            $out += "HKCU\Environment :: UserInitMprLogonScript = $($envProps.UserInitMprLogonScript)"
        }
    }
    return @($out)
}

function Get-BitsJobList {
    try {
        @(Get-BitsTransfer -AllUsers -ErrorAction Stop | ForEach-Object { "$($_.DisplayName) | $($_.TransferType) | $($_.JobState) | $($_.FileList.RemoteName -join ',')" })
    } catch { @() }
}

function Get-PsProfileList {
    $out = @()
    $cands = @(
        "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
        "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
        "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1"
    )
    foreach ($cp in $cands) {
        if (Test-Path -LiteralPath $cp) {
            $len = (Get-Item -LiteralPath $cp -Force -ErrorAction SilentlyContinue).Length
            $out += "$cp (len=$len)"
        }
    }
    return @($out)
}

function Get-ActiveSetupList {
    $out = @()
    $base = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
    if (Test-Path -LiteralPath $base) {
        Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
            $sp = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).StubPath
            if ($sp) { $out += "$($_.PSChildName) | $sp" }
        }
    }
    return @($out)
}

function Get-UdpList {
    try {
        @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $n = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            "$($_.LocalAddress):$($_.LocalPort) | $n"
        } | Select-Object -Unique)
    } catch { @() }
}

if ($TestMode) {
    $FileScan = @(@{ P = $env:TEMP; R = $true })
} else {
    $FileScan = @(
        @{ P = $env:APPDATA; R = $true }, @{ P = $env:LOCALAPPDATA; R = $true }, @{ P = $env:ProgramData; R = $true },
        @{ P = "$env:windir\Temp"; R = $true }, @{ P = $env:PUBLIC; R = $true }, @{ P = "$env:windir\System32\drivers"; R = $true },
        @{ P = "$env:windir\System32"; R = $false }, @{ P = "$env:windir\SysWOW64"; R = $false }, @{ P = $env:windir; R = $false },
        @{ P = 'C:\'; R = $false }, @{ P = "$env:USERPROFILE"; R = $false },
        @{ P = "$env:USERPROFILE\Desktop"; R = $true }, @{ P = "$env:USERPROFILE\Documents"; R = $true }
    )
}
$ExecExt = @('.exe', '.dll', '.sys', '.scr', '.com', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk', '.jar', '.msi', '.cpl', '.ocx')

function Get-FileIndex {
    $idx = @{}
    foreach ($d in $FileScan) {
        if (-not $d.P -or -not (Test-Path -LiteralPath $d.P)) { continue }
        $items = if ($d.R) { Get-ChildItem -LiteralPath $d.P -File -Force -Recurse -ErrorAction SilentlyContinue }
                 else { Get-ChildItem -LiteralPath $d.P -File -Force -ErrorAction SilentlyContinue }
        foreach ($f in $items) {
            if ($f.FullName.StartsWith($WorkPath, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($f.FullName.StartsWith($BasePath, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($InputDir -and $f.FullName.StartsWith($InputDir, [StringComparison]::OrdinalIgnoreCase)) { continue }
            if ($OutputDir -and $f.FullName.StartsWith($OutputDir, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $idx[$f.FullName] = "$($f.Length)|$($f.LastWriteTimeUtc.Ticks)"
        }
    }
    $idx
}

function Get-Snapshot {
    $s = @{}
    $s.Services = Get-ServiceList
    $s.Drivers = Get-DriverList
    $s.Tasks = Get-TaskList
    $s.RunKeys = @(Get-RunEntries)
    $s.Startup = Get-StartupList
    $s.Hosts = Get-HostsLines
    $s.WmiSubscriptions = Get-WmiSubscriptionList
    $s.ComHijacks = Get-ComHijackList
    $s.AppInitDlls = Get-AppInitList
    $s.BitsJobs = Get-BitsJobList
    $s.PsProfiles = Get-PsProfileList
    $s.ActiveSetup = Get-ActiveSetupList
    $s.Firewall = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.DisplayName)|$($_.Direction)|$($_.Action)|$($_.Enabled)" })
    $s.Listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $n = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "$($_.LocalAddress):$($_.LocalPort) | $n" } | Select-Object -Unique)
    $s.UdpEndpoints = Get-UdpList
    $s.Defender = @(Get-DefenderState)
    $s.Files = Get-FileIndex
    $s
}

function Compare-Set($Before, $After) {
    $b = @{}
    foreach ($x in @($Before)) { if ($null -ne $x) { $b[[string]$x] = 1 } }
    @(@($After) | Where-Object { $null -ne $_ -and -not $b.ContainsKey([string]$_) })
}

# ------------------------------------------------------------------ process / network watch
$Procs = @{}
$TreePids = @{}
$Conns = @{}
$DnsSeen = @{}
$script:RootPid = $null
$MonitorNames = @('pktmon.exe', 'procmon.exe', 'procmon64.exe', 'wmiprvse.exe', 'conhost.exe', 'auditpol.exe', 'mitmdump.exe', 'windows-redirector.exe')
$SuspiciousCmdRx = '(?i)-enc(odedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|start-bitstransfer|add-mppreference|set-mppreference|-windowstyle\s+hidden|-w\s+hidden|vssadmin.*delete|bcdedit|wevtutil\s+cl|certutil.*(-urlcache|-decode)|bitsadmin.*/transfer|mshta\s+http|regsvr32.*/i:http|rundll32.*javascript|schtasks.*/create|reg\s+add.*\\run\b|netsh\s+advfirewall\s+set.*off|cmd.*/c.*del.*\\'

function Add-Proc([int]$ProcId, [int]$ParentId, [string]$Name, [string]$Path, [string]$Cmd, [string]$SeenAt = '') {
    $inTree = ($script:RootPid -and $ProcId -eq $script:RootPid) -or $TreePids.ContainsKey($ParentId)
    if ($inTree) { $TreePids[$ProcId] = 1 }
    $parent = if ($Procs.ContainsKey($ParentId)) { $Procs[$ParentId].Name } else { (Get-Process -Id $ParentId -ErrorAction SilentlyContinue).ProcessName }
    $ts = if ($SeenAt) { $SeenAt } else { (Get-Date).ToString('HH:mm:ss') }
    $rec = [pscustomobject]@{
        FirstSeen = $ts; Pid = $ProcId; Ppid = $ParentId; ParentName = $parent
        Name = $Name; Path = $Path; CommandLine = $Cmd; InTree = [bool]$inTree; Suspicious = [bool]($Cmd -and $Cmd -match $SuspiciousCmdRx)
    }
    $Procs[$ProcId] = $rec
    if ($MonitorNames -notcontains ([string]$Name).ToLower()) {
        $tag = ''
        if ($inTree) { $tag += '[sample] ' }
        if ($rec.Suspicious) { $tag += '[SUSPICIOUS] ' }
        Log "PROCESS $tag$Name pid=$ProcId ppid=$ParentId :: $Cmd"
    }
}

$UseTrace = $false
if ($isAdmin -and -not $TestMode) {
    try {
        Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier ProcStart -ErrorAction Stop | Out-Null
        $UseTrace = $true
    } catch { Log "process start trace unavailable: $($_.Exception.Message)" }
    try {
        & auditpol.exe /set /subcategory:"Process Creation" /success:enable 2>&1 | Out-Null
        $audKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        if (-not (Test-Path -LiteralPath $audKey)) { New-Item -Path $audKey -Force | Out-Null }
        Set-ItemProperty -LiteralPath $audKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    } catch {}
}

function Import-AuditProcesses([datetime]$Since) {
    if (-not $isAdmin -or $TestMode) { return }
    try {
        $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $Since.AddSeconds(-2) } -MaxEvents 400 -ErrorAction Stop
        foreach ($ev in ($evts | Sort-Object TimeCreated)) {
            try {
                [xml]$xml = $ev.ToXml()
                $map = @{}
                foreach ($d in $xml.Event.EventData.Data) { $map[$d.Name] = [string]$d.'#text' }
                $newPid = [Convert]::ToInt32(($map['NewProcessId'] -replace '^0x', ''), $(if ($map['NewProcessId'] -match '^0x') { 16 } else { 10 }))
                $parPid = [Convert]::ToInt32(($map['ProcessId'] -replace '^0x', ''), $(if ($map['ProcessId'] -match '^0x') { 16 } else { 10 }))
                $pPath = $map['NewProcessName']
                $pName = if ($pPath) { [IO.Path]::GetFileName($pPath) } else { '' }
                $cmd = $map['CommandLine']
                if ($newPid -eq $PID -or -not $pName) { continue }
                if ($Procs.ContainsKey($newPid) -and $Procs[$newPid].Name -eq $pName) {
                    $r = $Procs[$newPid]
                    if (-not $r.CommandLine -and $cmd) {
                        $r.CommandLine = $cmd
                        if (-not $r.Path) { $r.Path = $pPath }
                        $r.Suspicious = [bool]($cmd -match $SuspiciousCmdRx)
                        if ($r.Suspicious) { Log "AUDIT4688 SUSPICIOUS pid=${newPid}: $cmd" }
                    }
                } else {
                    Add-Proc $newPid $parPid $pName $pPath $cmd $ev.TimeCreated.ToString('HH:mm:ss')
                }
            } catch {}
        }
    } catch {}
}

function Update-Watch([datetime]$Since) {
    if ($UseTrace) {
        foreach ($e in @(Get-Event -SourceIdentifier ProcStart -ErrorAction SilentlyContinue)) {
            $ne = $e.SourceEventArgs.NewEvent
            $procId = [int]$ne.ProcessID
            if (-not $Procs.ContainsKey($procId) -or $Procs[$procId].Name -ne $ne.ProcessName) {
                Add-Proc $procId ([int]$ne.ParentProcessID) $ne.ProcessName $null $null
            }
            Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
        }
    }
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -and $_.CreationDate -ge $Since } | Sort-Object CreationDate)
    foreach ($p in $all) {
        $procId = [int]$p.ProcessId
        if ($procId -eq $PID) { continue }
        if ($Procs.ContainsKey($procId) -and $Procs[$procId].Name -eq $p.Name) {
            $r = $Procs[$procId]
            if (-not $r.CommandLine -and $p.CommandLine) {
                $r.CommandLine = $p.CommandLine; $r.Path = $p.ExecutablePath
                $r.Suspicious = [bool]($p.CommandLine -match $SuspiciousCmdRx)
                if ($r.Suspicious) { Log "SUSPICIOUS command line pid=${procId}: $($p.CommandLine)" }
            }
        } else {
            Add-Proc $procId ([int]$p.ParentProcessId) $p.Name $p.ExecutablePath $p.CommandLine
        }
    }
    foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        if ("$($c.State)" -in 'Listen', 'Bound') { continue }
        $ra = [string]$c.RemoteAddress
        if ($ra -in '0.0.0.0', '::', '127.0.0.1', '::1' -or $ra.StartsWith('fe80')) { continue }
        $pname = if ($Procs.ContainsKey([int]$c.OwningProcess)) { $Procs[[int]$c.OwningProcess].Name } else { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
        $key = "$ra|$($c.RemotePort)|$pname"
        if (-not $Conns.ContainsKey($key)) {
            $fromSample = $TreePids.ContainsKey([int]$c.OwningProcess)
            $Conns[$key] = [pscustomobject]@{ FirstSeen = (Get-Date).ToString('HH:mm:ss'); Remote = $ra; Port = [int]$c.RemotePort
                Process = $pname; Pid = [int]$c.OwningProcess; FromSample = $fromSample; State = "$($c.State)" }
            Log "CONNECTION $(if ($fromSample) { '[sample] ' })$pname -> ${ra}:$($c.RemotePort) ($($c.State))"
        }
    }
    foreach ($d in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        $k = [string]$d.Entry
        if ($k -and -not $DnsSeen.ContainsKey($k)) {
            $DnsSeen[$k] = [pscustomobject]@{ FirstSeen = (Get-Date).ToString('HH:mm:ss'); Name = $k; Data = [string]$d.Data }
        }
    }
}

# live.json for the host panel (quick persistence diff every 30 s; file-system diff only at the end)
$script:LastQuick = [datetime]::MinValue
$script:Quick = $null
function Write-Live([int]$SecondsLeft, [string]$Phase) {
    if (((Get-Date) - $script:LastQuick).TotalSeconds -ge 30) {
        $script:LastQuick = Get-Date
        $script:Quick = [ordered]@{
            Services = @((Split-ServiceDiff $before.Services (Get-ServiceList)).New)
            Tasks    = @(Compare-Set $before.Tasks (Get-TaskList))
            RunKeys  = @(Compare-Set $before.RunKeys @(Get-RunEntries))
            Startup  = @(Compare-Set $before.Startup (Get-StartupList))
            Defender = @(Compare-Set $before.Defender @(Get-DefenderState))
            Hosts    = @(Compare-Set $before.Hosts (Get-HostsLines))
        }
    }
    $visible = @($Procs.Values | Where-Object { $MonitorNames -notcontains ([string]$_.Name).ToLower() })
    $live = [ordered]@{
        Updated            = (Get-Date).ToString('HH:mm:ss')
        Phase              = $Phase
        SecondsLeft        = $SecondsLeft
        Target             = $script:TargetRel
        TargetNote         = $script:TargetNote
        ProcessCount       = $visible.Count
        SampleProcessCount = @($visible | Where-Object { $_.InTree }).Count
        SuspiciousCount    = @($visible | Where-Object { $_.Suspicious }).Count
        ConnectionCount    = $Conns.Count
        RunMode            = $script:RunMode
        LanBlock           = $script:LanBlock
        Processes          = @($visible | Sort-Object @{ E = { -not $_.Suspicious } }, @{ E = { -not $_.InTree } }, @{ E = { $_.FirstSeen }; Descending = $true } | Select-Object -First 150)
        Connections        = @($Conns.Values | Sort-Object @{ E = { -not $_.FromSample } }, @{ E = { $_.FirstSeen }; Descending = $true } | Select-Object -First 150)
        Quick              = $script:Quick
    }
    Write-JsonFile 'live.json' $live 5
}

# ------------------------------------------------------------------ 1. copy sample + honeyfiles + baseline
$sampleFiles = @(Get-ChildItem -LiteralPath $InputDir -Recurse -File -Force -ErrorAction SilentlyContinue)
$sampleBytes = [double](($sampleFiles | Measure-Object -Property Length -Sum).Sum)
$sampleMB = [math]::Round($sampleBytes / 1MB, 1)
$copyMax = if ($cfg.PSObject.Properties['CopyMaxMB'] -and $cfg.CopyMaxMB) { [double]$cfg.CopyMaxMB } else { 1024 }
if ($sampleBytes -le $copyMax * 1MB) {
    Set-Status 'Ornek sandbox icine kopyalaniyor'
    Log "Copying sample ($sampleMB MB, read-only share -> sandbox disk)..."
    Copy-Item -Path (Join-Path $InputDir '*') -Destination $SampleDir -Recurse -Force -ErrorAction SilentlyContinue
    Log "Copied $(@(Get-ChildItem -LiteralPath $SampleDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count) files."
    $script:RunMode = 'copied'
} else {
    $SampleDir = (Get-Item -LiteralPath $InputDir).FullName
    Log "Sample is $sampleMB MB (> $copyMax MB): running in place from the read-only share, no copy."
    $script:RunMode = 'in-place (read-only share)'
}

$DeprioritizeRx = '(?i)(uninst|unins\d|crash|helper|vc_?redist|vcredist|dotnet|ndp\d|directx|dxsetup|redist|updater|elevat|report|cleanup|repair)'
$InstallerRx = '(?i)^(set-?up|install)'
# Disc menus only show an "Install" button (often custom-drawn, so it cannot be auto-clicked): the real installer
# they would start is picked first when there is one.
$LauncherRx = '(?i)^(autorun|autoplay|start)'
$CrackRx = '(?i)(patch|crack|loader|activat|keygen|genp)'
function Get-TargetRank($f) {
    if ($f.Extension.ToLower() -eq '.dll') { return 10 }
    if ($f.Name -match $DeprioritizeRx) { return 9 }
    if ($f.Name -match $InstallerRx) { return 0 }
    if ($f.Name -match $LauncherRx) { return 1 }
    if ($f.Name -match $CrackRx) { return 2 }
    return 5
}

$RunnableExts = @('.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.com', '.lnk', '.pif', '.jar', '.reg', '.dll')

function Find-Runnable([string]$Root) {
    $c = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $RunnableExts -contains $_.Extension.ToLower() })
    if (-not $c.Count) { return $null }
    $c | Sort-Object @{ E = { Get-TargetRank $_ } },
                     @{ E = { if ($_.Extension -in '.exe', '.msi') { 0 } else { 1 } } },
                     @{ E = { $_.FullName.Substring($Root.Length).Split('\').Count } },
                     @{ E = { $_.Length }; Descending = $true } | Select-Object -First 1
}

# Disc images (.iso/.img) are mounted read-only when the sample has nothing runnable at the top level, e.g. a
# download folder that holds only "Product.iso" plus checksum files. Mounting straight from the shared folder can
# fail, so the image is copied to the sandbox disk first in that case.
$script:MountedRoots = @()
$script:TargetNote = ''
function Mount-SampleImage([string]$ImagePath) {
    foreach ($attempt in 1..2) {
        $src = $ImagePath
        if ($attempt -eq 2) {
            $local = Join-Path $WorkPath ('img_' + [IO.Path]::GetFileName($ImagePath))
            Log "Copying image to the sandbox disk before mounting: $([IO.Path]::GetFileName($ImagePath))"
            Set-Status 'Disk goruntusu sandbox diskine kopyalaniyor'
            try { Copy-Item -LiteralPath $ImagePath -Destination $local -Force -ErrorAction Stop } catch { return "copy failed: $($_.Exception.Message)" }
            $src = $local
        }
        try {
            $null = Mount-DiskImage -ImagePath $src -StorageType ISO -Access ReadOnly -PassThru -ErrorAction Stop
            $vol = $null
            foreach ($i in 1..20) {
                $vol = Get-DiskImage -ImagePath $src -ErrorAction SilentlyContinue | Get-Volume -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($vol -and $vol.DriveLetter) { break }
                Start-Sleep -Milliseconds 500
            }
            if (-not $vol) {
                # CD-ROM volumes are not always linked back to the image: look for an unlettered CD-ROM volume
                $vol = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'CD-ROM' -and -not $_.DriveLetter } | Select-Object -First 1
            }
            Log ("Mount result: volume=" + [bool]$vol + " letter=" + $(if ($vol) { $vol.DriveLetter } else { '' }) + " path=" + $(if ($vol) { $vol.Path } else { '' }))
            if (-not $vol) { $err = 'mounted but no volume found'; continue }
            $root = $null
            if ($vol.DriveLetter) { $root = "$($vol.DriveLetter):\" }
            else {
                # Windows Sandbox does not auto-assign letters: pick a free one and assign it with mountvol
                $used = @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpper() })
                $free = @('R','S','T','U','V','W','X','Y','Z') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
                if ($free -and $vol.Path) {
                    $mv = & mountvol.exe "${free}:" $vol.Path 2>&1
                    Log "mountvol ${free}: $($vol.Path) -> exit $LASTEXITCODE $($mv -join ' ')"
                    if (Test-Path -LiteralPath "${free}:\") { $root = "${free}:\" }
                }
                if (-not $root -and $vol.Path -and (Test-Path -LiteralPath $vol.Path)) { $root = $vol.Path }   # \?\Volume{...}\ without a letter
            }
            if (-not $root) { $err = 'mounted but no drive letter could be assigned'; continue }
            $script:MountedRoots += [pscustomobject]@{ Root = $root; Image = [IO.Path]::GetFileName($ImagePath) }
            Log "Mounted image $([IO.Path]::GetFileName($ImagePath)) as $root (attempt $attempt)"
            return $null
        } catch {
            $err = $_.Exception.Message
            Log "Mount attempt $attempt failed for $([IO.Path]::GetFileName($ImagePath)): $err"
        }
    }
    return $err
}

function Resolve-Target {
    if ($cfg.Target) {
        $p = Join-Path $SampleDir $cfg.Target
        if (Test-Path -LiteralPath $p) { return (Get-Item -LiteralPath $p) }
        foreach ($m in $script:MountedRoots) {
            $p2 = Join-Path $m.Root $cfg.Target
            if (Test-Path -LiteralPath $p2) { return (Get-Item -LiteralPath $p2) }
        }
        Log "Configured target not found: $($cfg.Target) - falling back to auto-pick"
    }
    $hit = Find-Runnable $SampleDir
    if ($hit) { return $hit }
    foreach ($m in $script:MountedRoots) {
        $hit = Find-Runnable $m.Root
        if ($hit) { return $hit }
    }
    return $null
}

if (-not (Find-Runnable $SampleDir)) {
    $images = @(Get-ChildItem -LiteralPath $SampleDir -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLower() -in '.iso', '.img' } | Sort-Object Length -Descending | Select-Object -First 3)
    $mountErrors = @()
    foreach ($im in $images) {
        if (-not $isAdmin) { $mountErrors += "$($im.Name): not admin"; continue }
        $e = Mount-SampleImage $im.FullName
        if ($e) { $mountErrors += "$($im.Name): $e" }
    }
    if ($script:MountedRoots.Count) {
        $script:TargetNote = "Disk goruntusu baglandi: " + (($script:MountedRoots | ForEach-Object { "$($_.Image) -> $($_.Root)" }) -join ', ')
    } elseif ($mountErrors.Count) {
        $script:TargetNote = "Disk goruntusu baglanamadi: " + ($mountErrors -join '; ')
    } elseif (-not $images.Count) {
        $script:TargetNote = 'Ornekte calistirilabilir dosya ya da disk goruntusu (.iso/.img) yok.'
    }
}

# ------------------------------------------------------------------ home-network (LAN) block
# Private ranges and gateway are blocked; only DNS server IPs are exempted and restricted strictly to port 53 (TCP/UDP).
$script:LanBlock = [ordered]@{ Requested = [bool]$cfg.BlockLan; Applied = $false; Exempt = @(); Ranges = @(); Tampered = $false; Details = @(); Status = 'not requested' }
$LanRuleNames = @('SafeBox-BlockLAN-Out', 'SafeBox-BlockLAN-In')
$DnsRestrictRules = @('SafeBox-BlockDNS-TCP', 'SafeBox-BlockDNS-UDP')
$PrivateIpRx = '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)'

function ConvertTo-IpNum([string]$ip) { $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [uint64]$b[0] * 16777216 + [uint64]$b[1] * 65536 + [uint64]$b[2] * 256 + [uint64]$b[3] }
function ConvertFrom-IpNum([uint64]$n) { '{0}.{1}.{2}.{3}' -f ([math]::Floor($n / 16777216) % 256), ([math]::Floor($n / 65536) % 256), ([math]::Floor($n / 256) % 256), ($n % 256) }

function Get-LanRanges([string[]]$ExemptDns) {
    $cidrs = @(@('10.0.0.0', 8), @('172.16.0.0', 12), @('192.168.0.0', 16), @('169.254.0.0', 16), @('100.64.0.0', 10))
    $ex = @($ExemptDns | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | ForEach-Object { ConvertTo-IpNum $_ } | Sort-Object -Unique)
    foreach ($c in $cidrs) {
        $start = ConvertTo-IpNum $c[0]
        $end = $start + [uint64][math]::Pow(2, 32 - $c[1]) - 1
        $cur = $start
        foreach ($e in ($ex | Where-Object { $_ -ge $start -and $_ -le $end })) {
            if ($e -gt $cur) { if ($e -eq ($cur + 1)) { ConvertFrom-IpNum $cur } else { "$(ConvertFrom-IpNum $cur)-$(ConvertFrom-IpNum ($e - 1))" } }
            $cur = $e + 1
        }
        if ($cur -le $end) { if ($cur -eq $end) { ConvertFrom-IpNum $cur } else { "$(ConvertFrom-IpNum $cur)-$(ConvertFrom-IpNum $end)" } }
    }
    $v6dns = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -match '^f[cd]' })
    if (-not $v6dns.Count) { 'fc00::/7' }
    'fe80::/10'
}

$script:PrivateDnsList = @()
function Set-LanBlock {
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
    $script:LanBlock.Exempt = @($dns)
    $script:LanBlock.Ranges = @(Get-LanRanges $script:LanBlock.Exempt)
    $script:PrivateDnsList = @($dns | Where-Object { $_ -match $PrivateIpRx })
    foreach ($n in ($LanRuleNames + $DnsRestrictRules)) { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
    Set-NetFirewallProfile -All -Enabled True -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $LanRuleNames[0] -DisplayName 'SafeBox: block home network (outbound)' -Direction Outbound -Action Block -RemoteAddress $script:LanBlock.Ranges -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name $LanRuleNames[1] -DisplayName 'SafeBox: block home network (inbound)' -Direction Inbound -Action Block -RemoteAddress $script:LanBlock.Ranges -Profile Any -ErrorAction Stop | Out-Null
    if ($script:PrivateDnsList.Count) {
        New-NetFirewallRule -Name $DnsRestrictRules[0] -DisplayName 'SafeBox: DNS IP non-53 TCP block' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $script:PrivateDnsList -RemotePort @('1-52', '54-65535') -Profile Any -ErrorAction Stop | Out-Null
        New-NetFirewallRule -Name $DnsRestrictRules[1] -DisplayName 'SafeBox: DNS IP non-53 UDP block' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress $script:PrivateDnsList -RemotePort @('1-52', '54-65535') -Profile Any -ErrorAction Stop | Out-Null
    }
    $script:LanBlock.Applied = $true
}

function Test-LanBlock {
    if (-not $script:LanBlock.Applied) { return }
    $bad = @()
    $toCheck = @($LanRuleNames)
    if ($script:PrivateDnsList.Count) { $toCheck += $DnsRestrictRules }
    foreach ($n in $toCheck) {
        $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
        if (-not $r) { $bad += "$n removed" }
        elseif ("$($r.Enabled)" -ne 'True' -or "$($r.Action)" -ne 'Block') { $bad += "$n disabled or changed" }
    }
    $bad += @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { "firewall profile $($_.Name) turned off" })
    if ($bad.Count) {
        $script:LanBlock.Tampered = $true
        $script:LanBlock.Details = @(@($script:LanBlock.Details) + $bad | Select-Object -Unique)
        Log "LAN BLOCK TAMPERED: $($bad -join ', ') - re-applying"
        try { Set-LanBlock } catch { Log "re-apply failed: $($_.Exception.Message)" }
    }
}

if ($script:LanBlock.Requested -and $isAdmin -and -not $TestMode) {
    try {
        Set-LanBlock
        $script:LanBlock.Status = "active (dns-only-53 exempt: $($script:LanBlock.Exempt -join ', '))"
        Log "Home network blocked (gateway blocked, DNS port 53 only): $($script:LanBlock.Ranges -join ', ')"
    } catch { $script:LanBlock.Status = "FAILED: $($_.Exception.Message)"; Log "LAN block failed: $($_.Exception.Message)" }
} elseif ($script:LanBlock.Requested) { $script:LanBlock.Status = 'skipped (not admin or test mode)' }

$targetFile = Resolve-Target
$script:TargetRel = $null
if ($targetFile) {
    $mr = $script:MountedRoots | Where-Object { $targetFile.FullName.StartsWith($_.Root, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if ($mr) { $script:TargetRel = "[$($mr.Image)] " + $targetFile.FullName.Substring($mr.Root.Length) }
    else { $script:TargetRel = $targetFile.FullName.Substring($SampleDir.Length).TrimStart('\') }
    Log "Target: $($targetFile.FullName)"
} else { Log "No runnable file found - only observing the system. $($script:TargetNote)" }

Initialize-Honeyfiles

Set-Status 'Temiz sistem goruntusu (baseline) aliniyor'
# HTTPS decryption: block QUIC (HTTP/3 over UDP 443) so browsers and Chromium/Go programs fall back to TCP, which
# the decryptor sees. Created before the baseline, like the LAN block, so it is not reported as a change.
$script:QuicBlocked = $false
if ($cfg.DecryptHttps -and -not $TestMode) {
    try {
        New-NetFirewallRule -Name 'SafeBox-BlockQUIC' -DisplayName 'SafeBox: block QUIC (UDP 443) for HTTPS decryption' -Direction Outbound -Action Block -Protocol UDP -RemotePort 443 -Profile Any -ErrorAction Stop | Out-Null
        $script:QuicBlocked = $true
        Log 'QUIC (UDP 443) blocked so HTTPS goes over TCP to the decryptor'
    } catch { Log "QUIC block failed: $($_.Exception.Message)" }
}

Log 'Baseline snapshot...'
$before = Get-Snapshot
Log "Baseline: $($before.Files.Count) files, $($before.Services.Count) services, $($before.Tasks.Count) tasks"

# ------------------------------------------------------------------ 2. capture
$etl = Join-Path $WorkPath 'capture.etl'
$pcap = Join-Path $OutputDir 'capture.pcapng'
$captureStatus = 'not started'
if ($isAdmin -and -not $TestMode) {
    & pktmon.exe stop 2>&1 | Out-Null
    & pktmon.exe filter remove 2>&1 | Out-Null
    $o = & pktmon.exe start --capture --comp nics --pkt-size 4096 --file-name $etl --file-size 2048 2>&1
    if ($LASTEXITCODE -eq 0) { $captureStatus = 'running'; Log 'pktmon capture started (pkt-size 4096, max 2GB)' } else { $captureStatus = "pktmon failed: $($o -join ' ')"; Log $captureStatus }
} else { $captureStatus = 'skipped (not admin or test mode)'; Log "Capture $captureStatus" }

$procmon = $null
foreach ($pm in 'Procmon64.exe', 'Procmon.exe') { $pp = Join-Path $ToolsDir $pm; if (Test-Path -LiteralPath $pp) { $procmon = $pp; break } }
$pml = Join-Path $WorkPath 'procmon.pml'
if ($procmon -and -not $TestMode) {
    Start-Process -FilePath $procmon -ArgumentList "/AcceptEula /Quiet /Minimized /BackingFile `"$pml`""
    Start-Sleep -Seconds 6
    Log 'Process Monitor started'
}

# ------------------------------------------------------------------ live process memory scan + fakenet
if (-not $TestMode) {
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public static class SafeBoxMem {
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    private static readonly string[] Indicators = new string[] {
        "api.telegram.org/bot",
        "discord.com/api/webhooks",
        "stratum+tcp://",
        "sekurlsa::",
        "vssadmin",
        "AmsiScanBuffer",
        "Add-MpPreference",
        "NtUnmapViewOfSection"
    };

    private static readonly Regex UrlRx = new Regex(
        @"https?://[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(?::\d+)?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex BenignUrlRx = new Regex(
        @"^https?://([^/]+\.)?(microsoft\.com|windowsupdate\.com|aka\.ms|w3\.org|xmlsoap\.org|digicert\.com|verisign\.com|globalsign\.com|sectigo\.com|comodoca\.com|entrust\.net|letsencrypt\.org|pki\.goog|symantec\.com|thawte\.com|geotrust\.com|adobe\.com|localhost|127\.0\.0\.1)(:|/|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static void ScanText(string text, string procTag, HashSet<string> seen, List<string> findings) {
        if (string.IsNullOrEmpty(text)) return;
        for (int i = 0; i < Indicators.Length; i++) {
            if (findings.Count >= 200) return;
            string ind = Indicators[i];
            if (text.IndexOf(ind, StringComparison.OrdinalIgnoreCase) >= 0) {
                string entry = procTag + " " + ind;
                if (seen.Add(entry)) findings.Add(entry);
            }
        }
        MatchCollection matches = UrlRx.Matches(text);
        for (int i = 0; i < matches.Count && findings.Count < 200; i++) {
            string u = matches[i].Value;
            if (u.Length > 180) u = u.Substring(0, 180);
            if (BenignUrlRx.IsMatch(u)) continue;
            string entry = procTag + " " + u;
            if (seen.Add(entry)) findings.Add(entry);
        }
    }

    // Writes the process's private and executable memory (where unpacked / injected code lives) to a file,
    // XOR-encoded with key so the host's antivirus does not flag or delete the dump before it is scanned.
    // Mapped data files are skipped. Returns the number of bytes written.
    public static long DumpProcess(int pid, string path, long maxBytes, byte[] key) {
        IntPtr hProc = OpenProcess(0x0410, false, pid);
        if (hProc == IntPtr.Zero) return 0;
        long written = 0;
        try {
            using (System.IO.FileStream fs = new System.IO.FileStream(path, System.IO.FileMode.Create, System.IO.FileAccess.Write)) {
                long addr = 0;
                long maxAddr = IntPtr.Size == 8 ? 0x7FFFFFFEFFFFL : 0x7FFEFFFFL;
                uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                byte[] buf = new byte[1048576];
                while (addr < maxAddr && written < maxBytes) {
                    MEMORY_BASIC_INFORMATION mbi;
                    UIntPtr q = VirtualQueryEx(hProc, new IntPtr(addr), out mbi, mbiSize);
                    if (q == UIntPtr.Zero) break;
                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;
                    long baseAddr = mbi.BaseAddress.ToInt64();
                    long nextAddr = baseAddr + regionSize;
                    if (nextAddr <= addr) break;
                    bool committed = mbi.State == 0x1000;
                    bool noAccess = (mbi.Protect & 0x01) != 0;
                    bool guard = (mbi.Protect & 0x100) != 0;
                    bool readable = (mbi.Protect & 0xEE) != 0;
                    bool executable = (mbi.Protect & 0xF0) != 0;
                    bool isPrivate = mbi.Type == 0x20000;
                    if (committed && !noAccess && !guard && readable && (isPrivate || executable)) {
                        long offset = 0;
                        while (offset < regionSize && written < maxBytes) {
                            int toRead = (int)Math.Min(buf.Length, Math.Min(regionSize - offset, maxBytes - written));
                            if (toRead <= 0) break;
                            IntPtr bytesRead;
                            if (ReadProcessMemory(hProc, new IntPtr(baseAddr + offset), buf, toRead, out bytesRead)) {
                                int n = bytesRead.ToInt32();
                                for (int i = 0; i < n; i++) { buf[i] = (byte)(buf[i] ^ key[(written + i) % key.Length]); }
                                if (n > 0) { fs.Write(buf, 0, n); written += n; }
                            }
                            offset += toRead;
                        }
                    }
                    addr = nextAddr;
                }
            }
        } catch {
        } finally {
            CloseHandle(hProc);
        }
        return written;
    }

    public static string[] ScanProcess(int pid, string procName, int maxBytes) {
        List<string> findings = new List<string>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IntPtr hProc = OpenProcess(0x0410, false, pid);
        if (hProc == IntPtr.Zero) return findings.ToArray();
        string procTag = "[" + (string.IsNullOrEmpty(procName) ? "pid" : procName) + ":" + pid.ToString() + "]";
        try {
            long addr = 0;
            long maxAddr = IntPtr.Size == 8 ? 0x7FFFFFFEFFFFL : 0x7FFEFFFFL;
            long totalRead = 0;
            uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            byte[] buf = new byte[1048576];
            while (addr < maxAddr && totalRead < maxBytes && findings.Count < 200) {
                MEMORY_BASIC_INFORMATION mbi;
                UIntPtr q = VirtualQueryEx(hProc, new IntPtr(addr), out mbi, mbiSize);
                if (q == UIntPtr.Zero) break;
                long regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;
                long baseAddr = mbi.BaseAddress.ToInt64();
                long nextAddr = baseAddr + regionSize;
                if (nextAddr <= addr) break;

                bool committed = mbi.State == 0x1000;
                bool noAccess = (mbi.Protect & 0x01) != 0;
                bool guard = (mbi.Protect & 0x100) != 0;
                bool readable = (mbi.Protect & 0xEE) != 0;

                if (committed && !noAccess && !guard && readable) {
                    long offset = 0;
                    while (offset < regionSize && totalRead < maxBytes && findings.Count < 200) {
                        int toRead = (int)Math.Min(buf.Length, Math.Min(regionSize - offset, maxBytes - totalRead));
                        if (toRead <= 0) break;
                        IntPtr bytesRead;
                        if (ReadProcessMemory(hProc, new IntPtr(baseAddr + offset), buf, toRead, out bytesRead)) {
                            int n = bytesRead.ToInt32();
                            if (n > 0) {
                                totalRead += n;
                                string asciiStr = Encoding.ASCII.GetString(buf, 0, n);
                                ScanText(asciiStr, procTag, seen, findings);
                                string uniStr = Encoding.Unicode.GetString(buf, 0, n);
                                ScanText(uniStr, procTag, seen, findings);
                            }
                        }
                        offset += toRead;
                    }
                }
                addr = nextAddr;
            }
        } finally {
            CloseHandle(hProc);
        }
        return findings.ToArray();
    }
}
"@ -ErrorAction SilentlyContinue
    } catch {}
}

# Memory dumps of the sample's processes for YARA on the host (unpacked / decrypted code is only in memory).
# Same XOR key as pipeline.MEMDUMP_KEY. Caps: 64 MB per process, 192 MB in total, 6 processes.
$MemDumpKey = [Text.Encoding]::ASCII.GetBytes('SafeBoxMemDump!7')
function Dump-ProcessMemory {
    if ($TestMode) { return @() }
    $dir = Join-Path $OutputDir 'memdumps'
    $out = @()
    try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch { return @() }
    $total = [long]0
    $pids = @($TreePids.Keys | ForEach-Object { [int]$_ } | Where-Object { $_ -gt 0 -and $_ -ne $PID } | Select-Object -Unique)
    foreach ($tpid in $pids) {
        if ($out.Count -ge 6 -or $total -ge 201326592) { break }
        $p = Get-Process -Id $tpid -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $pname = [string]$p.ProcessName
        if ($MonitorNames -contains ($pname.ToLower() + '.exe')) { continue }
        $safe = ($pname -replace '[^A-Za-z0-9_.-]', '_')
        if ($safe.Length -gt 60) { $safe = $safe.Substring(0, 60) }
        $file = Join-Path $dir ("{0}_{1}.xbin" -f $safe, $tpid)
        try {
            $cap = [Math]::Min([long]67108864, [long]201326592 - $total)
            $n = [SafeBoxMem]::DumpProcess($tpid, $file, $cap, $MemDumpKey)
            if ($n -gt 0) { $total += $n; $out += "$safe.exe pid=$tpid $([Math]::Round($n / 1MB, 1)) MB" }
            else { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
    if ($out.Count) { Log ("Memory dumps: " + ($out -join '; ')) }
    return $out
}

# Early dumps: stealers often take what they want and exit within seconds, long before the end-of-run dump.
# Every sample process is dumped once, while still alive, as soon as it has run for 6 s (budget: 8 processes,
# 48 MB each, 128 MB in total; separate from the end-of-run dump).
$script:EarlyDumped = @{}
$script:EarlyDumpTotal = [long]0
$script:EarlyDumpList = New-Object System.Collections.ArrayList
function Dump-EarlySample {
    if ($TestMode -or $script:EarlyDumped.Count -ge 8 -or $script:EarlyDumpTotal -ge 134217728) { return }
    $dir = Join-Path $OutputDir 'memdumps'
    foreach ($k in @($TreePids.Keys)) {
        $tpid = [int]$k
        if ($tpid -le 0 -or $tpid -eq $PID -or $script:EarlyDumped.ContainsKey($tpid)) { continue }
        if ($script:EarlyDumped.Count -ge 8 -or $script:EarlyDumpTotal -ge 134217728) { break }
        $p = Get-Process -Id $tpid -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        $age = 0
        try { $age = ((Get-Date) - $p.StartTime).TotalSeconds } catch { $age = 999 }
        if ($age -lt 6) { continue }
        $pname = [string]$p.ProcessName
        $script:EarlyDumped[$tpid] = 1
        if ($MonitorNames -contains ($pname.ToLower() + '.exe')) { continue }
        $safe = ($pname -replace '[^A-Za-z0-9_.-]', '_')
        if ($safe.Length -gt 60) { $safe = $safe.Substring(0, 60) }
        try {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $file = Join-Path $dir ("{0}_{1}_early.xbin" -f $safe, $tpid)
            $cap = [Math]::Min([long]50331648, [long]134217728 - $script:EarlyDumpTotal)
            $n = [SafeBoxMem]::DumpProcess($tpid, $file, $cap, $MemDumpKey)
            if ($n -gt 0) {
                $script:EarlyDumpTotal += $n
                $line = "$safe.exe pid=$tpid early $([Math]::Round($n / 1MB, 1)) MB at $([int]$age) s"
                [void]$script:EarlyDumpList.Add($line)
                Log "Memory dump: $line"
            } else { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
}

function Scan-ProcessMemory {
    $all = New-Object System.Collections.ArrayList
    $seen = @{}
    if ($TestMode) { return @() }
    $pids = @($TreePids.Keys | ForEach-Object { [int]$_ } | Where-Object { $_ -gt 0 -and $_ -ne $PID } | Select-Object -Unique -First 8)
    foreach ($tpid in $pids) {
        try {
            $pname = if ($Procs.ContainsKey($tpid)) { [string]$Procs[$tpid].Name } else { [string](Get-Process -Id $tpid -ErrorAction SilentlyContinue).ProcessName }
            $hits = [SafeBoxMem]::ScanProcess($tpid, $pname, 33554432)
            foreach ($h in $hits) {
                if ($h -and -not $seen.ContainsKey($h) -and $all.Count -lt 200) {
                    $seen[$h] = 1
                    [void]$all.Add($h)
                }
            }
        } catch {}
    }
    if ($all.Count -gt 0) { Log "Memory scan findings: $($all.Count)" }
    return @($all)
}

# Program crashes Windows recorded while the sample ran: "Application Error" 1000 events, joined with the
# "Windows Error Reporting" 1001 BEX/APPCRASH event of the same crash for the fast-fail code (P9).
# Read from the event properties, never the message text: that is in the sandbox's display language.
function Get-CrashEvents([datetime]$Since) {
    $byKey = [ordered]@{}
    $evs = @()
    try { $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $Since } -ErrorAction Stop) } catch {}
    foreach ($e in $evs) {
        $p = $e.Properties
        if ($p.Count -lt 11) { continue }
        $code = ([string]$p[6].Value).ToLower() -replace '^0x', ''
        $off = ([string]$p[7].Value).ToLower() -replace '^0x', ''
        $key = '{0}|{1}|{2}|{3}' -f ([string]$p[0].Value).ToLower(), ([string]$p[3].Value).ToLower(), $code, $off
        if (-not $byKey.Contains($key)) {
            $byKey[$key] = [ordered]@{ App = [string]$p[0].Value; Version = [string]$p[1].Value; Module = [string]$p[3].Value
                                       Code = $code; Offset = $off; Path = [string]$p[10].Value; FastFail = ''; Count = 0
                                       First = $e.TimeCreated.ToString('HH:mm:ss') }
        }
        $byKey[$key].Count++
    }
    $wer = @()
    try { $wer = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $Since } -ErrorAction Stop) } catch {}
    foreach ($e in $wer) {
        $p = $e.Properties
        if ($p.Count -lt 14 -or ([string]$p[2].Value) -notmatch '^(BEX|BEX64|APPCRASH)$') { continue }
        $code = ([string]$p[12].Value).ToLower() -replace '^0x', ''
        $off = ([string]$p[11].Value).ToLower() -replace '^0x', ''
        $key = '{0}|{1}|{2}|{3}' -f ([string]$p[5].Value).ToLower(), ([string]$p[8].Value).ToLower(), $code, $off
        $ff = [string]$p[13].Value
        if ($byKey.Contains($key) -and $code -eq 'c0000409' -and $ff -match '^[0-9a-fA-F]{1,16}$') {
            $byKey[$key].FastFail = [string][Convert]::ToInt64($ff, 16)
        }
    }
    $out = @()
    foreach ($c in $byKey.Values) {
        $offTxt = $c.Offset.TrimStart('0'); if (-not $offTxt) { $offTxt = '0' }
        $line = "$($c.App) $($c.Version) | module $($c.Module) | code 0x$($c.Code)"
        if ($c.FastFail) { $line += " | fastfail $($c.FastFail)" }
        $line += " | offset 0x$offTxt | x$($c.Count) | first $($c.First) | $($c.Path)"
        $out += $line
        Log "CRASH $line"
    }
    return $out
}

$script:FakeNetLog = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:FakeNetState = [hashtable]::Synchronized(@{ Stop = $false; Log = $script:FakeNetLog; Udp = $null; Tcp = $null })
$script:FakeNetWorkers = @()
$script:FakeNetOrigDns = @()

function Start-FakeNet {
    if (-not $FakeNet -or $TestMode) { return }
    $script:FakeNetState.Stop = $false
    $dnsScript = {
        param($state)
        try {
            $udp = New-Object System.Net.Sockets.UdpClient([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 53))
            $udp.Client.ReceiveTimeout = 500
            $state.Udp = $udp
            while (-not $state.Stop) {
                try {
                    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $req = $udp.Receive([ref]$ep)
                    if (-not $req -or $req.Length -lt 17) { continue }
                    $pos = 12
                    $labels = @()
                    while ($pos -lt $req.Length) {
                        $len = [int]$req[$pos]
                        $pos++
                        if ($len -eq 0) { break }
                        if (($len -band 0xC0) -ne 0 -or ($pos + $len) -gt $req.Length) { break }
                        $labels += [System.Text.Encoding]::ASCII.GetString($req, $pos, $len)
                        $pos += $len
                    }
                    $qname = ($labels -join '.').Trim()
                    $qend = $pos + 4
                    if ($qend -gt $req.Length) { continue }
                    $qtype = ([int]$req[$pos] * 256) + [int]$req[$pos + 1]
                    $ms = New-Object System.IO.MemoryStream
                    $anc = if ($qtype -eq 1) { [byte]1 } else { [byte]0 }
                    $hdr = [byte[]]@($req[0], $req[1], 0x81, 0x80, 0x00, 0x01, 0x00, $anc, 0x00, 0x00, 0x00, 0x00)
                    $ms.Write($hdr, 0, 12)
                    $ms.Write($req, 12, ($qend - 12))
                    if ($qtype -eq 1) {
                        $ans = [byte[]]@(0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0x7F, 0x00, 0x00, 0x01)
                        $ms.Write($ans, 0, $ans.Length)
                    }
                    $resp = $ms.ToArray()
                    $ms.Dispose()
                    [void]$udp.Send($resp, $resp.Length, $ep)
                    if ($qname -and $state.Log.Count -lt 200) {
                        [void]$state.Log.Add("DNS $qname -> 127.0.0.1 (qtype=$qtype)")
                    }
                } catch {}
            }
        } catch {}
    }

    $httpScript = {
        param($state)
        try {
            $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 80)
            $tcp.Start()
            $state.Tcp = $tcp
            $okBytes = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: 2`r`nConnection: close`r`n`r`nok")
            while (-not $state.Stop) {
                try {
                    if (-not $tcp.Pending()) {
                        Start-Sleep -Milliseconds 100
                        continue
                    }
                    $client = $tcp.AcceptTcpClient()
                    try {
                        $client.ReceiveTimeout = 1000
                        $stream = $client.GetStream()
                        $buf = New-Object byte[] 4096
                        $n = $stream.Read($buf, 0, $buf.Length)
                        if ($n -gt 0) {
                            $txt = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                            $lines = $txt -split "`r?`n"
                            $reqLine = if ($lines.Count -gt 0) { $lines[0].Trim() } else { '' }
                            $hostHdr = ''
                            $uaHdr = ''
                            foreach ($ln in $lines) {
                                if ($ln -match '^(?i)Host:\s*(.+)$') { $hostHdr = $matches[1].Trim() }
                                elseif ($ln -match '^(?i)User-Agent:\s*(.+)$') { $uaHdr = $matches[1].Trim() }
                            }
                            if ($reqLine -and $state.Log.Count -lt 200) {
                                $entry = "HTTP $reqLine | Host=$hostHdr | UA=$uaHdr"
                                if ($entry.Length -gt 380) { $entry = $entry.Substring(0, 380) }
                                [void]$state.Log.Add($entry)
                            }
                        }
                        $stream.Write($okBytes, 0, $okBytes.Length)
                        $stream.Flush()
                    } finally {
                        $client.Close()
                    }
                } catch {}
            }
        } catch {}
    }

    foreach ($sc in @($dnsScript, $httpScript)) {
        try {
            $rs = [runspacefactory]::CreateRunspace()
            $rs.Open()
            $ps = [powershell]::Create()
            $ps.Runspace = $rs
            [void]$ps.AddScript($sc).AddArgument($script:FakeNetState)
            $ar = $ps.BeginInvoke()
            $script:FakeNetWorkers += [pscustomobject]@{ Ps = $ps; Rs = $rs; Ar = $ar }
        } catch {
            Log "FakeNet worker start error: $($_.Exception.Message)"
        }
    }

    $script:FakeNetOrigDns = @()
    foreach ($ad in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        try {
            $cur = @(Get-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses)
            $script:FakeNetOrigDns += [pscustomobject]@{ IfIndex = $ad.ifIndex; Servers = @($cur) }
            Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ServerAddresses @('127.0.0.1') -ErrorAction SilentlyContinue
        } catch {}
    }
    Log 'FakeNet sinkhole started (127.0.0.1:53 UDP, 127.0.0.1:80 TCP)'
}

function Stop-FakeNet {
    if (-not $FakeNet -or $TestMode) { return @() }
    $script:FakeNetState.Stop = $true
    try { if ($script:FakeNetState.Udp) { $script:FakeNetState.Udp.Close() } } catch {}
    try { if ($script:FakeNetState.Tcp) { $script:FakeNetState.Tcp.Stop() } } catch {}
    Start-Sleep -Milliseconds 300
    foreach ($w in $script:FakeNetWorkers) {
        try { $w.Ps.Stop() } catch {}
        try { $w.Ps.Dispose() } catch {}
        try { $w.Rs.Close(); $w.Rs.Dispose() } catch {}
    }
    $script:FakeNetWorkers = @()
    foreach ($item in $script:FakeNetOrigDns) {
        try {
            if ($item.Servers -and $item.Servers.Count -gt 0) {
                Set-DnsClientServerAddress -InterfaceIndex $item.IfIndex -ServerAddresses $item.Servers -ErrorAction SilentlyContinue
            } else {
                Set-DnsClientServerAddress -InterfaceIndex $item.IfIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    Log "FakeNet sinkhole stopped (requests=$($script:FakeNetLog.Count))"
    return @($script:FakeNetLog)
}

# ------------------------------------------------------------------ HTTPS decryption (optional)
# mitmproxy in "local" capture mode intercepts every program's traffic (proxy settings are not needed); its CA is
# trusted in LocalMachine\Root so Windows (Schannel) programs accept the intercepted TLS. Programs that pin their
# certificate fail instead and are logged as tls_failed by the addon.
$script:Https = [ordered]@{ Requested = [bool]$cfg.DecryptHttps; Status = 'not requested'; CaTrusted = $false; CaEnv = $false; QuicBlocked = $false }
$script:MitmProc = $null
function Start-HttpsDecrypt {
    if (-not $cfg.DecryptHttps -or $TestMode) { return }
    $exe = 'C:\Analysis\mitm\mitmdump.exe'
    $addon = Join-Path $ToolsDir 'https_logger.py'
    if (-not (Test-Path -LiteralPath $exe) -or -not (Test-Path -LiteralPath $addon)) {
        $script:Https.Status = 'mitmdump.exe or addon missing'; Log "HTTPS decryption: $($script:Https.Status)"; return
    }
    $conf = Join-Path $WorkPath 'mitm'
    New-Item -ItemType Directory -Force -Path $conf | Out-Null
    $env:SAFEBOX_HTTPS_LOG = Join-Path $OutputDir 'https_log.jsonl'
    $errLog = Join-Path $WorkPath 'mitm_stderr.txt'
    $argList = @('--mode', 'local', '--set', "confdir=$conf", '-s', $addon, '-q')
    try {
        $script:MitmProc = Start-Process -FilePath $exe -ArgumentList $argList -WindowStyle Hidden -PassThru -RedirectStandardError $errLog
    } catch { $script:Https.Status = "start failed: $($_.Exception.Message)"; Log "HTTPS decryption: $($script:Https.Status)"; return }
    $ca = Join-Path $conf 'mitmproxy-ca-cert.cer'
    foreach ($i in 1..60) { if (Test-Path -LiteralPath $ca) { break }; Start-Sleep -Milliseconds 500 }
    if (-not (Test-Path -LiteralPath $ca)) {
        $script:Https.Status = 'CA certificate was not created'
    } else {
        try { Import-Certificate -FilePath $ca -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null; $script:Https.CaTrusted = $true } catch {}
        # Python (requests/certifi), Node/Electron and programs with their own OpenSSL ignore the Windows store and
        # read these variables instead. Set for this process (the sample inherits it) and machine-wide (setx
        # broadcasts the change, so programs started from the desktop get it too).
        $pem = Join-Path $conf 'mitmproxy-ca-cert.pem'
        if (Test-Path -LiteralPath $pem) {
            foreach ($v in 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS') {
                Set-Item -Path "Env:$v" -Value $pem
                try { & setx.exe $v $pem /M | Out-Null } catch {}
            }
            $script:Https.CaEnv = $true
        }
        Start-Sleep -Seconds 3
        if ($script:MitmProc.HasExited) {
            $tail = ''
            try { $tail = (Get-Content -LiteralPath $errLog -Tail 3 -ErrorAction Stop) -join ' ' } catch {}
            $script:Https.Status = "mitmdump exited (code $($script:MitmProc.ExitCode)) $tail".Trim()
        } else {
            $script:Https.Status = 'running'
        }
    }
    $script:Https.QuicBlocked = $script:QuicBlocked
    Log "HTTPS decryption: $($script:Https.Status) (CA trusted: $($script:Https.CaTrusted), CA env: $($script:Https.CaEnv), QUIC blocked: $($script:QuicBlocked))"
}

function Stop-HttpsDecrypt {
    if ($script:MitmProc -and -not $script:MitmProc.HasExited) {
        try { Stop-Process -Id $script:MitmProc.Id -Force -ErrorAction Stop } catch {}
        Get-Process -Name 'windows-redirector' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    if ($script:Https.Status -eq 'running') { $script:Https.Status = 'done' }
}

# ------------------------------------------------------------------ 3. run sample + watch
Start-HttpsDecrypt
Start-FakeNet
$watchStart = (Get-Date).AddSeconds(-2)
$startedAt = Get-Date
if ($targetFile) {
    $wd = $targetFile.DirectoryName
    $fp = $targetFile.FullName
    $ext = $targetFile.Extension.ToLower()
    $launchExe = $fp
    $launchArg = $TargetArgs
    switch ($ext) {
        '.msi' { $launchExe = 'msiexec.exe'; $launchArg = "/i `"$fp`" $TargetArgs".Trim() }
        '.ps1' { $launchExe = 'powershell.exe'; $launchArg = "-NoProfile -ExecutionPolicy Bypass -File `"$fp`" $TargetArgs".Trim() }
        { $_ -in '.bat', '.cmd' } { $launchExe = 'cmd.exe'; $launchArg = "/c `"`"$fp`" $TargetArgs`"".Trim() }
        { $_ -in '.vbs', '.vbe', '.js', '.jse', '.wsf' } { $launchExe = 'wscript.exe'; $launchArg = "`"$fp`" $TargetArgs".Trim() }
        '.hta' { $launchExe = 'mshta.exe'; $launchArg = "`"$fp`" $TargetArgs".Trim() }
        '.reg' { $launchExe = 'reg.exe'; $launchArg = "import `"$fp`"" }
        '.jar' {
            $javaCmd = Get-Command javaw.exe -ErrorAction SilentlyContinue
            if (-not $javaCmd) { $javaCmd = Get-Command java.exe -ErrorAction SilentlyContinue }
            if ($javaCmd) { $launchExe = $javaCmd.Source; $launchArg = "-jar `"$fp`" $TargetArgs".Trim() }
            else { Log 'Java runtime not found for .jar sample'; $launchExe = '' }
        }
        '.dll' {
            if ($DllExport) {
                $launchExe = 'rundll32.exe'
                $launchArg = "`"$fp`",$DllExport $TargetArgs".Trim()
            } else {
                $launchExe = 'regsvr32.exe'
                $launchArg = "/s `"$fp`""
            }
        }
        default { $launchExe = $fp; $launchArg = $TargetArgs }
    }
    if ($launchExe) {
        try {
            $proc = $null
            if ($RunAsStandardUser -and -not $TestMode) {
                try {
                    $fullCmd = if ($launchArg) { "`"$launchExe`" $launchArg" } else { "`"$launchExe`"" }
                    $escapedCmd = $fullCmd.Replace('"', '\"')
                    $proc = Start-Process 'runas.exe' -ArgumentList "/trustlevel:0x20000 `"$escapedCmd`"" -WorkingDirectory $wd -PassThru -ErrorAction Stop
                    Log "Sample launched via runas standard user trustlevel"
                } catch {
                    Log "runas fallback to normal user: $($_.Exception.Message)"
                    $proc = $null
                }
            }
            if (-not $proc) {
                if ($launchArg) {
                    $proc = Start-Process -FilePath $launchExe -ArgumentList $launchArg -WorkingDirectory $wd -PassThru
                } else {
                    $proc = Start-Process -FilePath $launchExe -WorkingDirectory $wd -PassThru
                }
            }
            if ($proc) { $script:RootPid = $proc.Id; $TreePids[$proc.Id] = 1; Log "Sample started, pid $($proc.Id) ($launchExe $launchArg)" }
        } catch { Log "Failed to start sample: $($_.Exception.Message)" }
    }
}

$end = $startedAt.AddSeconds($Duration)
$stoppedEarly = $false
# 24 gallery shots spread over the observation window (a 30 min install would otherwise only be covered for 12 min)
$ShotInterval = [Math]::Max(30, [int]($Duration / 22))
$lastSlowTick = [datetime]::MinValue
Capture-Screen
while ((Get-Date) -lt $end) {
    $now = Get-Date
    if (($now - $lastSlowTick).TotalSeconds -ge 5) {
        $lastSlowTick = $now
        Update-Watch $watchStart
        Update-HoneyReads $startedAt
        Test-LanBlock
        Invoke-FakeUser
        Dump-EarlySample
        if (($now - $script:LastShot).TotalSeconds -ge $ShotInterval) { Capture-Screen }
        Capture-LiveScreen
        $left = [int]($end - $now).TotalSeconds
        $sampleProcs = @($Procs.Values | Where-Object { $_.InTree }).Count
        Set-Status ("Izleniyor: {0} sn kaldi, {1} yeni islem ({2} ornekten), {3} baglanti" -f $left, $Procs.Count, $sampleProcs, $Conns.Count)
        Write-Live $left 'observing'
    } else {
        Update-Watch $watchStart
    }
    if (Test-Path -LiteralPath $StopFlag) { Log 'Stop requested from host panel.'; $stoppedEarly = $true; break }
    Start-Sleep -Seconds 1
}
Update-Watch $watchStart
Import-AuditProcesses $startedAt
Update-HoneyReads $startedAt
$memFindings = @(Scan-ProcessMemory)
Set-Status 'Bellek dokumu aliniyor (ornek islemleri)'
$memDumps = @($script:EarlyDumpList) + @(Dump-ProcessMemory)
$crashes = @(Get-CrashEvents $startedAt)
Test-LanBlock
Capture-Screen
$endedAt = Get-Date
Log 'Observation window finished.'

# ------------------------------------------------------------------ 4. stop capture
Set-Status 'Ag kaydi durduruluyor ve donusturuluyor'
Write-Live 0 'finishing'
$fakeNetReqs = @(Stop-FakeNet)
Stop-HttpsDecrypt
if ($UseTrace) { Unregister-Event -SourceIdentifier ProcStart -ErrorAction SilentlyContinue }
if ($procmon -and -not $TestMode) {
    & $procmon /Terminate | Out-Null
    Start-Sleep -Seconds 5
    if (Test-Path -LiteralPath $pml) {
        Copy-Item -LiteralPath $pml -Destination $OutputDir -Force
        Log 'procmon.pml saved'
        try {
            $pmlCsv = Join-Path $WorkPath 'procmon.csv'
            & $procmon /OpenLog $pml /SaveAs $pmlCsv /Quiet | Out-Null
            Start-Sleep -Seconds 3
            if (Test-Path -LiteralPath $pmlCsv) {
                $sensitiveHits = @()
                $hitSeen = @{}
                $rxSens = '(?i)(Login Data|Local State|wallet\.dat|logins\.json|cookies\.sqlite|seed\.seco|default_wallet|lsass\.exe|CurrentVersion\\Run|Windows Defender)'
                $rxHoneyCsv = '^"[^"]*","([^"]+)","(\d+)","(ReadFile|CreateFileMapping)","([^"]+)"'
                $sr = [IO.File]::OpenText($pmlCsv)
                try {
                    $lineNo = 0
                    while ($null -ne ($line = $sr.ReadLine()) -and $lineNo -lt 250000) {
                        $lineNo++
                        if ($script:HoneyMap.Count -gt 0 -and ($line.IndexOf('ReadFile', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $line.IndexOf('CreateFileMapping', [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                            $hm = [regex]::Match($line, $rxHoneyCsv)
                            if ($hm.Success) {
                                Record-HoneyRead $hm.Groups[4].Value $hm.Groups[1].Value ([int]$hm.Groups[2].Value)
                            }
                        }
                        if ($sensitiveHits.Count -lt 100 -and $line -match $rxSens) {
                            $trim = $line.Substring(0, [Math]::Min(240, $line.Length))
                            if (-not $hitSeen.ContainsKey($trim)) {
                                $hitSeen[$trim] = 1
                                $sensitiveHits += $trim
                            }
                        }
                    }
                } finally { $sr.Dispose() }
                Write-JsonFile 'procmon_summary.json' ([ordered]@{ SensitiveEvents = $sensitiveHits; Count = $sensitiveHits.Count }) 4
            }
        } catch { Log "Procmon summary skipped: $($_.Exception.Message)" }
    }
}
if ($captureStatus -eq 'running') {
    & pktmon.exe stop 2>&1 | Out-Null
    $o = & pktmon.exe etl2pcap $etl --out $pcap 2>&1
    if (Test-Path -LiteralPath $pcap) { $captureStatus = "saved ($([math]::Round((Get-Item -LiteralPath $pcap).Length / 1MB, 1)) MB)"; Log 'capture.pcapng saved' }
    else { $captureStatus = "conversion failed: $($o -join ' ')"; Log $captureStatus }
}

# ------------------------------------------------------------------ 5. after snapshot + diff
Set-Status 'Son sistem goruntusu aliniyor ve karsilastiriliyor'
Log 'Final snapshot...'
$after = Get-Snapshot
$honeyAlerts = Check-Honeyfiles $startedAt

$newFiles = @($after.Files.Keys | Where-Object { -not $before.Files.ContainsKey($_) })
$modFiles = @($after.Files.Keys | Where-Object { $before.Files.ContainsKey($_) -and $before.Files[$_] -ne $after.Files[$_] })
$isExec = { param($p) $ExecExt -contains ([IO.Path]::GetExtension($p)).ToLower() }
$newExec = @($newFiles | Where-Object { & $isExec $_ } | Sort-Object)
$modExec = @($modFiles | Where-Object { & $isExec $_ } | Sort-Object)

function Get-QuickEntropy([string]$FilePath) {
    try {
        $fs = [IO.File]::OpenRead($FilePath)
        try {
            $buf = New-Object byte[] 262144
            $n = $fs.Read($buf, 0, $buf.Length)
            if ($n -le 0) { return 0.0 }
            $counts = New-Object int[] 256
            for ($i = 0; $i -lt $n; $i++) { $counts[$buf[$i]]++ }
            $ent = 0.0
            for ($b = 0; $b -lt 256; $b++) {
                if ($counts[$b] -gt 0) {
                    $px = $counts[$b] / [double]$n
                    $ent -= $px * [Math]::Log($px, 2)
                }
            }
            return [Math]::Round($ent, 2)
        } finally { $fs.Dispose() }
    } catch { return 0.0 }
}

$droppedHashes = @()
foreach ($p in ($newExec | Select-Object -First 100)) {
    try {
        if (Test-Path -LiteralPath $p) {
            $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            $sz = (Get-Item -LiteralPath $p -ErrorAction Stop).Length
            $sigSt = 'Unknown'
            try { $sigSt = [string](Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop).Status } catch {}
            $ent = Get-QuickEntropy $p
            $flags = @()
            try {
                $rawBytes = [IO.File]::ReadAllBytes($p)
                $maxSlice = [Math]::Min($rawBytes.Length, 2097152)
                $asciiText = [System.Text.Encoding]::ASCII.GetString($rawBytes, 0, $maxSlice)
                foreach ($pat in 'Login Data', 'vssadmin', 'api.telegram.org', 'discord.com/api/webhooks', 'Add-MpPreference') {
                    if ($asciiText.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $flags += $pat }
                }
            } catch {}
            $droppedHashes += [ordered]@{ Path = $p; SHA256 = $h; Size = $sz; SigStatus = $sigSt; Entropy = $ent; Flags = @($flags) }
        }
    } catch {}
}

$threats = @()
try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $startedAt.AddMinutes(-1) } | ForEach-Object {
        $name = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
        "$name :: $(@($_.Resources) -join ', ')" })
} catch {}

$fwAdded = @(Compare-Set $before.Firewall $after.Firewall | Where-Object { [string]$_ -notlike 'SafeBox-*' })
$fwDetail = @(foreach ($r in $fwAdded) {
    $name = $r.Split('|')[0]
    $prog = $null
    try { $prog = (Get-NetFirewallRule -Name $name -ErrorAction Stop | Get-NetFirewallApplicationFilter -ErrorAction Stop).Program } catch {}
    "$r | program=$prog"
})

$result = [ordered]@{
    Target          = $script:TargetRel
    TargetNote      = $script:TargetNote
    Started         = $startedAt.ToString('yyyy-MM-dd HH:mm:ss')
    Ended           = $endedAt.ToString('yyyy-MM-dd HH:mm:ss')
    StoppedEarly    = $stoppedEarly
    Admin           = $isAdmin
    CaptureStatus   = $captureStatus
    RunMode         = $script:RunMode
    LanBlock        = $script:LanBlock
    HoneyfileAlerts = @($honeyAlerts)
    MemoryFindings  = @($memFindings)
    Crashes         = @($crashes)
    MemoryDumps     = @($memDumps)
    Https           = $script:Https
    FakeNetRequests = @($fakeNetReqs)
    AutoClicks      = @($script:ClickedActions)
    Processes       = @($Procs.Values | Where-Object { $MonitorNames -notcontains ([string]$_.Name).ToLower() } | Sort-Object FirstSeen)
    Network         = [ordered]@{
        Connections  = @($Conns.Values | Sort-Object FirstSeen)
        DnsCache     = @($DnsSeen.Values | Sort-Object Name)
        NewListening = @(Compare-Set $before.Listening $after.Listening)
        UdpEndpoints = @(Compare-Set $before.UdpEndpoints $after.UdpEndpoints)
    }
    Persistence     = [ordered]@{
        Services         = @((Split-ServiceDiff $before.Services $after.Services).New)
        ServicesChanged  = @((Split-ServiceDiff $before.Services $after.Services).Changed)
        Drivers          = @(Compare-Set $before.Drivers $after.Drivers)
        Tasks            = @(Compare-Set $before.Tasks $after.Tasks)
        RunKeys          = @(Compare-Set $before.RunKeys $after.RunKeys)
        Startup          = @(Compare-Set $before.Startup $after.Startup)
        WmiSubscriptions = @(Compare-Set $before.WmiSubscriptions $after.WmiSubscriptions)
        ComHijacks       = @(Compare-Set $before.ComHijacks $after.ComHijacks)
        AppInitDlls      = @(Compare-Set $before.AppInitDlls $after.AppInitDlls)
        BitsJobs         = @(Compare-Set $before.BitsJobs $after.BitsJobs)
        PsProfiles       = @(Compare-Set $before.PsProfiles $after.PsProfiles)
        ActiveSetup      = @(Compare-Set $before.ActiveSetup $after.ActiveSetup)
    }
    Defender        = [ordered]@{
        Added           = @(Compare-Set $before.Defender $after.Defender)
        ThreatsDetected = $threats
    }
    Hosts           = [ordered]@{ Added = @(Compare-Set $before.Hosts $after.Hosts); Removed = @(Compare-Set $after.Hosts $before.Hosts) }
    Firewall        = [ordered]@{ Added = $fwDetail }
    Files           = [ordered]@{
        NewCount            = $newFiles.Count
        ModifiedCount       = $modFiles.Count
        NewExecutables      = @($newExec | Select-Object -First 1000)
        ModifiedExecutables = @($modExec | Select-Object -First 500)
        DroppedHashes       = @($droppedHashes)
        NewFilesSample      = @($newFiles | Sort-Object | Select-Object -First 1500)
    }
}

Write-JsonFile 'behavior.json' $result 6
Log ("Done. processes={0} connections={1} newFiles={2} newExec={3} modExec={4} honey={5} services+={6} tasks+={7} runkeys+={8} defender={9}" -f `
    $result.Processes.Count, $result.Network.Connections.Count, $newFiles.Count, $newExec.Count, $modExec.Count, $honeyAlerts.Count,
    $result.Persistence.Services.Count, $result.Persistence.Tasks.Count, $result.Persistence.RunKeys.Count, $result.Defender.Added.Count)
Set-Status 'done'
Set-Content -LiteralPath (Join-Path $OutputDir 'done.flag') -Value (Get-Date -Format o)
