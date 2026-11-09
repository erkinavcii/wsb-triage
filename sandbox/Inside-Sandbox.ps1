<#
    SafeBox sandbox monitor. Runs INSIDE Windows Sandbox (started by the .wsb LogonCommand).
    C:\Analysis\input  (read-only)  extracted sample
    C:\Analysis\tools  (read-only)  this script, config.json, optional Procmon64.exe, stop.flag (written by host)
    C:\Analysis\output (writable)   live.json (every 5 s), behavior.json, capture.pcapng, timeline.log, procmon.pml

    Steps: baseline snapshot -> start pktmon (+Procmon) -> run sample -> watch for N seconds
           (new processes, TCP connections, DNS cache, quick persistence diff) -> stop capture
           -> final snapshot -> diff -> behavior.json + done.flag
#>
param(
    [string]$BasePath = 'C:\Analysis',
    [string]$WorkPath = 'C:\SandboxWork',
    [switch]$TestMode      # host self-test: small file scan, no capture tools
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$InputDir = Join-Path $BasePath 'input'
$OutputDir = Join-Path $BasePath 'output'
$ToolsDir = Join-Path $BasePath 'tools'
$SampleDir = Join-Path $WorkPath 'sample'
New-Item -ItemType Directory -Force -Path $WorkPath, $SampleDir, $OutputDir | Out-Null
$WorkPath = (Get-Item -LiteralPath $WorkPath).FullName
$SampleDir = (Get-Item -LiteralPath $SampleDir).FullName
$StopFlag = Join-Path $ToolsDir 'stop.flag'
try { $Host.UI.RawUI.WindowTitle = 'SafeBox monitor - do not close' } catch {}

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
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "Monitor started. admin=$isAdmin duration=${Duration}s"
Set-Status 'preparing'

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

function Get-ServiceList { @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) | $($_.StartMode) | $($_.PathName)" }) }
function Get-DriverList { @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) | $($_.PathName)" }) }
function Get-TaskList {
    @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $acts = @($_.Actions | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join '; '
        "$($_.TaskPath)$($_.TaskName) | $acts" })
}
function Get-StartupList { @(Get-ChildItem -Force -ErrorAction SilentlyContinue -LiteralPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | ForEach-Object { $_.FullName }) }
function Get-HostsLines { @(Get-Content -LiteralPath "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) }

if ($TestMode) {
    $FileScan = @(@{ P = $env:TEMP; R = $true })
} else {
    $FileScan = @(
        @{ P = $env:APPDATA; R = $true }, @{ P = $env:LOCALAPPDATA; R = $true }, @{ P = $env:ProgramData; R = $true },
        @{ P = "$env:windir\Temp"; R = $true }, @{ P = $env:PUBLIC; R = $true }, @{ P = "$env:windir\System32\drivers"; R = $true },
        @{ P = "$env:windir\System32"; R = $false }, @{ P = "$env:windir\SysWOW64"; R = $false }, @{ P = $env:windir; R = $false },
        @{ P = 'C:\'; R = $false }, @{ P = "$env:USERPROFILE"; R = $false }, @{ P = "$env:USERPROFILE\Desktop"; R = $true }
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
    $s.Firewall = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.DisplayName)|$($_.Direction)|$($_.Action)|$($_.Enabled)" })
    $s.Listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $n = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "$($_.LocalAddress):$($_.LocalPort) | $n" } | Select-Object -Unique)
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
$MonitorNames = @('pktmon.exe', 'procmon.exe', 'procmon64.exe', 'wmiprvse.exe', 'conhost.exe')
$SuspiciousCmdRx = '(?i)-enc(odedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|start-bitstransfer|add-mppreference|set-mppreference|-windowstyle\s+hidden|-w\s+hidden|vssadmin.*delete|bcdedit|wevtutil\s+cl|certutil.*(-urlcache|-decode)|bitsadmin.*/transfer|mshta\s+http|regsvr32.*/i:http|rundll32.*javascript|schtasks.*/create|reg\s+add.*\\run\b|netsh\s+advfirewall\s+set.*off|cmd.*/c.*del.*\\'

function Add-Proc([int]$ProcId, [int]$ParentId, [string]$Name, [string]$Path, [string]$Cmd) {
    $inTree = ($script:RootPid -and $ProcId -eq $script:RootPid) -or $TreePids.ContainsKey($ParentId)
    if ($inTree) { $TreePids[$ProcId] = 1 }
    $parent = if ($Procs.ContainsKey($ParentId)) { $Procs[$ParentId].Name } else { (Get-Process -Id $ParentId -ErrorAction SilentlyContinue).ProcessName }
    $rec = [pscustomobject]@{
        FirstSeen = (Get-Date).ToString('HH:mm:ss'); Pid = $ProcId; Ppid = $ParentId; ParentName = $parent
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
            Services = @(Compare-Set $before.Services (Get-ServiceList))
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

# ------------------------------------------------------------------ 1. copy sample + baseline
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
    # Large installers (multi-GB): run straight from the read-only share instead of duplicating them on the sandbox disk.
    $SampleDir = (Get-Item -LiteralPath $InputDir).FullName
    Log "Sample is $sampleMB MB (> $copyMax MB): running in place from the read-only share, no copy."
    $script:RunMode = 'in-place (read-only share)'
}

$DeprioritizeRx = '(?i)(uninst|unins\d|crash|helper|vc_?redist|vcredist|dotnet|ndp\d|directx|dxsetup|redist|updater|elevat|report|cleanup|repair)'
$InstallerRx = '(?i)^(set-?up|install|autorun|autoplay|start)'
$CrackRx = '(?i)(patch|crack|loader|activat|keygen|genp)'
function Get-TargetRank($f) {
    if ($f.Name -match $DeprioritizeRx) { return 9 }
    if ($f.Name -match $InstallerRx) { return 0 }
    if ($f.Name -match $CrackRx) { return 1 }
    return 5
}

function Resolve-Target {
    if ($cfg.Target) {
        $p = Join-Path $SampleDir $cfg.Target
        if (Test-Path -LiteralPath $p) { return (Get-Item -LiteralPath $p) }
        Log "Configured target not found: $($cfg.Target) - falling back to auto-pick"
    }
    $exts = @('.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.scr', '.com', '.lnk')
    $c = @(Get-ChildItem -LiteralPath $SampleDir -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $exts -contains $_.Extension.ToLower() })
    if (-not $c.Count) { return $null }
    # name first (Set-up.exe / setup / install... beat vc_redist, uninstall), then exe/msi, then shallowest, then biggest
    $c | Sort-Object @{ E = { Get-TargetRank $_ } },
                     @{ E = { if ($_.Extension -in '.exe', '.msi') { 0 } else { 1 } } },
                     @{ E = { $_.FullName.Substring($SampleDir.Length).Split('\').Count } },
                     @{ E = { $_.Length }; Descending = $true } | Select-Object -First 1
}

# ------------------------------------------------------------------ home-network (LAN) block
# Internet stays reachable (so C2 traffic is captured), but private ranges - your router, NAS, other PCs, the host -
# are blocked, except the sandbox's own gateway/DNS. A sample running as admin could remove the rule, so it is
# re-checked every 5 s; tampering is re-applied and reported as a red flag.
$script:LanBlock = [ordered]@{ Requested = [bool]$cfg.BlockLan; Applied = $false; Exempt = @(); Ranges = @(); Tampered = $false; Details = @(); Status = 'not requested' }
$LanRuleNames = @('SafeBox-BlockLAN-Out', 'SafeBox-BlockLAN-In')

function ConvertTo-IpNum([string]$ip) { $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [uint64]$b[0] * 16777216 + [uint64]$b[1] * 65536 + [uint64]$b[2] * 256 + [uint64]$b[3] }
function ConvertFrom-IpNum([uint64]$n) { '{0}.{1}.{2}.{3}' -f ([math]::Floor($n / 16777216) % 256), ([math]::Floor($n / 65536) % 256), ([math]::Floor($n / 256) % 256), ($n % 256) }

function Get-LanRanges([string[]]$Exempt) {
    $cidrs = @(@('10.0.0.0', 8), @('172.16.0.0', 12), @('192.168.0.0', 16), @('169.254.0.0', 16), @('100.64.0.0', 10))
    $ex = @($Exempt | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | ForEach-Object { ConvertTo-IpNum $_ } | Sort-Object -Unique)
    foreach ($c in $cidrs) {
        $start = ConvertTo-IpNum $c[0]
        $end = $start + [uint64][math]::Pow(2, 32 - $c[1]) - 1
        $cur = $start
        foreach ($e in ($ex | Where-Object { $_ -ge $start -and $_ -le $end })) {
            if ($e -gt $cur) { if ($e - 1 -eq $cur) { ConvertFrom-IpNum $cur } else { "$(ConvertFrom-IpNum $cur)-$(ConvertFrom-IpNum ($e - 1))" } }
            $cur = $e + 1
        }
        if ($cur -le $end) { if ($cur -eq $end) { ConvertFrom-IpNum $cur } else { "$(ConvertFrom-IpNum $cur)-$(ConvertFrom-IpNum $end)" } }
    }
    $v6dns = @(Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -match '^f[cd]' })
    if (-not $v6dns.Count) { 'fc00::/7' }
}

function Set-LanBlock {
    $gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop } | Where-Object { $_ -and $_ -ne '0.0.0.0' })
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
    $script:LanBlock.Exempt = @($gw + $dns | Where-Object { $_ } | Select-Object -Unique)
    $script:LanBlock.Ranges = @(Get-LanRanges $script:LanBlock.Exempt)
    foreach ($n in $LanRuleNames) { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
    Set-NetFirewallProfile -All -Enabled True -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $LanRuleNames[0] -DisplayName 'SafeBox: block home network (outbound)' -Direction Outbound -Action Block -RemoteAddress $script:LanBlock.Ranges -Profile Any -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name $LanRuleNames[1] -DisplayName 'SafeBox: block home network (inbound)' -Direction Inbound -Action Block -RemoteAddress $script:LanBlock.Ranges -Profile Any -ErrorAction Stop | Out-Null
    $script:LanBlock.Applied = $true
}

function Test-LanBlock {
    if (-not $script:LanBlock.Applied) { return }
    $bad = @()
    foreach ($n in $LanRuleNames) {
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
        $script:LanBlock.Status = "active (exempt: $($script:LanBlock.Exempt -join ', '))"
        Log "Home network blocked: $($script:LanBlock.Ranges -join ', ')"
    } catch { $script:LanBlock.Status = "FAILED: $($_.Exception.Message)"; Log "LAN block failed: $($_.Exception.Message)" }
} elseif ($script:LanBlock.Requested) { $script:LanBlock.Status = 'skipped (not admin or test mode)' }

$targetFile = Resolve-Target
$script:TargetRel = if ($targetFile) { $targetFile.FullName.Substring($SampleDir.Length).TrimStart('\') } else { $null }
if ($targetFile) { Log "Target: $($targetFile.FullName)" } else { Log 'No runnable file found - only observing the system.' }

Set-Status 'Temiz sistem goruntusu (baseline) aliniyor'
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
    $o = & pktmon.exe start --capture --comp nics --pkt-size 0 --file-name $etl --file-size 2048 2>&1
    if ($LASTEXITCODE -eq 0) { $captureStatus = 'running'; Log 'pktmon capture started' } else { $captureStatus = "pktmon failed: $($o -join ' ')"; Log $captureStatus }
} else { $captureStatus = 'skipped (not admin or test mode)'; Log "Capture $captureStatus" }

$procmon = $null
foreach ($pm in 'Procmon64.exe', 'Procmon.exe') { $pp = Join-Path $ToolsDir $pm; if (Test-Path -LiteralPath $pp) { $procmon = $pp; break } }
$pml = Join-Path $WorkPath 'procmon.pml'
if ($procmon -and -not $TestMode) {
    Start-Process -FilePath $procmon -ArgumentList "/AcceptEula /Quiet /Minimized /BackingFile `"$pml`""
    Start-Sleep -Seconds 6
    Log 'Process Monitor started'
}

# ------------------------------------------------------------------ 3. run sample + watch
$watchStart = (Get-Date).AddSeconds(-2)
$startedAt = Get-Date
if ($targetFile) {
    $wd = $targetFile.DirectoryName
    $fp = $targetFile.FullName
    try {
        switch ($targetFile.Extension.ToLower()) {
            '.msi' { $proc = Start-Process msiexec.exe -ArgumentList "/i `"$fp`"" -WorkingDirectory $wd -PassThru }
            '.ps1' { $proc = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$fp`"" -WorkingDirectory $wd -PassThru }
            { $_ -in '.bat', '.cmd' } { $proc = Start-Process cmd.exe -ArgumentList "/c `"`"$fp`"`"" -WorkingDirectory $wd -PassThru }
            { $_ -in '.vbs', '.js' } { $proc = Start-Process wscript.exe -ArgumentList "`"$fp`"" -WorkingDirectory $wd -PassThru }
            '.hta' { $proc = Start-Process mshta.exe -ArgumentList "`"$fp`"" -WorkingDirectory $wd -PassThru }
            default { $proc = Start-Process -FilePath $fp -WorkingDirectory $wd -PassThru }
        }
        if ($proc) { $script:RootPid = $proc.Id; $TreePids[$proc.Id] = 1; Log "Sample started, pid $($proc.Id)" }
    } catch { Log "Failed to start sample: $($_.Exception.Message)" }
}

$end = $startedAt.AddSeconds($Duration)
$stoppedEarly = $false
while ((Get-Date) -lt $end) {
    Update-Watch $watchStart
    Test-LanBlock
    $left = [int]($end - (Get-Date)).TotalSeconds
    $sampleProcs = @($Procs.Values | Where-Object { $_.InTree }).Count
    Set-Status ("Izleniyor: {0} sn kaldi, {1} yeni islem ({2} ornekten), {3} baglanti" -f $left, $Procs.Count, $sampleProcs, $Conns.Count)
    Write-Live $left 'observing'
    if (Test-Path -LiteralPath $StopFlag) { Log 'Stop requested from host panel.'; $stoppedEarly = $true; break }
    Start-Sleep -Seconds 5
}
Update-Watch $watchStart
Test-LanBlock
$endedAt = Get-Date
Log 'Observation window finished.'

# ------------------------------------------------------------------ 4. stop capture
Set-Status 'Ag kaydi durduruluyor ve donusturuluyor'
Write-Live 0 'finishing'
if ($UseTrace) { Unregister-Event -SourceIdentifier ProcStart -ErrorAction SilentlyContinue }
if ($procmon -and -not $TestMode) {
    & $procmon /Terminate | Out-Null
    Start-Sleep -Seconds 5
    if (Test-Path -LiteralPath $pml) { Copy-Item -LiteralPath $pml -Destination $OutputDir -Force; Log 'procmon.pml saved' }
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

$newFiles = @($after.Files.Keys | Where-Object { -not $before.Files.ContainsKey($_) })
$modFiles = @($after.Files.Keys | Where-Object { $before.Files.ContainsKey($_) -and $before.Files[$_] -ne $after.Files[$_] })
$isExec = { param($p) $ExecExt -contains ([IO.Path]::GetExtension($p)).ToLower() }
$newExec = @($newFiles | Where-Object { & $isExec $_ } | Sort-Object)
$modExec = @($modFiles | Where-Object { & $isExec $_ } | Sort-Object)

$threats = @()
try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $startedAt.AddMinutes(-1) } | ForEach-Object {
        $name = (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName
        "$name :: $(@($_.Resources) -join ', ')" })
} catch {}

$fwAdded = @(Compare-Set $before.Firewall $after.Firewall)
$fwDetail = @(foreach ($r in $fwAdded) {
    $name = $r.Split('|')[0]
    $prog = $null
    try { $prog = (Get-NetFirewallRule -Name $name -ErrorAction Stop | Get-NetFirewallApplicationFilter -ErrorAction Stop).Program } catch {}
    "$r | program=$prog"
})

$result = [ordered]@{
    Target        = $script:TargetRel
    Started       = $startedAt.ToString('yyyy-MM-dd HH:mm:ss')
    Ended         = $endedAt.ToString('yyyy-MM-dd HH:mm:ss')
    StoppedEarly  = $stoppedEarly
    Admin         = $isAdmin
    CaptureStatus = $captureStatus
    RunMode       = $script:RunMode
    LanBlock      = $script:LanBlock
    Processes     = @($Procs.Values | Where-Object { $MonitorNames -notcontains ([string]$_.Name).ToLower() } | Sort-Object FirstSeen)
    Network       = [ordered]@{
        Connections  = @($Conns.Values | Sort-Object FirstSeen)
        DnsCache     = @($DnsSeen.Values | Sort-Object Name)
        NewListening = @(Compare-Set $before.Listening $after.Listening)
    }
    Persistence   = [ordered]@{
        Services = @(Compare-Set $before.Services $after.Services)
        Drivers  = @(Compare-Set $before.Drivers $after.Drivers)
        Tasks    = @(Compare-Set $before.Tasks $after.Tasks)
        RunKeys  = @(Compare-Set $before.RunKeys $after.RunKeys)
        Startup  = @(Compare-Set $before.Startup $after.Startup)
    }
    Defender      = [ordered]@{
        Added           = @(Compare-Set $before.Defender $after.Defender)
        ThreatsDetected = $threats
    }
    Hosts         = [ordered]@{ Added = @(Compare-Set $before.Hosts $after.Hosts); Removed = @(Compare-Set $after.Hosts $before.Hosts) }
    Firewall      = [ordered]@{ Added = $fwDetail }
    Files         = [ordered]@{
        NewCount            = $newFiles.Count
        ModifiedCount       = $modFiles.Count
        NewExecutables      = @($newExec | Select-Object -First 1000)
        ModifiedExecutables = @($modExec | Select-Object -First 500)
        NewFilesSample      = @($newFiles | Sort-Object | Select-Object -First 1500)
    }
}

Write-JsonFile 'behavior.json' $result 6
Log ("Done. processes={0} connections={1} newFiles={2} newExec={3} services+={4} tasks+={5} runkeys+={6} defender={7}" -f `
    $result.Processes.Count, $result.Network.Connections.Count, $newFiles.Count, $newExec.Count,
    $result.Persistence.Services.Count, $result.Persistence.Tasks.Count, $result.Persistence.RunKeys.Count, $result.Defender.Added.Count)
Set-Status 'done'
Set-Content -LiteralPath (Join-Path $OutputDir 'done.flag') -Value (Get-Date -Format o)
