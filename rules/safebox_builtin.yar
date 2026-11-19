rule SafeBox_Credential_Stealer_Browser_Targets
{
    meta:
        description = "Multiple browser credential, cookie, or crypto-wallet store paths"
        severity = "critical"
        score = 25
    strings:
        $c1 = "Login Data" ascii wide nocase
        $c2 = "Local State" ascii wide nocase
        $c3 = "logins.json" ascii wide nocase
        $c4 = "cookies.sqlite" ascii wide nocase
        $c5 = "wallet.dat" ascii wide nocase
        $c6 = "Electrum\\wallets" ascii wide nocase
        $c7 = "Exodus\\exodus.wallet" ascii wide nocase
        $c8 = "Web Data" ascii wide nocase
    condition:
        3 of them
}

rule SafeBox_Defender_Exclusion_Tampering
{
    meta:
        description = "Attempts to disable Windows Defender or add scan exclusions"
        severity = "high"
        score = 25
    strings:
        $a1 = "Add-MpPreference" ascii wide nocase
        $a2 = "Set-MpPreference" ascii wide nocase
        $b1 = "ExclusionPath" ascii wide nocase
        $b2 = "DisableRealtimeMonitoring" ascii wide nocase
        $b3 = "DisableBehaviorMonitoring" ascii wide nocase
    condition:
        any of ($a*) and any of ($b*)
}

rule SafeBox_Ransomware_Shadow_Delete
{
    meta:
        description = "Deletes Windows shadow copies or disables recovery catalog"
        severity = "critical"
        score = 35
    strings:
        $v1 = "vssadmin" ascii wide nocase
        $v2 = "delete shadows" ascii wide nocase
        $w1 = "wbadmin" ascii wide nocase
        $w2 = "delete catalog" ascii wide nocase
        $b1 = "bcdedit" ascii wide nocase
        $b2 = "recoveryenabled no" ascii wide nocase
    condition:
        ($v1 and $v2) or ($w1 and $w2) or ($b1 and $b2)
}

rule SafeBox_PowerShell_Hidden_Download_Exec
{
    meta:
        description = "Hidden or Base64-encoded PowerShell dropper behavior"
        severity = "high"
        score = 20
    strings:
        $ps = "powershell" ascii wide nocase
        $h1 = "-WindowStyle Hidden" ascii wide nocase
        $h2 = "-w hidden" ascii wide nocase
        $h3 = "FromBase64String" ascii wide nocase
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "-enc " ascii wide nocase
    condition:
        $ps and any of ($h*) and any of ($d*)
}

rule SafeBox_Chat_Webhook_Exfiltration
{
    meta:
        description = "Contains Telegram Bot API or Discord webhook endpoint"
        severity = "high"
        score = 25
    strings:
        $tg = "api.telegram.org/bot" ascii wide nocase
        $dc1 = "discord.com/api/webhooks/" ascii wide nocase
        $dc2 = "discordapp.com/api/webhooks/" ascii wide nocase
    condition:
        any of them
}

rule SafeBox_Patch_Keygen_Artifacts
{
    meta:
        description = "Crack, keygen, or binary patcher indicators"
        severity = "medium"
        score = 15
    strings:
        $p1 = "PATCHED_BY" ascii wide nocase
        $p2 = "CRACKED BY" ascii wide nocase
        $p3 = "CrackTro" ascii wide nocase
        $p4 = "Keygen" ascii wide nocase
        $m1 = "Bypass" ascii wide nocase
        $m2 = "Activation" ascii wide nocase
        $m3 = "Serial" ascii wide nocase
        $m4 = "VirtualAlloc" ascii wide nocase
    condition:
        any of ($p*) and any of ($m*)
}

rule SafeBox_Crypto_Miner_Indicators
{
    meta:
        description = "Cryptocurrency miner stratum pool or XMRig indicators"
        severity = "high"
        score = 25
    strings:
        $m1 = "stratum+tcp://" ascii wide nocase
        $m2 = "xmrig" ascii wide nocase fullword
        $m3 = "cryptonight" ascii wide nocase
        $m4 = "moneroocean" ascii wide nocase
        $m5 = "donate-level" ascii wide nocase
        $m6 = "randomx" ascii wide nocase fullword
    condition:
        2 of them
}

rule SafeBox_Reverse_Shell_PowerShell
{
    meta:
        description = "PowerShell TCP socket reverse shell pattern"
        severity = "critical"
        score = 35
    strings:
        $t = "Net.Sockets.TCPClient" ascii wide nocase
        $s1 = "GetStream" ascii wide nocase
        $s2 = "StreamReader" ascii wide nocase
        $e1 = "Invoke-Expression" ascii wide nocase
        $e2 = "IEX" ascii wide nocase fullword
    condition:
        $t and any of ($s*) and any of ($e*)
}

rule SafeBox_LSASS_Credential_Dump
{
    meta:
        description = "Attempts to dump LSASS memory or credentials"
        severity = "critical"
        score = 35
    strings:
        $k = "sekurlsa::" ascii wide nocase
        $m1 = "MiniDumpWriteDump" ascii wide nocase
        $m2 = "lsass" ascii wide nocase fullword
        $c1 = "comsvcs.dll" ascii wide nocase
        $c2 = "MiniDump" ascii wide nocase
    condition:
        $k or ($m1 and $m2) or ($c1 and $c2)
}

rule SafeBox_AMSI_ETW_Bypass
{
    meta:
        description = "AMSI or ETW memory patching indicators"
        severity = "high"
        score = 25
    strings:
        $a = "AmsiScanBuffer" ascii wide nocase
        $ai = "amsiInitFailed" ascii wide nocase
        $etw = "EtwEventWrite" ascii wide nocase
        $vp = "VirtualProtect" ascii wide nocase
    condition:
        ($a and ($vp or $ai)) or ($etw and $vp)
}

rule SafeBox_Office_Macro_Dropper
{
    meta:
        description = "Office macro auto-execution combined with shell or download API"
        severity = "high"
        score = 25
    strings:
        $a1 = "AutoOpen" ascii wide nocase
        $a2 = "Document_Open" ascii wide nocase
        $a3 = "Workbook_Open" ascii wide nocase
        $x1 = "WScript.Shell" ascii wide nocase
        $x2 = "PowerShell" ascii wide nocase
        $x3 = "URLDownloadToFile" ascii wide nocase
        $x4 = "ShellExecute" ascii wide nocase
    condition:
        any of ($a*) and any of ($x*)
}

rule SafeBox_PDF_Suspicious_Action
{
    meta:
        description = "PDF document with automatic action, embedded JavaScript, or Launch command"
        severity = "high"
        score = 20
    strings:
        $hdr = "%PDF-" ascii
        $l = "/Launch" ascii
        $o = "/OpenAction" ascii
        $j1 = "/JavaScript" ascii
        $j2 = "/JS" ascii fullword
    condition:
        $hdr and ($l or ($o and any of ($j*)))
}

rule SafeBox_Clipboard_Hijacker
{
    meta:
        description = "Monitors or modifies clipboard along with cryptocurrency wallet patterns"
        severity = "high"
        score = 25
    strings:
        $c1 = "AddClipboardFormatListener" ascii wide nocase
        $c2 = "GetClipboardData" ascii wide nocase
        $c3 = "SetClipboardData" ascii wide nocase
        $w1 = "bc1" ascii wide nocase fullword
        $w2 = "0x" ascii wide nocase fullword
        $w3 = "bitcoin" ascii wide nocase fullword
        $w4 = "ethereum" ascii wide nocase fullword
        $w5 = "wallet" ascii wide nocase fullword
    condition:
        ($c1 or ($c2 and $c3)) and any of ($w*)
}

rule SafeBox_Persistence_WMI_Subscription
{
    meta:
        description = "WMI permanent event subscription persistence indicators"
        severity = "critical"
        score = 30
    strings:
        $f = "__EventFilter" ascii wide nocase
        $c = "CommandLineEventConsumer" ascii wide nocase
        $b = "__FilterToConsumerBinding" ascii wide nocase
    condition:
        $f and $c and $b
}

rule SafeBox_UAC_Bypass_Registry
{
    meta:
        description = "Known UAC bypass binary and ms-settings registry hijack indicators"
        severity = "high"
        score = 25
    strings:
        $b1 = "fodhelper" ascii wide nocase
        $b2 = "computerdefaults" ascii wide nocase
        $b3 = "eventvwr" ascii wide nocase
        $r1 = "ms-settings\\Shell\\Open\\command" ascii wide nocase
        $r2 = "DelegateExecute" ascii wide nocase
    condition:
        any of ($b*) and any of ($r*)
}

rule SafeBox_DotNet_Memory_Loader
{
    meta:
        description = ".NET reflection in-memory assembly loader pattern"
        severity = "high"
        score = 25
    strings:
        $r = "System.Reflection" ascii wide
        $a = "Assembly" ascii wide
        $b = "FromBase64String" ascii wide
        $x1 = "DownloadData" ascii wide
        $x2 = "VirtualAlloc" ascii wide
        $x3 = "Invoke" ascii wide fullword
    condition:
        $r and $a and $b and any of ($x*)
}
