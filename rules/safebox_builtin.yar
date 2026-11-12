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
