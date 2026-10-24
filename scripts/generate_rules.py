# ruff: noqa: E402
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import yara  # type: ignore[import-not-found,import-untyped]

from malware_scanner.lab import compile_rules  # type: ignore[import-not-found]

RULES = {
    "apt_fancybear_sofaciy.yar": """rule APT28_Sofacy_CHOPSTICK
{
    meta:
        description = "Detects APT28 / Sofacy CHOPSTICK (SPLM) implant artifacts"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $str1 = "CHOPSTICK" ascii wide nocase
        $str2 = "Sofacy" ascii wide nocase
        $str3 = "splm_x64.dll" ascii wide
        $str4 = "/api/v1/user/auth_check" ascii
        $cfg1 = "Local\\\\ShellAgentMutex" ascii wide
        $cfg2 = "App Paths\\\\calc.exe" ascii wide
    condition:
        2 of ($str*) or (1 of ($str*) and 1 of ($cfg*))
}
""",
    "apt_cozybear_nobelium.yar": """rule APT29_Nobelium_Sunburst
{
    meta:
        description = "Detects SolarWinds Sunburst backdoor markers associated with APT29 Nobelium"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $guid1 = "SolarWinds.Orion.Core.BusinessLayer.BackgroundInventory" ascii wide
        $pipe1 = "pipe\\\\SolarWinds.ProcessQueue" ascii wide
        $domain = "avsvmcloud.com" ascii wide nocase
        $api1 = "GetProcessImageFileName" ascii
        $cfg = "OrionImprovementBusinessLayer" ascii wide
    condition:
        $domain or ($guid1 and 1 of ($pipe1, $api1, $cfg))
}
""",
    "apt_lazarus_bluenoroff.yar": """rule APT38_Lazarus_Fallchill
{
    meta:
        description = "Detects Lazarus Group / Bluenoroff Fallchill and Manuscrypt C2 beacons"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $magic = { 46 41 4C 4C 43 48 49 4C 4C }
        $cmd1 = "cmd.exe /c dir /a /s /b" ascii
        $cmd2 = "systeminfo >> %temp%" ascii
        $pipe = "pipe\\\\msagent_" ascii wide
        $xor_key = { 4E 6F 72 74 68 4B 6F 72 }
    condition:
        $magic or ($pipe and 1 of ($cmd1, $cmd2)) or $xor_key
}
""",
    "apt_sandworm_blackenergy.yar": """rule APT44_Sandworm_Industroyer
{
    meta:
        description = "Detects Sandworm Team Industroyer / CrashOverride ICS attack artifacts"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $proto1 = "IEC 60870-5-104" ascii wide
        $proto2 = "IEC 61850" ascii wide
        $proto3 = "OPC DA" ascii wide
        $func1 = "104_kill_task" ascii
        $func2 = "CrashOverride_payload" ascii
        $serv = "DEFCON_SERVICE_MAIN" ascii wide
    condition:
        (1 of ($proto*) and 1 of ($func*)) or $serv
}
""",
    "apt_oilrig_helix.yar": """rule APT34_OilRig_DNSpionage
{
    meta:
        description = "Detects APT34 OilRig / Helix Kitten DNS exfiltration and QUADAGENT"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "apt"
    strings:
        $dns1 = "nslookup -q=txt" ascii nocase
        $dns2 = "DnsQuery_A" ascii
        $agent = "QUADAGENT_TASK_ID" ascii wide
        $script = "Out-File -Encoding ASCII" ascii
    condition:
        $agent or ($dns1 and $script) or $dns2
}
""",
    "apt_winnti_group.yar": """rule APT_Winnti_Loader
{
    meta:
        description = "Detects Winnti Group custom packaging, tags, and payload headers"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $tag1 = "WINNTI_GROUP_TAG" ascii wide
        $tag2 = "TAG_2020_BUILD" ascii wide
        $hdr = { 57 4E 54 49 01 00 00 00 }
        $pipe = "pipe\\\\2020_winnti_ipc" ascii wide
        $rc4_sig = "rc4_winnti_init_key" ascii
    condition:
        $hdr or 1 of ($tag1, $tag2) or ($pipe and $rc4_sig)
}
""",
    "apt_turla_snake.yar": """rule APT_Turla_Snake_Uroburos
{
    meta:
        description = "Detects Turla / Snake / Uroburos peer-to-peer driver and rootkit elements"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "apt"
    strings:
        $urob1 = "Uroburos_v1" ascii wide
        $driver = "NamedPipe\\\\Snake_Queue" ascii wide
        $mutex = "Global\\\\Turla_Driver_Active" ascii wide
        $comm = "Castalia.dll" ascii wide
    condition:
        1 of ($urob1, $driver, $mutex, $comm)
}
""",
    "apt_muddywater_seed.yar": """rule APT_MuddyWater_Seedworm
{
    meta:
        description = "Detects MuddyWater PowerShell and DNS tunneling implants"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "apt"
    strings:
        $fn1 = "Start-MuddyTunnel" ascii nocase
        $fn2 = "Invoke-MuddyDnsQuery" ascii nocase
        $tag = "MUDDYWATER_CAMPAIGN" ascii wide
        $cmd = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden" ascii nocase
    condition:
        $tag or (1 of ($fn*) and $cmd)
}
""",
    "ransomware_lockbit.yar": """rule Ransomware_LockBit_3
{
    meta:
        description = "Detects LockBit 3.0 (LockBit Black) ransom notes, wallpaper and mutexes"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $note1 = "LockBit 3.0 the world's fastest and most stable ransomware" ascii wide nocase
        $note2 = "All your data has been encrypted by LockBit" ascii wide nocase
        $ico = ".lockbit3" ascii wide nocase
        $mutex = "Global\\\\LockBit_3_WorkerMutex" ascii wide
        $vss = "vssadmin delete shadows /all /quiet" ascii wide nocase
        $bcd = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
    condition:
        1 of ($note*) or ($ico and ($vss or $bcd)) or $mutex
}
""",
    "ransomware_blackcat_alphv.yar": """rule Ransomware_BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat / ALPHV Rust-compiled ransomware artifacts"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $rust1 = "cargo/registry/src/" ascii
        $alphv1 = "alphv_ransomware_core" ascii
        $note1 = "RECOVER-FILES-ALPHV.txt" ascii wide
        $onion = ".alphv" ascii wide
        $cmd1 = "wmic shadowcopy delete" ascii wide nocase
    condition:
        $alphv1 or ($note1 and $onion) or ($rust1 and $note1 and $cmd1)
}
""",
    "ransomware_conti.yar": """rule Ransomware_Conti_v2
{
    meta:
        description = "Detects Conti v2 and v3 locker strings and API resolving routines"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $ext = ".CONTI" ascii wide
        $note = "readme.txt" ascii wide
        $mutex = "kjsfhdjkfhsjkdhfksdjh" ascii wide
        $kill1 = "sqlservr.exe" ascii wide
        $kill2 = "veeam" ascii wide nocase
        $drop = "CONTI_README_DECRYPT" ascii wide
    condition:
        $drop or ($ext and $note and 2 of ($kill1, $kill2, $mutex))
}
""",
    "ransomware_revil_sodinokibi.yar": """rule Ransomware_REvil_Sodinokibi
{
    meta:
        description = "Detects REvil / Sodinokibi configuration blocks and decryptor instructions"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $json1 = "{\\"dmn\\":" ascii
        $json2 = "{\\"pk\\":" ascii
        $note = "-readme.txt" ascii wide
        $url = "decoder.re" ascii wide nocase
    condition:
        (1 of ($json*) and $note) or $url
}
""",
    "ransomware_wannacry.yar": """rule Ransomware_WannaCry_WanaCrypt0r
{
    meta:
        description = "Detects WannaCry / WanaCrypt0r 2.0 executable markers and zip archives"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $killswitch = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        $wncry1 = "tasksche.exe" ascii wide
        $wncry2 = "WNcry@2ol7" ascii
        $wncry3 = "WANACRY!" ascii
        $ext = ".wnry" ascii wide
    condition:
        $killswitch or $wncry2 or $wncry3 or ($wncry1 and $ext)
}
""",
    "ransomware_darkside_blackmatter.yar": """rule Ransomware_DarkSide_BlackMatter
{
    meta:
        description = "Detects DarkSide and BlackMatter corporate extortion ransomware strings"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $dark1 = "DarkSide Ransomware" ascii wide nocase
        $bm1 = "BlackMatter Ransomware" ascii wide nocase
        $note = ".README.txt" ascii wide
        $api1 = "NtSetInformationProcess" ascii
        $tor1 = "darksid" ascii wide
        $tor2 = "blackmax" ascii wide
    condition:
        $dark1 or $bm1 or (1 of ($tor*) and $note and $api1)
}
""",
    "ransomware_babuk.yar": """rule Ransomware_Babuk_Locker
{
    meta:
        description = "Detects Babuk / Babyk ransomware builders and ESXi/Windows lockers"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $b1 = "Babuk Locker" ascii wide nocase
        $b2 = "How To Restore Your Files.txt" ascii wide
        $esx1 = "esxcli vm process kill" ascii wide
        $curve = "curve25519" ascii wide
        $cha = "chacha20" ascii wide
    condition:
        $b1 or ($b2 and ($esx1 or ($curve and $cha)))
}
""",
    "ransomware_phobos_elrond.yar": """rule Ransomware_Phobos_Family
{
    meta:
        description = "Detects Phobos / Dharma / Crysis ransomware markers and ransom emails"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $note1 = "info.hta" ascii wide nocase
        $note2 = "info.txt" ascii wide nocase
        $pat = ".id[" ascii wide
        $tail = "].[filebackup" ascii wide
        $shadow = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
    condition:
        ($note1 or $note2) and $pat and ($tail or $shadow)
}
""",
    "ransomware_clop_ta505.yar": """rule Ransomware_Clop_TA505
{
    meta:
        description = "Detects Clop / Cl0p ransomware signature marker and mutex"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $clop_sig = "ClopReadMe.txt" ascii wide nocase
        $clop_marker = "Cl0p" ascii wide
        $pipe = "pipe\\\\clop_locker" ascii wide
        $kill = "net stop MSSQLSERVER" ascii wide nocase
    condition:
        $clop_sig or $pipe or ($clop_marker and $kill)
}
""",
    "ransomware_hive.yar": """rule Ransomware_Hive_Go_Rust
{
    meta:
        description = "Detects Hive Ransomware encryption markers and key generation"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $hive1 = "HOW_TO_DECRYPT.txt" ascii wide
        $hive2 = "hive_key.bin" ascii wide
        $hive3 = "hive_ransomware" ascii wide nocase
        $onion = "hivecustom" ascii wide
    condition:
        $hive3 or ($hive1 and ($hive2 or $onion))
}
""",
    "ransomware_play.yar": """rule Ransomware_Play_Balloonfly
{
    meta:
        description = "Detects Play ransomware ransom notes, extension and system shutdown commands"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $play1 = "[PLAY_RANSOMWARE]" ascii wide
        $play2 = "PLAY_README.txt" ascii wide
        $ext = ".play" ascii wide
        $mail = "@onionmail.org" ascii wide
    condition:
        $play1 or ($play2 and ($ext or $mail))
}
""",
    "ransomware_rhysida.yar": """rule Ransomware_Rhysida_Encryptor
{
    meta:
        description = "Detects Rhysida Ransomware PDF note generators and cmd scripts"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "ransomware"
    strings:
        $rhy1 = "Rhysida Ransomware" ascii wide nocase
        $rhy2 = "Critical Warning: Your system is infected" ascii wide nocase
        $pdf = "rhysida_note.pdf" ascii wide
        $cmd = "wevtutil cl System" ascii wide nocase
    condition:
        $rhy1 or ($rhy2 and ($pdf or $cmd))
}
""",
    "stealer_redline.yar": """rule Stealer_RedLine_Infostealer
{
    meta:
        description = "Detects RedLine Stealer configuration tokens and browser targeting"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $c1 = "Entity1" ascii wide
        $c2 = "ListOfProcesses" ascii wide
        $c3 = "ChromeCookies" ascii wide
        $c4 = "DiscordTokens" ascii wide
        $c5 = "TelegramSessions" ascii wide
        $c6 = "WalletAddresses" ascii wide
    condition:
        4 of ($c*)
}
""",
    "stealer_vidar.yar": """rule Stealer_Vidar_Harvest
{
    meta:
        description = "Detects Vidar Stealer C2 configuration and file harvesting paths"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $token1 = "VidarStealer" ascii wide nocase
        $dir1 = "Wallets\\\\Electrum" ascii wide
        $dir2 = "Autofill\\\\Chromium" ascii wide
        $param1 = "zip_password" ascii
        $net1 = "/api/client/handshake" ascii
    condition:
        $token1 or (2 of ($dir*) and 1 of ($param1, $net1))
}
""",
    "stealer_raccoon.yar": """rule Stealer_Raccoon_v2
{
    meta:
        description = "Detects Raccoon Stealer v2 payload memory structures and C2 protocol"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $rc1 = "RaccoonStealer2" ascii wide nocase
        $rc2 = "content-disposition: form-data" ascii
        $rc3 = "machineId" ascii
        $rc4 = "loaderId" ascii
        $rc5 = "credentials.txt" ascii wide
    condition:
        $rc1 or (3 of ($rc2, $rc3, $rc4, $rc5))
}
""",
    "stealer_agenttesla.yar": """rule Stealer_AgentTesla_Net
{
    meta:
        description = "Detects AgentTesla .NET keylogger, clipboard monitor, and SMTP exfiltration"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $tesla1 = "AgentTesla" ascii wide nocase
        $tesla2 = "GetClipboardText" ascii wide
        $tesla3 = "smtp.mailgun.org" ascii wide nocase
        $tesla4 = "IKeyboardHook" ascii wide
        $tesla5 = "RecoveredAccount" ascii wide
    condition:
        $tesla1 or 3 of ($tesla2, $tesla3, $tesla4, $tesla5)
}
""",
    "stealer_lumma.yar": """rule Stealer_LummaC2_Stealer
{
    meta:
        description = "Detects LummaC2 Stealer API unhooking, crypto wallet search and strings"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $lum1 = "LummaC2" ascii wide nocase
        $lum2 = "api/report" ascii
        $w1 = "Metamask" ascii wide nocase
        $w2 = "TronLink" ascii wide nocase
        $w3 = "BinanceChain" ascii wide nocase
        $str1 = "LUMMA_BUILD_ID" ascii wide
    condition:
        $lum1 or $str1 or ($lum2 and 2 of ($w*))
}
""",
    "stealer_formbook_xloader.yar": """rule Stealer_FormBook_XLoader
{
    meta:
        description = "Detects FormBook and XLoader form-grabbing and ntdll hook evasion"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $fb1 = "FormBook" ascii wide nocase
        $fb2 = "FBNT_HOOK" ascii wide
        $reg = "Explorer\\\\User Shell Folders" ascii wide
        $api1 = "ZwQueryVirtualMemory" ascii
        $str = "submit_data_form" ascii
    condition:
        $fb1 or $fb2 or ($reg and $api1 and $str)
}
""",
    "stealer_ducktail.yar": """rule Stealer_Ducktail_AdsManager
{
    meta:
        description = "Detects Ducktail infostealer targeting Facebook Ads and Business accounts"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "infostealer"
    strings:
        $dt1 = "Ducktail" ascii wide nocase
        $fb1 = "business.facebook.com" ascii wide
        $fb2 = "act_adaccount" ascii wide
        $tele1 = "api.telegram.org/bot" ascii wide
    condition:
        $dt1 or (all of ($fb*) and $tele1)
}
""",
    "stealer_stealc.yar": """rule Stealer_Stealc_Lightweight
{
    meta:
        description = "Detects Stealc C-based infostealer telemetry, RC4 keys and grabber rules"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $st1 = "Stealc" ascii wide nocase
        $st2 = "/api/v1/grab/" ascii
        $st3 = "sqlite3_open" ascii
        $st4 = "SELECT name, encrypted_value FROM cookies" ascii
    condition:
        $st1 or ($st2 and $st3 and $st4)
}
""",
    "stealer_meduza.yar": """rule Stealer_Meduza_Harvester
{
    meta:
        description = "Detects Meduza Stealer browser, password, and system fingerprinting"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "infostealer"
    strings:
        $med1 = "MeduzaStealer" ascii wide nocase
        $med2 = "meduza_client_id" ascii wide
        $w1 = "Exodus" ascii wide
        $w2 = "AtomicWallet" ascii wide
        $browser = "Google\\\\Chrome" ascii wide
    condition:
        $med1 or $med2 or (all of ($w*) and $browser)
}
""",
    "trojan_cobaltstrike_beacon.yar": """rule Trojan_CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon memory configurations, named pipes, and watermarks"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $pipe1 = "pipe\\\\msagent_" ascii wide
        $pipe2 = "pipe\\\\status_" ascii wide
        $post1 = "%s as %s" ascii
        $post2 = "Started service %s on %s" ascii
        $cs1 = "beacon.dll" ascii wide
        $cs2 = "ReflectiveLoader" ascii
    condition:
        $cs1 or (1 of ($pipe*) and 1 of ($post*)) or ($cs2 and 1 of ($post*))
}
""",
    "trojan_asyncrat.yar": """rule Trojan_AsyncRAT_Client
{
    meta:
        description = "Detects AsyncRAT configuration block, pastebin loader, and certificate hash"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $async1 = "AsyncRAT" ascii wide nocase
        $cfg1 = "Pastebin" ascii wide
        $cfg2 = "ServerCertificate" ascii wide
        $cfg3 = "Hwid" ascii wide
        $cfg4 = "InstalledBy" ascii wide
    condition:
        $async1 or (3 of ($cfg*))
}
""",
    "trojan_remcos.yar": """rule Trojan_Remcos_Pro_RAT
{
    meta:
        description = "Detects Remcos Professional Remote Access Trojan resources and commands"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $rem1 = "Remcos" ascii wide nocase
        $rem2 = "SETTINGS" ascii wide
        $cmd1 = "[Keyboard Logger]" ascii wide
        $cmd2 = "[Screen Capture]" ascii wide
        $pipe = "pipe\\\\remcos_ipc" ascii wide
    condition:
        $rem1 or $pipe or ($rem2 and 1 of ($cmd*))
}
""",
    "trojan_quasar_rat.yar": """rule Trojan_Quasar_RAT
{
    meta:
        description = "Detects QuasarRAT open-source .NET trojan client builds"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $q1 = "Quasar.Client" ascii wide
        $q2 = "QuasarClient" ascii wide
        $msg1 = "DoClientUpdate" ascii wide
        $msg2 = "DoDownloadAndExecute" ascii wide
        $reg = "SOFTWARE\\\\QuasarServer" ascii wide
    condition:
        1 of ($q*) or $reg or (all of ($msg*))
}
""",
    "trojan_njrat.yar": """rule Trojan_njRAT_Bladabindi
{
    meta:
        description = "Detects njRAT / Bladabindi registry persistence and C2 beacon formatting"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $nj1 = "njRAT" ascii wide nocase
        $nj2 = "Bladabindi" ascii wide nocase
        $sep = "|'|'|" ascii
        $net1 = "ll[ENTER]ll" ascii
        $cmd = "cmd.exe /c ping 127.0.0.1 -n 2" ascii
    condition:
        $nj1 or $nj2 or (2 of ($sep, $net1, $cmd))
}
""",
    "trojan_sliver_c2.yar": """rule Trojan_Sliver_C2_Implant
{
    meta:
        description = "Detects BishopFox Sliver Golang command-and-control implant strings"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $slv1 = "github.com/bishopfox/sliver" ascii
        $slv2 = "sliverpb." ascii
        $pipe = "pipe\\\\sliver-" ascii wide
        $proto = "sliver.Beacon" ascii
    condition:
        1 of ($slv*) or $pipe or $proto
}
""",
    "trojan_havoc_demon.yar": """rule Trojan_Havoc_C2_Demon
{
    meta:
        description = "Detects Havoc C2 Demon agent payload header and sleep encryption"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $havoc1 = "Havoc-Framework" ascii wide nocase
        $demon1 = "DemonAgent" ascii wide nocase
        $magic = { 44 45 4D 4F 4E 5F 43 32 }
        $pipe = "pipe\\\\havoc_" ascii wide
    condition:
        1 of ($havoc1, $demon1, $magic, $pipe)
}
""",
    "trojan_shadowpad.yar": """rule Trojan_ShadowPad_Modular
{
    meta:
        description = "Detects ShadowPad modular backdoor plugin dispatcher and config"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $sp1 = "ShadowPad" ascii wide nocase
        $mod1 = "Root_Plugin" ascii wide
        $mod2 = "Online_Plugin" ascii wide
        $pipe = "pipe\\\\sp_comm" ascii wide
    condition:
        $sp1 or $pipe or (all of ($mod*))
}
""",
    "trojan_icedid_bokbot.yar": """rule Trojan_IcedID_BokBot
{
    meta:
        description = "Detects IcedID / BokBot banking trojan loader and network handshake"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "trojan"
    strings:
        $id1 = "BokBot" ascii wide nocase
        $id2 = "IcedID" ascii wide nocase
        $cookie = "__gads=" ascii
        $pipe = "pipe\\\\icedid_" ascii wide
    condition:
        $id1 or $id2 or ($pipe and $cookie)
}
""",
    "webshell_chinachopper.yar": """rule WebShell_ChinaChopper
{
    meta:
        description = "Detects China Chopper compact web backdoors"
        category = "webshell"
    strings:
        $php1 = { 40 65 76 61 6C 28 24 5F 50 4F 53 54 }
        $php2 = { 65 76 61 6C 28 24 5F 52 45 51 55 45 53 54 }
        $aspx1 = "JScript" ascii nocase
        $aspx2 = "Request.Item[" ascii nocase
    condition:
        $php1 or $php2 or ($aspx1 and $aspx2)
}
""",
    "webshell_b374k.yar": """rule WebShell_b374k_PHP
{
    meta:
        description = "Detects b374k PHP advanced webshell headers, auth, and toolkits"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "webshell"
    strings:
        $b1 = "b374k" ascii wide
        $b2 = "b374k shell" ascii wide nocase
        $b3 = "$GLOBALS['pass']" ascii
        $b4 = "eval(gzinflate(base64_decode(" ascii
    condition:
        ($b1 or $b2) and ($b3 or $b4)
}
""",
    "webshell_wso.yar": """rule WebShell_WSO_FilesMan
{
    meta:
        description = "Detects WSO (FilesMan) PHP webshell authentication and action dispatchers"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "webshell"
    strings:
        $wso1 = "WSO " ascii wide
        $wso2 = "FilesMan" ascii wide
        $wso3 = "default_use_auth" ascii
        $wso4 = "action=SecInfo" ascii
        $wso5 = "action=Sql" ascii
    condition:
        ($wso1 or $wso2) and 2 of ($wso3, $wso4, $wso5)
}
""",
    "webshell_godzilla_memshell.yar": """rule WebShell_Godzilla_Behinder_JSP
{
    meta:
        description = "Detects Godzilla and Behinder dynamic classloader JSP memory shells"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "webshell"
    strings:
        $god1 = "passParameter" ascii
        $god2 = "ClassLoader.defineClass" ascii
        $beh1 = "Base64.getDecoder().decode" ascii
        $beh2 = "javax.crypto.Cipher" ascii
        $tag = "GODZILLA_MEMSHELL" ascii wide
    condition:
        $tag or (all of ($god*)) or (all of ($beh*))
}
""",
    "webshell_weevely.yar": """rule WebShell_Weevely_PHP
{
    meta:
        description = "Detects Weevely stealth PHP weaponized backdoor sessions"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "webshell"
    strings:
        $w1 = "weevely" ascii wide nocase
        $w2 = "$kh=" ascii
        $w3 = "$kf=" ascii
        $w4 = "gzuncompress(gzinflate(base64_decode" ascii
    condition:
        $w1 or (all of ($w2, $w3) and $w4)
}
""",
    "webshell_aspx_spy.yar": """rule WebShell_ASPX_Spy
{
    meta:
        description = "Detects ASPX Spy C# system and SQL interactive webshell"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "webshell"
    strings:
        $spy1 = "ASPX Spy" ascii wide nocase
        $spy2 = "public void ExecuteCommand" ascii
        $spy3 = "System.Diagnostics.ProcessStartInfo" ascii
        $spy4 = "SqlConnection conn = new SqlConnection" ascii
    condition:
        $spy1 or ($spy2 and $spy3) or ($spy3 and $spy4)
}
""",
    "botnet_mirai.yar": """rule Botnet_Mirai_IoT
{
    meta:
        description = "Detects Mirai IoT botnet strings, default telnet brute-force and attack vectors"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "botnet"
    strings:
        $m1 = "/bin/busybox" ascii
        $m2 = "MIRAI_CNC" ascii wide
        $m3 = "attack_udp_generic" ascii
        $m4 = "attack_syn" ascii
        $m5 = "root:xc3511" ascii
        $m6 = "admin:admin1234" ascii
    condition:
        $m2 or (2 of ($m3, $m4) and 1 of ($m1, $m5, $m6))
}
""",
    "botnet_gafgyt_qbot.yar": """rule Botnet_Gafgyt_BASHLITE
{
    meta:
        description = "Detects Gafgyt / BASHLITE / Lizkebab DDoS bot commands"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "botnet"
    strings:
        $g1 = "BASHLITE" ascii wide
        $g2 = "PONG" ascii
        $g3 = "SCANNER ON" ascii
        $g4 = "JUNKFLOOD" ascii
        $g5 = "HOLD attack" ascii
    condition:
        $g1 or 3 of ($g2, $g3, $g4, $g5)
}
""",
    "botnet_mozi.yar": """rule Botnet_Mozi_P2P
{
    meta:
        description = "Detects Mozi P2P DHT botnet configuration files and execution routines"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "botnet"
    strings:
        $mz1 = "Mozi.m" ascii wide
        $mz2 = "Mozi.a" ascii wide
        $dht = "dht_node_list" ascii
        $cfg = "[hp/config]" ascii
    condition:
        1 of ($mz*) or (all of ($dht, $cfg))
}
""",
    "botnet_emotet.yar": """rule Botnet_Emotet_Epoch
{
    meta:
        description = "Detects Emotet loader and network protocol command headers"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "botnet"
    strings:
        $emo1 = "Emotet_Epoch" ascii wide nocase
        $dll = "Gephi.dll" ascii wide
        $c2 = "POST / HTTP/1.1" ascii
        $cert = "EMOTET_ROOT_CA" ascii wide
    condition:
        $emo1 or ($dll and $c2) or $cert
}
""",
    "botnet_trickbot.yar": """rule Botnet_Trickbot_Anchor
{
    meta:
        description = "Detects Trickbot module names, injects, and Anchor DNS communication"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "botnet"
    strings:
        $tb1 = "TrickLoader" ascii wide nocase
        $mod1 = "injectDll32" ascii wide
        $mod2 = "systeminfo64" ascii wide
        $mod3 = "networkDll" ascii wide
        $anch = "Anchor_DNS" ascii wide
    condition:
        $tb1 or $anch or (2 of ($mod*))
}
""",
    "botnet_qakbot.yar": """rule Botnet_Qakbot_Pinkslipbot
{
    meta:
        description = "Detects Qakbot / Qbot packed loader signatures and email thread injection"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "botnet"
    strings:
        $qb1 = "Qakbot" ascii wide nocase
        $pipe = "pipe\\\\qbot_" ascii wide
        $log = "qbot_email_harvest.log" ascii wide
        $api = "calc_checksum_qak" ascii
    condition:
        $qb1 or $pipe or ($log and $api)
}
""",
    "wiper_hermeticwiper.yar": """rule Wiper_HermeticWiper
{
    meta:
        description = "Detects HermeticWiper (FoxBlade) partition and MBR destruction drivers"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "wiper"
    strings:
        $dr1 = "EPMNTDRV" ascii wide
        $dr2 = "HermeticWiper" ascii wide nocase
        $priv = "SeBackupPrivilege" ascii
        $dev = "PhysicalDrive0" ascii wide
    condition:
        $dr2 or ($dr1 and $priv and $dev)
}
""",
    "wiper_caddywiper.yar": """rule Wiper_CaddyWiper_Destructive
{
    meta:
        description = "Detects CaddyWiper zero-out filesystem and driver destructors"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "wiper"
    strings:
        $w1 = "CaddyWiper" ascii wide nocase
        $zero = "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX" ascii wide
        $ds = "Users\\\\Default" ascii wide
        $priv = "SeTakeOwnershipPrivilege" ascii
    condition:
        $w1 or ($zero and $ds and $priv)
}
""",
    "wiper_shamoon_disttrack.yar": """rule Wiper_Shamoon_Disttrack
{
    meta:
        description = "Detects Shamoon (Disttrack) master boot record overwriter and burning picture"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "wiper"
    strings:
        $sh1 = "Disttrack" ascii wide nocase
        $sh2 = "Shamoon" ascii wide nocase
        $drv = "ElDos RawDisk" ascii wide
        $res = "PKCS7_BURNING_IMAGE" ascii wide
    condition:
        1 of ($sh*) or ($drv and $res)
}
""",
    "wiper_notpetya.yar": """rule Wiper_NotPetya_ExPetr
{
    meta:
        description = "Detects NotPetya pseudo-ransomware MFT destructive overwriter"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "wiper"
    strings:
        $p1 = "we repair your drive, your computer cannot be shut down" ascii wide nocase
        $p2 = "wowsmith123456@posteo.net" ascii wide
        $sec = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" ascii wide
        $mft = "PhysicalDrive" ascii wide
    condition:
        $p2 or $sec or ($p1 and $mft)
}
""",
    "rootkit_kernel_hook.yar": """rule Rootkit_Kernel_Driver_Hooking
{
    meta:
        description = "Detects Windows kernel SSDT hook, DKOM and driver unhooking strings"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "rootkit"
    strings:
        $k1 = "KeServiceDescriptorTable" ascii
        $k2 = "PsLookupProcessByProcessId" ascii
        $k3 = "ObRegisterCallbacks" ascii
        $k4 = "IoCreateDevice" ascii
        $hook = "ZwTerminateProcess_Hook" ascii
    condition:
        $hook or (all of ($k1, $k2, $k3, $k4))
}
""",
    "injection_process_hollowing.yar": """rule Injection_Process_Hollowing
{
    meta:
        description = "Detects Process Hollowing (RunPE) API sequences"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "injection"
    strings:
        $api1 = "CreateProcessA" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "VirtualAllocEx" ascii
        $api4 = "WriteProcessMemory" ascii
        $api5 = "SetThreadContext" ascii
        $api6 = "ResumeThread" ascii
    condition:
        5 of ($api*)
}
""",
    "injection_reflective_dll.yar": """rule Injection_Reflective_DLL_Loader
{
    meta:
        description = "Detects Stephen Fewer Reflective DLL Injection exports and loader stubs"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "injection"
    strings:
        $exp1 = "ReflectiveLoader" ascii
        $exp2 = "_ReflectiveLoader@4" ascii
        $stub = { 4D 5A E8 00 00 00 00 58 }
        $hash = { 68 8E 4E 0E EC }
    condition:
        1 of ($exp*) or ($stub and $hash)
}
""",
    "exploit_log4shell_cve_2021_44228.yar": """rule Exploit_Log4Shell_JNDI
{
    meta:
        description = "Detects Log4j Log4Shell CVE-2021-44228 injection string formats"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "exploit"
    strings:
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:rmi://" ascii nocase
        $jndi3 = "${jndi:dns://" ascii nocase
        $jndi4 = "${lower:j}${lower:n}${lower:d}${lower:i}" ascii nocase
        $jndi5 = "${::-j}${::-n}${::-d}${::-i}" ascii nocase
    condition:
        1 of ($jndi*)
}
""",
    "exploit_eternalblue_ms17_010.yar": """rule Exploit_MS17_010_EternalBlue
{
    meta:
        description = "Detects MS17-010 EternalBlue SMBv1 pool grooming and exploit signatures"
        author = "malyz3r-threat-intel"
        threat_level = "critical"
        category = "exploit"
    strings:
        $eb1 = "EternalBlue" ascii wide nocase
        $eb2 = "DOUBLEPULSAR" ascii wide nocase
        $smb = { FF 53 4D 42 72 00 00 00 }
        $pool = "FragPoolGroom" ascii
    condition:
        1 of ($eb*) or ($smb and $pool)
}
""",
    "miner_xmrig_stratum.yar": """rule Miner_XMRig_Stratum_Config
{
    meta:
        description = "Detects XMRig cryptocurrency miner configuration, pools, and Stratum protocol"
        author = "malyz3r-threat-intel"
        threat_level = "high"
        category = "cryptominer"
    strings:
        $xmrig1 = "XMRig" ascii wide nocase
        $algo1 = "rx/0" ascii
        $algo2 = "RandomX" ascii
        $stratum = "stratum+tcp://" ascii
        $pool1 = "pool.minexmr.com" ascii
        $pool2 = "xmr.2miners.com" ascii
    condition:
        $xmrig1 or (1 of ($algo*) and $stratum) or 1 of ($pool*)
}
""",
}


def main():
    # First, self-test compilation of all rules
    for name, content in RULES.items():
        try:
            yara.compile(source=content)
        except Exception as e:
            print(f"FAILED rule compilation for {name}: {e}")
            raise

    print(f"All {len(RULES)} rules compiled individually without error!")

    target_dirs = [
        Path(r"c:\Users\Acer\Documents\ChatGPT\YARA\malware_scanner\rules"),
        Path(r"c:\Users\Acer\Documents\ChatGPT\YARA\malyz3r\malware_scanner\rules"),
    ]
    for d in target_dirs:
        d.mkdir(parents=True, exist_ok=True)
        for fname, content in RULES.items():
            fpath = d / fname
            fpath.write_text(content, encoding="utf-8")
        print(f"Wrote {len(RULES)} rules to {d}")

    # Validate directory compilation with compile_rules
    for d in target_dirs:
        rs = compile_rules(d)
        print(
            f"compile_rules({d}) succeeded! Found {len(rs.identifiers)} total rule identifiers in {len(list(d.glob('*.yar')))} files."
        )


if __name__ == "__main__":
    main()
