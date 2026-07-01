rule AsyncRAT_Angola
{
    meta:
        description = "Detecta AsyncRAT - ameaca numero 1 em Angola"
        author = "BenguelaShield"
        severity = "critical"
        tags = "rat, windows, Angola"
    strings:
        $mutex1 = "AsyncMutex_" ascii wide
        $mutex2 = "AsyncSettingsMutex_" ascii wide
        $str1 = "AsyncRAT" ascii wide nocase
        $str2 = "Pastebin" ascii wide
        $str3 = "get_Username" ascii wide
        $str4 = "get_MachineName" ascii wide
        $str5 = "get_IsAdmin" ascii wide
        $str6 = "get_Webcam" ascii wide
        $cfg1 = "Hosts=" ascii
        $cfg2 = "Ports=" ascii
        $cfg3 = "Version=" ascii
        $cfg4 = "Install=" ascii
        $net1 = "TCPClient" ascii wide
        $net2 = "NetworkStream" ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            any of ($mutex*) or
            ($str1 and 2 of ($cfg*)) or
            (3 of ($str*) and any of ($cfg*)) or
            ($str1 and any of ($net*) and any of ($cfg*))
        )
}