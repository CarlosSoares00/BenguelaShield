rule RemcosRAT_Africa
{
    meta:
        description = "Detecta Remcos RAT - activo em Africa incluindo Angola"
        author = "BenguelaShield"
        severity = "critical"
        tags = "rat, windows, Africa"
    strings:
        $str1 = "Remcos" ascii wide nocase
        $str2 = "REMCOS_MUTEX_" ascii wide
        $str3 = "Breaking-Security.Net" ascii wide nocase
        $str4 = "remcos.exe" ascii wide nocase
        $reg1 = "Software\\Remcos" ascii wide nocase
        $cfg1 = "Host=" ascii wide
        $cfg2 = "license=" ascii wide nocase
        $cfg3 = "password=" ascii wide nocase
        $clip1 = "ClipboardData" ascii wide
        $key1 = "GetAsyncKeyState" ascii
        $cam1 = "avicap32" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (
            $str2 or
            $str4 or
            $reg1 or
            ($str1 and 2 of ($cfg*)) or
            ($str3 and any of ($cfg*)) or
            ($str1 and any of ($clip*, $key*, $cam*))
        )
}