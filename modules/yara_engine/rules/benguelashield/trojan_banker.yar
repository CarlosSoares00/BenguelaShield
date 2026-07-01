rule Trojan_Banker_Generico
{
    meta:
        description = "Detecta trojans bancarios genericos"
        author = "BenguelaShield"
        severity = "critical"
        tags = "banker, trojan, credential-theft"
    strings:
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "SetWindowsHookEx" ascii
        $key3 = "GetKeyState" ascii
        $screen1 = "BitBlt" ascii
        $screen2 = "GetDesktopWindow" ascii
        $screen3 = "CreateCompatibleBitmap" ascii
        $screen4 = "GetWindowDC" ascii
        $bank1 = "banking" ascii nocase
        $bank2 = "login" ascii nocase
        $bank3 = "account" ascii nocase
        $bank4 = "password" ascii nocase
        $bank5 = "credit" ascii nocase
        $bank6 = "transfer" ascii nocase
        $cnc1 = "POST" ascii
        $cnc2 = "Content-Type: application/x-www-form-urlencoded" ascii
        $cnc3 = "User-Agent:" ascii
        $obf1 = "base64" ascii nocase
        $obf2 = "eval(" ascii
        $obf3 = "fromCharCode" ascii
        $obf4 = "unescape(" ascii
    condition:
        uint16(0) == 0x5A4D and (
            (2 of ($key*) and 2 of ($screen*)) or
            (2 of ($key*) and 2 of ($bank*)) or
            (2 of ($key*) and 1 of ($cnc*) and 1 of ($obf*)) or
            (1 of ($screen*) and 3 of ($bank*) and 1 of ($cnc*))
        )
}
