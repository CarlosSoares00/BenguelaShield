rule Crypto_Clipboard_Hijacker
{
    meta:
        description = "Detecta malware que substitui enderecos crypto no clipboard"
        author = "BenguelaShield"
        severity = "critical"
        tags = "clipboard, crypto, bitcoin"
    strings:
        $btc1 = "bitcoin" ascii nocase
        $eth1 = "0x" ascii
        $eth2 = "ethereum" ascii nocase
        $wallet1 = "wallet" ascii nocase
        $wallet2 = "blockchain" ascii nocase
        $clip1 = "OpenClipboard" ascii wide
        $clip2 = "SetClipboardData" ascii wide
        $clip3 = "GetClipboardData" ascii wide
        $clip4 = "CF_UNICODETEXT" ascii wide
        $clip5 = "EmptyClipboard" ascii wide
        $clip6 = "AddClipboardFormatListener" ascii wide
        $loop1 = "GetForegroundWindow" ascii wide
        $loop2 = "SleepEx" ascii wide
        $loop3 = "SetTimer" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of ($clip*) and
        ($btc1 or $eth1 or $eth2 or any of ($wallet*)) and
        ($clip6 or any of ($loop*))
}