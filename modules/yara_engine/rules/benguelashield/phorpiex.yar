rule Phorpiex_Worm_Africa
{
    meta:
        description = "Detecta Phorpiex/Trik - worm de spam prevalente em Africa"
        author = "BenguelaShield"
        severity = "high"
        tags = "worm, spam, Africa, USB"
    strings:
        $mutex1 = "Phorpiex" ascii wide nocase
        $str1 = "trik" ascii wide nocase
        $str2 = "SpamBot" ascii wide nocase
        $irc1 = "PRIVMSG" ascii
        $irc2 = "USERHOST" ascii
        $irc3 = "JOIN #" ascii
        $spread1 = "*.exe" ascii wide
        $spread2 = "autorun.inf" ascii wide nocase
        $spread3 = "removable" ascii wide nocase
        $spam1 = "smtp" ascii nocase
        $spam2 = "mail from:" ascii nocase
    condition:
        uint16(0) == 0x5A4D and (
            $mutex1 or
            (2 of ($irc*) and any of ($spread*)) or
            ($str1 and any of ($spread*)) or
            ($str2 and any of ($spread*, $irc*)) or
            (2 of ($spam*) and any of ($irc*))
        )
}