rule Pirated_Software_Dropper_Angola
{
    meta:
        description = "Dropper comum em software pirata - contexto Angola"
        author = "BenguelaShield"
        severity = "high"
        tags = "dropper, pirated, Angola, social-engineering"
    strings:
        $crack1 = "crack" nocase ascii wide
        $crack2 = "keygen" nocase ascii wide
        $crack3 = "patch" nocase ascii wide
        $crack4 = "activator" nocase ascii wide
        $crack5 = "loader" nocase ascii wide
        $crack6 = "serial" nocase ascii wide
        $crack7 = "registered" nocase ascii wide
        $dl1 = "URLDownloadToFile" ascii wide
        $dl2 = "http://" ascii
        $dl3 = "https://" ascii
        $dl4 = "WebClient" ascii wide
        $exec1 = "ShellExecute" ascii wide
        $exec2 = "CreateProcess" ascii wide
        $exec3 = "WinExec" ascii wide
        $obf1 = "base64" ascii nocase
        $obf2 = "eval(" ascii
        $obf3 = "fromCharCode" ascii
        $obf4 = "decodeURIComponent" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        any of ($crack*) and
        any of ($dl*) and
        any of ($exec*) and
        any of ($obf*)
}

rule Malware_Social_Engineering_Angola
{
    meta:
        description = "Malware que usa engenharia social comum em Angola"
        author = "BenguelaShield"
        severity = "high"
        tags = "social-engineering, Angola, phishing"
    strings:
        $doc1 = "documento" ascii nocase
        $doc2 = "factura" ascii nocase
        $doc3 = "comprovativo" ascii nocase
        $doc4 = "declaracao" ascii nocase
        $doc5 = "contrato" ascii nocase
        $pay1 = "pagamento" ascii nocase
        $pay2 = "transferencia" ascii nocase
        $pay3 = "IBAN" ascii nocase
        $exe1 = ".exe" ascii nocase
        $exe2 = ".scr" ascii nocase
        $dl1 = "URLDownloadToFile" ascii wide
        $dl2 = "WebClient" ascii wide
    condition:
        (2 of ($doc*) or 2 of ($pay*)) and
        any of ($exe*) and
        any of ($dl*)
}
