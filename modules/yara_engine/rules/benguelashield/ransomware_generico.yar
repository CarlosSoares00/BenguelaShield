rule Ransomware_Generico
{
    meta:
        description = "Detecta ransomware generico baseado em strings comuns"
        author = "BenguelaShield"
        severity = "critical"
        tags = "ransomware, encryption, bitcoin"
    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "your files are encrypted" nocase
        $ransom3 = "pay bitcoin" nocase
        $ransom4 = "decrypt your files" nocase
        $ransom5 = "send payment" nocase
        $ransom6 = "your important files" nocase
        $ransom7 = "files will be deleted" nocase
        $ransom8 = "data will be lost" nocase
        $encrypt1 = "AES-256" ascii
        $encrypt2 = "RSA-2048" ascii
        $encrypt3 = "AES-128" ascii
        $ext1 = ".encrypted" ascii nocase
        $ext2 = ".locked" ascii nocase
        $ext3 = ".crypto" ascii nocase
        $ext4 = ".crypt" ascii nocase
        $ext5 = ".wnry" ascii nocase
        $ext6 = ".wcry" ascii nocase
        $btc1 = "bitcoin" ascii nocase
        $btc2 = "wallet" ascii nocase
        $instr1 = "how to decrypt" ascii nocase
        $instr2 = "DECRYPT" ascii
        $instr3 = "recover files" ascii nocase
        $instr4 = "decryption instructions" ascii nocase
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wbadmin delete catalog" ascii nocase
    condition:
        (3 of ($ransom*) and 1 of ($encrypt*)) or
        (2 of ($ransom*) and 2 of ($encrypt*)) or
        (2 of ($ransom*) and 1 of ($ext*) and 1 of ($btc*)) or
        (1 of ($ransom*) and 1 of ($ext*) and 1 of ($shadow*)) or
        (2 of ($ransom*) and 2 of ($instr*)) or
        (1 of ($ransom*) and 1 of ($ext*) and 1 of ($instr*))
}