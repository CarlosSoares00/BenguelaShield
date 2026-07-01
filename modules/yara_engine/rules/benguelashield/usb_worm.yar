rule USB_Shortcut_Worm_Angola
{
    meta:
        description = "Detecta virus de atalho LNK via USB - muito comum em Angola"
        author = "BenguelaShield"
        severity = "critical"
        tags = "USB, worm, LNK, Angola"
    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd.exe" nocase wide ascii
        $cmd2 = "wscript" nocase wide ascii
        $cmd3 = "powershell" nocase wide ascii
        $cmd4 = "mshta" nocase wide ascii
        $hide1 = "attrib +h +s" nocase
        $hide2 = "attrib +H +S" nocase
        $copy1 = "xcopy" nocase
        $copy2 = "/E /H /C /I" nocase
        $reg1 = "CurrentVersion\\Run" ascii nocase
    condition:
        $lnk_header at 0 and (
            (($cmd1 or $cmd2 or $cmd3 or $cmd4) and ($hide1 or $hide2)) or
            (($cmd1 or $cmd2 or $cmd3) and ($copy1 or $copy2)) or
            (($cmd1 or $cmd2 or $cmd3) and $reg1)
        )
}

rule USB_Autorun_Malicioso
{
    meta:
        description = "Autorun.inf malicioso em USB"
        author = "BenguelaShield"
        severity = "critical"
        tags = "USB, autorun, worm"
    strings:
        $autorun = "[autorun]" nocase
        $open = "open=" nocase
        $shellexec = "shellexecute=" nocase
        $exe1 = ".exe" nocase
        $exe2 = ".vbs" nocase
        $exe3 = ".bat" nocase
        $exe4 = ".cmd" nocase
        $exe5 = ".pif" nocase
        $exe6 = ".scr" nocase
    condition:
        filesize < 1KB and
        $autorun and
        ($open or $shellexec) and
        any of ($exe*)
}

rule VBS_Worm_USB_Angola
{
    meta:
        description = "VBScript worm via USB - padrao comum em Angola"
        author = "BenguelaShield"
        severity = "critical"
        tags = "USB, VBS, worm, Angola"
    strings:
        $vbs1 = "WScript.Shell" nocase
        $vbs2 = "CreateObject" nocase
        $vbs3 = "Scripting.FileSystemObject" nocase
        $usb1 = "removable" nocase
        $usb2 = "DriveType" nocase
        $usb3 = "GetDrive" nocase
        $copy1 = "CopyFile" nocase
        $copy2 = "CopyFolder" nocase
        $hide1 = "attrib" nocase
        $hide2 = "Hidden" nocase
    condition:
        (any of ($vbs*)) and
        (any of ($usb*)) and
        (($copy1 or $copy2) or ($hide1 and $hide2))
}