rule QuasarRAT_Angola
{
    meta:
        description = "Detecta QuasarRAT - RAT comum em Angola"
        author = "BenguelaShield"
        severity = "critical"
        tags = "rat, windows, dotnet"
    strings:
        $mutex = "QSR_MUTEX_" ascii wide
        $str1 = "Quasar" ascii wide nocase
        $str2 = "DoShellExecute" ascii wide
        $str3 = "DoDownloadAndExecute" ascii wide
        $str4 = "DoUploadAndExecute" ascii wide
        $str5 = "get_IsAdministrator" ascii wide
        $str6 = "get_ScreenCapture" ascii wide
        $pdb = "\\Quasar\\" ascii
        $net1 = "SslStream" ascii wide
        $enc1 = "RijndaelManaged" ascii wide
    condition:
        uint16(0) == 0x5A4D and (
            $mutex or
            $pdb or
            ($str1 and any of ($net*)) or
            (3 of ($str*) and any of ($enc*))
        )
}