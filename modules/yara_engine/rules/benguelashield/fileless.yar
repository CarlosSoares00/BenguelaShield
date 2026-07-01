rule Fileless_Malware
{
    meta:
        description = "Detecta fileless malware via PowerShell/WMI"
        author = "BenguelaShield"
        severity = "critical"
        tags = "fileless, powershell, wmi, living-off-the-land"
    strings:
        $ps1 = "powershell" ascii nocase
        $enc1 = "-enc" ascii nocase
        $enc2 = "-encodedcommand" ascii nocase
        $enc3 = "-EncodedCommand" ascii wide
        $dl1 = "DownloadString" ascii
        $dl2 = "DownloadData" ascii
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "Net.WebClient" ascii wide
        $exec1 = "IEX" ascii
        $exec2 = "Invoke-Expression" ascii nocase
        $exec3 = "Invoke-Command" ascii nocase
        $exec4 = "Start-Job" ascii nocase
        $wmi1 = "Win32_Process" ascii nocase
        $wmi2 = "Create()" ascii
        $wmi3 = "CommandLineEventConsumer" ascii nocase
        $wmi4 = "Win32_EventFilter" ascii nocase
        $wmi5 = "CreateObject(\"WScript.Shell\")" ascii nocase
        $ref1 = "System.Reflection.Assembly" ascii nocase
        $ref2 = "FromBase64String" ascii
        $ref3 = "Load" ascii
        $amsi1 = "AmsiUtils" ascii
        $amsi2 = "AmsiScanBuffer" ascii
        $amsi3 = "amsiInitFailed" ascii
    condition:
        ($ps1 and any of ($enc*) and any of ($dl*)) or
        ($ps1 and any of ($enc*) and any of ($exec*)) or
        ($ps1 and any of ($ref*) and $ref2) or
        ($wmi1 and $wmi2 and any of ($exec*)) or
        ($wmi1 and any of ($wmi*, $exec*)) or
        ($ps1 and any of ($amsi*) and any of ($enc*))
}
