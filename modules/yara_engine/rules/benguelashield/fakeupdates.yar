rule FakeUpdates_SocGholish
{
    meta:
        description = "Detecta FakeUpdates/SocGholish - downloader disfarcado de update"
        author = "BenguelaShield"
        severity = "high"
        reference = "Google TAG 2024"
        tags = "downloader, fakeupdate, socgholish"
    strings:
        $fake1 = "Chrome Update" nocase wide ascii
        $fake2 = "Firefox Update" nocase wide ascii
        $fake3 = "Windows Update" nocase wide ascii
        $fake4 = "Adobe Update" nocase wide ascii
        $fake5 = "Flash Player Update" nocase wide ascii
        $fake6 = "Java Update" nocase wide ascii
        $js1 = "eval(" ascii
        $js2 = "WScript.Shell" ascii wide nocase
        $js3 = "ActiveXObject" ascii wide nocase
        $js4 = "Scripting.FileSystemObject" ascii wide nocase
        $dl1 = "URLDownloadToFile" ascii wide
        $dl2 = "WinHttp.WinHttpRequest" ascii wide nocase
        $dl3 = "MSXML2.XMLHTTP" ascii wide nocase
        $dl4 = "XMLHTTP" ascii wide
        $exec1 = "ShellExecute" ascii wide
        $exec2 = "Run" ascii wide
        $exec3 = "exec(" ascii
    condition:
        (any of ($fake*) and any of ($js*) and any of ($dl*)) or
        (any of ($fake*) and any of ($js*) and any of ($exec*))
}
