rule Webshell_PHP_Generico
{
    meta:
        description = "Detecta webshells PHP genericos"
        author = "BenguelaShield"
        severity = "high"
        tags = "webshell, php, backdoor"
    strings:
        $exec1 = "system(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "passthru(" ascii
        $exec4 = "shell_exec(" ascii
        $exec5 = "popen(" ascii
        $exec6 = "proc_open(" ascii
        $eval1 = "eval(" ascii
        $eval2 = "assert(" ascii
        $eval3 = "preg_replace(" ascii
        $eval4 = "create_function(" ascii
        $obf1 = "base64_decode" ascii
        $obf2 = "gzinflate" ascii
        $obf3 = "gzuncompress" ascii
        $obf4 = "str_rot13" ascii
        $obf5 = "gzdecode" ascii
        $obf6 = "convert_uudecode" ascii
        $danger1 = "file_get_contents" ascii
        $danger2 = "file_put_contents" ascii
        $danger3 = "move_uploaded_file" ascii
        $danger4 = "chmod(" ascii
        $danger5 = "unlink(" ascii
        $ws1 = "$_REQUEST" ascii
        $ws2 = "$_POST" ascii
        $ws3 = "$_GET" ascii
        $ws4 = "$_COOKIE" ascii
    condition:
        (2 of ($eval*) and 1 of ($obf*)) or
        (1 of ($exec*) and 1 of ($eval*)) or
        (1 of ($eval*) and 2 of ($obf*) and 1 of ($ws*)) or
        (2 of ($danger*) and 1 of ($eval*) and 1 of ($ws*)) or
        (1 of ($exec*) and 1 of ($danger*) and 1 of ($ws*))
}

rule Webshell_ASP_Generico
{
    meta:
        description = "Detecta webshells ASP/ASPX genericos"
        author = "BenguelaShield"
        severity = "high"
        tags = "webshell, asp, aspx, backdoor"
    strings:
        $eval1 = "eval(Request" ascii nocase
        $eval2 = "execute(Request" ascii nocase
        $eval3 = "ExecuteGlobal(Request" ascii nocase
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "WScript.Shell" ascii nocase
        $cmd3 = "Process.Start" ascii nocase
        $io1 = "StreamReader" ascii wide
        $io2 = "StreamWriter" ascii wide
        $io3 = "System.IO" ascii wide
        $net1 = "WebClient" ascii wide
        $net2 = "HttpWebRequest" ascii wide
        $net3 = "DownloadFile" ascii wide
    condition:
        any of ($eval*) or
        (2 of ($cmd*) and any of ($io*)) or
        (any of ($cmd*) and any of ($net*))
}
