rule Keylogger_Generico
{
    meta:
        description = "Detecta keyloggers genericos"
        author = "BenguelaShield"
        severity = "high"
        tags = "keylogger, spyware, credential-theft"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookEx" ascii
        $k3 = "GetKeyState" ascii
        $k4 = "GetKeyboardState" ascii
        $k5 = "MapVirtualKey" ascii
        $k6 = "GetKeyboardLayout" ascii
        $log1 = "keyboard" ascii nocase
        $log2 = "keystroke" ascii nocase
        $log3 = "keylog" ascii nocase
        $log4 = "password" ascii nocase
        $log5 = "credential" ascii nocase
        $log6 = "credential" ascii nocase
        $file1 = "CreateFile" ascii
        $file2 = "WriteFile" ascii
        $file3 = "fopen" ascii
        $file4 = "fwrite" ascii
        $file5 = "FILE_APPEND" ascii
        $screen1 = "BitBlt" ascii
        $screen2 = "GetDesktopWindow" ascii
        $screen3 = "GetDC" ascii
    condition:
        (3 of ($k*)) or
        (2 of ($k*) and 1 of ($log*)) or
        (2 of ($k*) and 2 of ($file*)) or
        (1 of ($k*) and 1 of ($screen*) and 1 of ($log*))
}
