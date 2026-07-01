rule Worm_Generico
{
    meta:
        description = "Detecta worms genericos"
        author = "BenguelaShield"
        severity = "high"
        tags = "worm, network, propagation"
    strings:
        $net1 = "NetShareEnum" ascii
        $net2 = "WNetEnumResource" ascii
        $net3 = "NetUserEnum" ascii
        $net4 = "NetShareAdd" ascii
        $net5 = "WNetOpenEnum" ascii
        $copy1 = "CopyFile" ascii
        $copy2 = "SHFileOperation" ascii
        $copy3 = "CopyFileEx" ascii
        $copy4 = "MoveFileEx" ascii
        $spread1 = "autorun.inf" ascii nocase
        $spread2 = "RECYCLER" ascii
        $spread3 = "System Volume Information" ascii
        $spread4 = " removable" ascii nocase
        $prop1 = "ShellExecute" ascii
        $prop2 = "CreateProcess" ascii
        $prop3 = "WinExec" ascii
        $prop4 = "ShellExecuteA" ascii
    condition:
        (2 of ($net*) and 2 of ($copy*)) or
        (1 of ($net*) and 1 of ($spread*) and 1 of ($prop*)) or
        (2 of ($copy*) and 1 of ($spread*)) or
        (3 of ($copy*) and 1 of ($prop*))
}
