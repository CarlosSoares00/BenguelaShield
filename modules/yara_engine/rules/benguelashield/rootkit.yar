rule Rootkit_Generico
{
    meta:
        description = "Detecta rootkits genericos"
        author = "BenguelaShield"
        severity = "critical"
        tags = "rootkit, kernel, stealth"
    strings:
        $hook1 = "NtQuerySystemInformation" ascii
        $hook2 = "ZwQuerySystemInformation" ascii
        $hook3 = "NtQueryDirectoryFile" ascii
        $hook4 = "NtEnumerateValueKey" ascii
        $hook5 = "NtOpenProcess" ascii
        $hook6 = "ZwOpenProcess" ascii
        $hide1 = "HideFile" ascii
        $hide2 = "HideProcess" ascii
        $hide3 = "HideRegistry" ascii
        $hide4 = "UnlinkProcess" ascii
        $driver1 = "IoCreateDriver" ascii
        $driver2 = "ZwLoadDriver" ascii
        $driver3 = "NtLoadDriver" ascii
        $driver4 = "ZwSetSystemInformation" ascii
        $dk1 = "DKOM" ascii
        $dk2 = "Direct Kernel Object" ascii nocase
        $dk3 = "ZwCreateSection" ascii
    condition:
        (3 of ($hook*)) or
        (2 of ($hook*) and 1 of ($hide*)) or
        (2 of ($driver*) and 1 of ($hook*)) or
        (1 of ($dk*) and 2 of ($hook*)) or
        (2 of ($hide*) and 1 of ($driver*))
}
