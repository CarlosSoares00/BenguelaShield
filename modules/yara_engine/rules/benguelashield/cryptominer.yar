rule Cryptominer_Generico
{
    meta:
        description = "Detecta cryptominers genericos"
        author = "BenguelaShield"
        severity = "high"
        tags = "cryptominer, mining, cryptojacking"
    strings:
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $pool3 = "pool.minexmr.com" ascii
        $pool4 = "nanopool.org" ascii
        $pool5 = "nicehash" ascii
        $pool6 = "moneropool" ascii
        $pool7 = "hashvault" ascii
        $pool8 = "minergate" ascii
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
        $algo4 = "kawpow" ascii nocase
        $algo5 = "equihash" ascii nocase
        $algo6 = "argon2" ascii nocase
        $xmrig1 = "xmrig" ascii nocase
        $xmrig2 = "--donate-level" ascii
        $xmrig3 = "--threads" ascii
        $xmrig4 = "-o stratum" ascii
        $xmrig5 = "xmrig-amd" ascii nocase
        $xmrig6 = "xmrig-nvidia" ascii nocase
        $mining1 = "hashrate" ascii nocase
        $mining2 = "difficulty" ascii nocase
        $mining3 = "nonce" ascii
        $mining4 = "getwork" ascii
        $mining5 = "submit" ascii
        $mining6 = "share" ascii
        $cpu1 = "CPU" ascii
        $cpu2 = "OpenCL" ascii
        $cpu3 = "CUDA" ascii
    condition:
        (3 of ($pool*)) or
        (3 of ($pool*)) or
        (2 of ($algo*)) or
        (2 of ($xmrig*)) or
        (1 of ($pool*) and 2 of ($algo*)) or
        (1 of ($pool*) and 2 of ($mining*)) or
        (2 of ($xmrig*) and 1 of ($mining*)) or
        (1 of ($pool*) and 1 of ($algo*) and 1 of ($mining*)) or
        (1 of ($algo*) and 1 of ($xmrig*) and any of ($cpu*))
}
