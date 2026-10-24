
rule PHP_Webshell_Candidate {
    meta:
        description = "Experimental PHP webshell heuristic; source-label benchmark only"
        status = "research candidate, not production validated"
    strings:
        $php = "<?" ascii
        $input1 = "$_POST" ascii
        $input2 = "$_GET" ascii
        $input3 = "$_REQUEST" ascii
        $input4 = "$_COOKIE" ascii
        $exec1 = "eval(" ascii
        $exec2 = "assert(" ascii
        $exec3 = "system(" ascii
        $exec4 = "exec(" ascii
        $exec5 = "passthru(" ascii
        $exec6 = "popen(" ascii
        $exec7 = "proc_open(" ascii
        $obfuscation1 = "base64_decode" ascii
        $obfuscation2 = "gzinflate" ascii
        $brand1 = "WSO_VERSION" ascii
        $brand2 = "FilesMan" ascii
        $brand3 = "b374k" ascii nocase
        $brand4 = "c99shell" ascii nocase
        $brand5 = "r57shell" ascii nocase
    condition:
        filesize < 4MB and $php and (any of ($brand*) or (any of ($input*) and any of ($exec*)) or (any of ($exec*) and any of ($obfuscation*)))
}
