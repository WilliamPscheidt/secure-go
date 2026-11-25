package yara

// DefaultBuiltinRules contém o conjunto oficial de regras YARA embutidas no SecureGo.
const DefaultBuiltinRules = `
rule Win32_Mimikatz_Lsass_Dump {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Detecta comandos e stubs de extração de credenciais do Mimikatz / LSASS"
        threat_level = "CRITICAL"
        reference = "MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "privilege::debug" ascii nocase
        $s3 = "sekurlsa::wdigest" ascii nocase
        $s4 = "MiniDumpWriteDump" ascii
        $s5 = "lsasrv.dll" ascii nocase
    condition:
        ($s1 and $s2) or ($s1 and $s3) or ($s3 and $s4) or ($s2 and $s5 and $s4)
}

rule Ransomware_ShadowCopy_Wiper {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Comandos comuns de ransomware para exclusão de cópias de sombra e restauração"
        threat_level = "CRITICAL"
        reference = "MITRE ATT&CK T1490 (Inhibit System Recovery)"
    strings:
        $cmd1 = "vssadmin delete shadows" ascii nocase
        $cmd2 = "vssadmin.exe delete shadows" ascii nocase
        $cmd3 = "wmic shadowcopy delete" ascii nocase
        $cmd4 = "wbadmin delete catalog" ascii nocase
        $cmd5 = "bcdedit /set {default} recoveryenabled no" ascii nocase
        $cmd6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii nocase
    condition:
        any of them
}

rule PowerShell_Reverse_Shell {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Detecta payloads e stubs de Reverse Shell interativo via PowerShell"
        threat_level = "HIGH"
        reference = "MITRE ATT&CK T1059.001 (PowerShell Execution)"
    strings:
        $p1 = "Net.Sockets.TCPClient" ascii nocase
        $p2 = "System.Text.ASCIIEncoding" ascii nocase
        $p3 = "DownloadString" ascii nocase
        $p4 = "-WindowStyle Hidden -ExecutionPolicy Bypass" ascii nocase
        $p5 = "IEX" ascii nocase
    condition:
        ($p1 and $p2) or ($p4 and $p3 and $p5)
}

rule Webshell_Generic_Backdoor {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Detecta comandos clássicos de execução arbitrária e WebShells"
        threat_level = "HIGH"
        reference = "MITRE ATT&CK T1505.003 (Server Software Component: Web Shell)"
    strings:
        $w1 = "passthru($_" ascii
        $w2 = "eval(base64_decode" ascii
        $w3 = "shell_exec($_" ascii
        $w4 = "system($_GET" ascii
        $w5 = "cmd.exe /c whoami" ascii nocase
    condition:
        any of them
}

rule CoinMiner_Stratum_Pool {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Detecta conexão a pools de mineração de criptomoeda (Monero / XMRig)"
        threat_level = "MEDIUM"
        reference = "MITRE ATT&CK T1496 (Resource Hijacking)"
    strings:
        $m1 = "stratum+tcp://" ascii nocase
        $m2 = "stratum+ssl://" ascii nocase
        $m3 = "stratum+udp://" ascii nocase
        $m4 = "cryptonight" ascii nocase
        $m5 = "xmrig" ascii nocase
        $m6 = "donate-level" ascii nocase
    condition:
        any of ($m1, $m2, $m3) or (any of ($m4, $m5) and $m6)
}

rule Trojan_Keylogger_API_Hooks {
    meta:
        author = "SecureGo Threat Intelligence"
        description = "Identifica chamadas típicas de captura de digitação associadas a rotinas de log"
        threat_level = "HIGH"
        reference = "MITRE ATT&CK T1056.001 (Keylogging)"
    strings:
        $k1 = "GetAsyncKeyState" ascii
        $k2 = "SetWindowsHookExW" ascii
        $k3 = "GetKeyboardState" ascii
        $k4 = "[KEYLOGGER]" ascii nocase
        $k5 = "KeyStroke:" ascii nocase
        $k6 = "keys.log" ascii nocase
    condition:
        any of ($k1, $k2, $k3) and any of ($k4, $k5, $k6)
}
`

// DefaultScanner instancia um motor YARA com todas as regras nativas pré-compiladas.
func DefaultScanner() (*Scanner, error) {
	scanner := NewScanner()
	_, err := scanner.AddRulesFromSource(DefaultBuiltinRules)
	if err != nil {
		return nil, err
	}
	return scanner, nil
}
