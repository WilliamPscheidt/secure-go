package yara

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRuleString(t *testing.T) {
	sample := `
	rule Test_Rule : Trojan Malicious {
		meta:
			author = "Security Analyst"
			description = "Regra de teste unitário"
			threat_level = "CRITICAL"
		strings:
			$s1 = "malicious_string" ascii nocase
			$h1 = { 4D 5A ?? 00 }
		condition:
			any of them
	}
	`

	rules, err := ParseRuleString(sample)
	if err != nil {
		t.Fatalf("ParseRuleString falhou: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("esperava 1 regra, obteve %d", len(rules))
	}

	r := rules[0]
	if r.Name != "Test_Rule" {
		t.Errorf("esperava nome Test_Rule, obteve %s", r.Name)
	}
	if r.Meta.ThreatLevel != "CRITICAL" {
		t.Errorf("esperava threat_level CRITICAL, obteve %s", r.Meta.ThreatLevel)
	}
	if len(r.Patterns) != 2 {
		t.Errorf("esperava 2 padrões, obteve %d", len(r.Patterns))
	}
}

func TestDefaultScannerMatches(t *testing.T) {
	scanner, err := DefaultScanner()
	if err != nil {
		t.Fatalf("DefaultScanner falhou: %v", err)
	}

	if scanner.Count() == 0 {
		t.Fatal("esperava regras embutidas no scanner")
	}

	// 1. Testa detecção do Mimikatz (requer strings de comando e privilégio)
	mimikatzPayload := []byte("Iniciando injeção em memória... sekurlsa::logonpasswords e depois privilege::debug ativado!")
	matches, err := scanner.ScanBytes(mimikatzPayload)
	if err != nil {
		t.Fatalf("ScanBytes falhou: %v", err)
	}

	foundMimikatz := false
	for _, m := range matches {
		if m.RuleName == "Win32_Mimikatz_Lsass_Dump" {
			foundMimikatz = true
			if m.ThreatLevel != "CRITICAL" {
				t.Errorf("esperava nível CRITICAL, obteve %s", m.ThreatLevel)
			}
		}
	}
	if !foundMimikatz {
		t.Error("esperava detecção da regra Win32_Mimikatz_Lsass_Dump")
	}

	// 2. Testa detecção de Ransomware (vssadmin delete shadows)
	ransomPayload := []byte("cmd.exe /c vssadmin delete shadows /all /quiet & echo ransomware encrypted")
	matches, err = scanner.ScanBytes(ransomPayload)
	if err != nil {
		t.Fatalf("ScanBytes falhou: %v", err)
	}

	foundRansom := false
	for _, m := range matches {
		if m.RuleName == "Ransomware_ShadowCopy_Wiper" {
			foundRansom = true
		}
	}
	if !foundRansom {
		t.Error("esperava detecção da regra Ransomware_ShadowCopy_Wiper")
	}

	// 3. Testa amostra limpa (deve retornar 0 detecções)
	cleanPayload := []byte("Este é um arquivo de texto perfeitamente normal sem nenhuma instrução suspeita.")
	matches, err = scanner.ScanBytes(cleanPayload)
	if err != nil {
		t.Fatalf("ScanBytes falhou: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("esperava 0 matches em payload limpo, obteve %d", len(matches))
	}

	// 4. Testa que APIs do Windows sem string de log NÃO acionam falso positivo de Keylogger
	conhostLikePayload := []byte("Imports: GetAsyncKeyState, GetKeyboardState, SetWindowsHookExW (standard system UI hooks)")
	matches, err = scanner.ScanBytes(conhostLikePayload)
	if err != nil {
		t.Fatalf("ScanBytes falhou: %v", err)
	}
	for _, m := range matches {
		if m.RuleName == "Trojan_Keylogger_API_Hooks" {
			t.Errorf("falso positivo detectado: conhostLikePayload não deveria acionar Trojan_Keylogger_API_Hooks")
		}
	}

	// 5. Testa que Keylogger real (com string de log) É detectado
	actualKeylogger := []byte("GetAsyncKeyState hook active. [KEYLOGGER] saving keystrokes to disk...")
	matches, err = scanner.ScanBytes(actualKeylogger)
	if err != nil {
		t.Fatalf("ScanBytes falhou: %v", err)
	}
	foundKeylogger := false
	for _, m := range matches {
		if m.RuleName == "Trojan_Keylogger_API_Hooks" {
			foundKeylogger = true
		}
	}
	if !foundKeylogger {
		t.Error("esperava detecção da regra Trojan_Keylogger_API_Hooks para keylogger real")
	}
}

func TestScanFileYara(t *testing.T) {
	scanner, err := DefaultScanner()
	if err != nil {
		t.Fatalf("DefaultScanner falhou: %v", err)
	}

	tempDir := t.TempDir()
	malFile := filepath.Join(tempDir, "script_suspeito.bat")
	_ = os.WriteFile(malFile, []byte("@echo off\r\nwmic shadowcopy delete\r\n"), 0644)

	matches, err := scanner.ScanFile(malFile)
	if err != nil {
		t.Fatalf("ScanFile falhou: %v", err)
	}

	if len(matches) == 0 {
		t.Fatal("esperava detecção em arquivo suspeito no disco")
	}

	if matches[0].RuleName != "Ransomware_ShadowCopy_Wiper" {
		t.Errorf("esperava regra Ransomware_ShadowCopy_Wiper, obteve: %s", matches[0].RuleName)
	}
}

func TestEvalCondition(t *testing.T) {
	tests := []struct {
		name          string
		condStr       string
		matched       []string
		totalPatterns int
		want          bool
	}{
		{"any of them - true", "any of them", []string{"$s1"}, 3, true},
		{"any of them - false", "any of them", []string{}, 3, false},
		{"all of them - true", "all of them", []string{"$s1", "$s2", "$s3"}, 3, true},
		{"all of them - false", "all of them", []string{"$s1", "$s2"}, 3, false},
		{"2 of them - true", "2 of them", []string{"$s1", "$s2"}, 3, true},
		{"2 of them - false", "2 of them", []string{"$s1"}, 3, false},
		{"custom and/or", "($s1 and $s2) or $s3", []string{"$s3"}, 3, true},
		{"custom and/or false", "($s1 and $s2) or $s3", []string{"$s1"}, 3, false},
		{"group any of", "any of ($k1, $k2) and any of ($k3, $k4)", []string{"$k1", "$k4"}, 4, true},
		{"group any of false", "any of ($k1, $k2) and any of ($k3, $k4)", []string{"$k1", "$k2"}, 4, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvalCondition(tc.condStr, tc.matched, tc.totalPatterns)
			if got != tc.want {
				t.Errorf("EvalCondition(%q, %v, %d) = %v; esperado %v", tc.condStr, tc.matched, tc.totalPatterns, got, tc.want)
			}
		})
	}
}
