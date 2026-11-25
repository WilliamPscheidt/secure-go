package heuristics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	// Dados uniformes (apenas zeros): entropia deve ser 0.0
	zeroBytes := make([]byte, 1024)
	entZero := CalculateEntropy(zeroBytes)
	if entZero != 0.0 {
		t.Errorf("esperava entropia 0.0 para dados homogêneos, obteve %f", entZero)
	}

	// Dados distribuídos igualmente (todos os 256 bytes possíveis repetidos): entropia máxima ~8.0
	var allBytes []byte
	for i := 0; i < 4; i++ {
		for b := 0; b < 256; b++ {
			allBytes = append(allBytes, byte(b))
		}
	}
	entMax := CalculateEntropy(allBytes)
	if entMax < 7.99 {
		t.Errorf("esperava entropia próxima a 8.0, obteve %f", entMax)
	}
}

func TestVerifyAuthenticode(t *testing.T) {
	// 1. Testa arquivo com assinatura Authenticode embutida (como git.exe)
	gitPath := "C:\\Program Files\\Git\\cmd\\git.exe"
	if _, err := os.Stat(gitPath); err == nil {
		sig := VerifyAuthenticode(gitPath)
		t.Logf("Authenticode para %s: Assinado=%v, Confiável=%v, Status=%s",
			gitPath, sig.IsSigned, sig.IsTrusted, sig.Status)
		if !sig.IsSigned || !sig.IsTrusted {
			t.Errorf("esperava que git.exe tivesse assinatura Authenticode válida")
		}
	}

	// 2. Arquivo inexistente
	sigInvalid := VerifyAuthenticode("C:\\arquivo_que_nao_existe_123456.exe")
	if sigInvalid.IsTrusted {
		t.Errorf("arquivo inexistente não deveria ser confiável")
	}
}

func TestAnalyzePE(t *testing.T) {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	notepadPath := filepath.Join(systemRoot, "System32", "notepad.exe")
	if _, err := os.Stat(notepadPath); err == nil {
		res := AnalyzePE(notepadPath)
		if !res.IsValidPE {
			t.Errorf("esperava que notepad.exe fosse um PE válido")
		}
		if len(res.Sections) == 0 {
			t.Errorf("esperava encontrar seções no PE do notepad.exe")
		}
		t.Logf("Notepad PE: Arq=%s, Seções=%d, MaxEntropy=%.2f",
			res.Architecture, len(res.Sections), res.MaxEntropy)
	}
}
