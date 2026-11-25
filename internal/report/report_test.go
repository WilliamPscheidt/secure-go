package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secure-go/internal/cache"
)

func TestExportToCSVAndJSON(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "relatorio_teste.csv")
	jsonPath := filepath.Join(tempDir, "relatorio_teste.json")

	records := []*cache.HashRecord{
		{
			SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			FileName:     "test_safe.exe",
			FilePath:     "C:\\test\\test_safe.exe",
			Verdict:      cache.VerdictSafe,
			TotalEngines: 70,
			Source:       "Authenticode",
			CheckedAt:    time.Now(),
			MBChecked:    true,
			VTChecked:    true,
		},
		{
			SHA256:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			FileName:     "trojan_sample.exe",
			FilePath:     "C:\\temp\\trojan_sample.exe",
			Verdict:      cache.VerdictMalicious,
			ThreatName:   "Win32.Trojan.Agent",
			Positives:    45,
			TotalEngines: 70,
			Source:       "VirusTotal",
			CheckedAt:    time.Now(),
			MBChecked:    true,
			VTChecked:    true,
		},
	}

	// 1. Testa CSV
	if err := ExportToCSV(records, csvPath); err != nil {
		t.Fatalf("ExportToCSV falhou: %v", err)
	}

	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("falha ao ler CSV gerado: %v", err)
	}
	if !strings.Contains(string(csvData), "test_safe.exe") || !strings.Contains(string(csvData), "trojan_sample.exe") {
		t.Errorf("conteúdo esperado não encontrado no CSV")
	}

	// 2. Testa JSON
	if err := ExportToJSON(records, jsonPath); err != nil {
		t.Fatalf("ExportToJSON falhou: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("falha ao ler JSON gerado: %v", err)
	}
	if !strings.Contains(string(jsonData), `"safe": 1`) || !strings.Contains(string(jsonData), `"malicious": 1`) {
		t.Errorf("sumário esperado não encontrado no JSON")
	}
}
