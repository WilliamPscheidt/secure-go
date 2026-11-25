package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_cache.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("falha ao criar store: %v", err)
	}
	defer store.Close()

	rec := &HashRecord{
		SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		FileName:     "test.exe",
		FilePath:     "C:\\Windows\\System32\\test.exe",
		Verdict:      VerdictSafe,
		ThreatName:   "",
		Positives:    0,
		TotalEngines: 72,
		Source:       "VirusTotal",
		CheckedAt:    time.Now(),
	}

	// 1. Salvar
	if err := store.Save(rec); err != nil {
		t.Fatalf("falha ao salvar registro: %v", err)
	}

	// 2. Buscar
	got, exists, err := store.Get(rec.SHA256)
	if err != nil {
		t.Fatalf("falha ao buscar registro: %v", err)
	}
	if !exists {
		t.Fatalf("esperava que o registro existisse")
	}
	if got.Verdict != VerdictSafe {
		t.Errorf("esperava veredito %s, obteve %s", VerdictSafe, got.Verdict)
	}

	// 3. IsSafe
	if !store.IsSafe(rec.SHA256) {
		t.Errorf("IsSafe deveria retornar true")
	}

	// 4. Salvar malicioso e checar stats
	malRec := &HashRecord{
		SHA256:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		FileName:     "malware.exe",
		FilePath:     "C:\\Users\\Temp\\malware.exe",
		Verdict:      VerdictMalicious,
		ThreatName:   "Trojan.Win32.Generic",
		Positives:    45,
		TotalEngines: 70,
		Source:       "MalwareBazaar",
		CheckedAt:    time.Now(),
	}
	if err := store.Save(malRec); err != nil {
		t.Fatalf("falha ao salvar registro malicioso: %v", err)
	}

	stats, err := store.GetStats()
	if err != nil {
		t.Fatalf("falha ao obter stats: %v", err)
	}
	if stats.Total != 2 || stats.Safe != 1 || stats.Malicious != 1 {
		t.Errorf("estatísticas incorretas: %+v", stats)
	}
}
