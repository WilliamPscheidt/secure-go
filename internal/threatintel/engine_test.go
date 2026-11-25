package threatintel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"secure-go/internal/cache"
)

func TestEngineCacheHit(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_engine.db")

	store, err := cache.NewStore(dbPath)
	if err != nil {
		t.Fatalf("falha ao criar store: %v", err)
	}
	defer store.Close()

	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// Pré-cadastra no banco como SAFE
	_ = store.Save(&cache.HashRecord{
		SHA256:       hash,
		FileName:     "calc.exe",
		Verdict:      cache.VerdictSafe,
		Source:       "VirusTotal",
		CheckedAt:    time.Now(),
		TotalEngines: 72,
	})

	engine := NewEngine(store, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := engine.AnalyzeHash(ctx, hash, "calc.exe", "C:\\Windows\\calc.exe", false)
	if err != nil {
		t.Fatalf("AnalyzeHash falhou: %v", err)
	}

	if res.Verdict != cache.VerdictSafe {
		t.Errorf("esperava veredito SAFE, obteve %s", res.Verdict)
	}
	if res.Source != "VirusTotal (Cache Local)" {
		t.Errorf("esperava fonte de cache local, obteve %s", res.Source)
	}
}
