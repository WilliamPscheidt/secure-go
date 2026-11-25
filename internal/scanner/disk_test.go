package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/hasher"
	"secure-go/internal/threatintel"
)

func TestDiskScannerWithCleanCache(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_disk_scanner.db")

	store, err := cache.NewStore(dbPath)
	if err != nil {
		t.Fatalf("falha ao criar store: %v", err)
	}
	defer store.Close()

	engine := threatintel.NewEngine(store, "")
	scanner := NewDiskScanner(engine, 2)

	// Cria arquivos de teste
	safeFilePath := filepath.Join(tempDir, "clean_app.exe")
	safeContent := []byte("legitimate safe application binary content")
	if err := os.WriteFile(safeFilePath, safeContent, 0755); err != nil {
		t.Fatalf("falha ao criar arquivo de teste: %v", err)
	}

	safeHash, err := hasher.ComputeFileSHA256(safeFilePath)
	if err != nil {
		t.Fatalf("falha ao calcular hash: %v", err)
	}

	// Pré-registra esse hash no banco local como SAFE ("Seguro")
	err = store.Save(&cache.HashRecord{
		SHA256:       safeHash,
		FileName:     "clean_app.exe",
		FilePath:     safeFilePath,
		Verdict:      cache.VerdictSafe,
		Source:       "PreCheckedClean",
		CheckedAt:    time.Now(),
		TotalEngines: 70,
	})
	if err != nil {
		t.Fatalf("falha ao salvar registro limpo no banco: %v", err)
	}

	// Cria outro arquivo não-executável para testar filtro
	txtPath := filepath.Join(tempDir, "notes.txt")
	_ = os.WriteFile(txtPath, []byte("plain text file"), 0644)

	var scannedFiles []*FileScanResult
	scanner.SetCallbacks(
		func(res *FileScanResult) {
			scannedFiles = append(scannedFiles, res)
		},
		nil,
		nil,
	)

	summary, err := scanner.ScanDirectory(tempDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory falhou: %v", err)
	}

	if summary.FilesScanned != 1 {
		t.Errorf("esperava 1 arquivo executável escaneado, obteve %d", summary.FilesScanned)
	}

	if len(scannedFiles) != 1 {
		t.Fatalf("esperava 1 resultado, obteve %d", len(scannedFiles))
	}

	res := scannedFiles[0]
	if res.Verdict != cache.VerdictSafe {
		t.Errorf("esperava veredito Seguro (SAFE), obteve %s", res.Verdict)
	}
	if res.Source != "Banco Local (Seguro)" {
		t.Errorf("esperava fonte 'Banco Local (Seguro)', obteve '%s'", res.Source)
	}

	t.Logf("Escaneamento de disco testado com sucesso: Arquivo=%s Veredito=%s Fonte=%s",
		res.FileName, res.Verdict, res.Source)
}
