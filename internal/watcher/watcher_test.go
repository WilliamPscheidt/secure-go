package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/threatintel"
)

func TestCleanExecutablePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"C:\Program Files\App\app.exe" --silent`, `C:\Program Files\App\app.exe`},
		{`C:\Windows\System32\cmd.exe /c start`, `C:\Windows\System32\cmd.exe`},
		{`"C:\Users\test\AppData\Local\Discord\Update.exe" --processStart Discord.exe`, `C:\Users\test\AppData\Local\Discord\Update.exe`},
		{`notepad.exe myfile.txt`, `notepad.exe`},
		{`%windir%\system32\calc.exe`, os.Getenv("windir") + `\system32\calc.exe`},
	}

	for _, tc := range tests {
		got := CleanExecutablePath(tc.input)
		if got != tc.expected {
			t.Errorf("CleanExecutablePath(%q) = %q, esperava %q", tc.input, got, tc.expected)
		}
	}
}

func TestScanAutoruns(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_autoruns.db")
	store, err := cache.NewStore(dbPath)
	if err != nil {
		t.Fatalf("falha ao criar store: %v", err)
	}
	defer store.Close()

	engine := threatintel.NewEngine(store, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entries, err := ScanAutoruns(ctx, engine)
	if err != nil {
		t.Fatalf("ScanAutoruns falhou: %v", err)
	}

	t.Logf("Total de entradas em Autoruns encontradas: %d", len(entries))
	for _, e := range entries {
		t.Logf("[%s] %s -> %s (Hash: %.10s..., Veredito: %s)", e.Location, e.Name, e.FilePath, e.SHA256, e.Verdict)
	}
}

func TestFileWatcherLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fw.db")
	store, _ := cache.NewStore(dbPath)
	defer store.Close()

	engine := threatintel.NewEngine(store, "")
	fw := NewFileWatcher(engine, nil)

	// Sobrescreve dirs para a pasta de teste
	fw.dirs = []string{tempDir}

	if err := fw.Start(); err != nil {
		t.Fatalf("falha ao iniciar filewatcher: %v", err)
	}

	if !fw.IsRunning() {
		t.Error("esperava IsRunning = true")
	}

	// Cria um arquivo no diretório vigiado
	testFile := filepath.Join(tempDir, "sample_app.exe")
	_ = os.WriteFile(testFile, []byte("MZ-TEST-BINARY-DATA"), 0644)

	// Aguarda processamento
	time.Sleep(1 * time.Second)

	fw.Stop()

	if fw.IsRunning() {
		t.Error("esperava IsRunning = false após Stop()")
	}
}
