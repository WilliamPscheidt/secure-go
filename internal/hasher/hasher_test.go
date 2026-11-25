package hasher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeBytesSHA256(t *testing.T) {
	// Hash conhecido de string vazia em SHA-256
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := ComputeBytesSHA256([]byte{})
	if got != expected {
		t.Errorf("esperava %s, obteve %s", expected, got)
	}
}

func TestComputeFileSHA256(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.txt")
	content := []byte("secure-go malware detector test")

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("falha ao criar arquivo de teste: %v", err)
	}

	expected := ComputeBytesSHA256(content)
	got, err := ComputeFileSHA256(filePath)
	if err != nil {
		t.Fatalf("falha ao calcular hash do arquivo: %v", err)
	}

	if got != expected {
		t.Errorf("esperava %s, obteve %s", expected, got)
	}
}
