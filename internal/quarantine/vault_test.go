package quarantine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineAndRestore(t *testing.T) {
	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "vault")

	vault, err := NewVault(vaultDir)
	if err != nil {
		t.Fatalf("falha ao criar cofre: %v", err)
	}

	// Cria arquivo malicioso simulado
	testFile := filepath.Join(tempDir, "malware_sample.exe")
	sampleContent := []byte("MALICIOUS_PAYLOAD_EICAR_STANDARD_TEST_STRING_1234567890")
	if err := os.WriteFile(testFile, sampleContent, 0755); err != nil {
		t.Fatalf("falha ao criar arquivo de teste: %v", err)
	}

	fakeHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// 1. Envia para a Quarentena
	rec, err := vault.QuarantineFile(testFile, "Trojan.Generic.Test", fakeHash, 0)
	if err != nil {
		t.Fatalf("QuarantineFile falhou: %v", err)
	}

	// 2. Confirma que o arquivo original foi removido do sistema
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Errorf("arquivo original deveria ter sido removido do caminho original")
	}

	// 3. Confirma que o arquivo cifrado existe no cofre
	vaultFilePath := filepath.Join(vaultDir, rec.VaultFile)
	vaultData, err := os.ReadFile(vaultFilePath)
	if err != nil {
		t.Fatalf("arquivo cifrado não encontrado no cofre: %v", err)
	}

	// Confirma que o payload está criptografado (não contém a string em texto plano)
	if bytes.Contains(vaultData, sampleContent) {
		t.Errorf("arquivo no cofre NÃO está criptografado (encontrou texto plano)")
	}

	// 4. Confirma listagem
	list := vault.List()
	if len(list) != 1 {
		t.Fatalf("esperava 1 item na quarentena, obteve %d", len(list))
	}
	if list[0].ThreatName != "Trojan.Generic.Test" {
		t.Errorf("esperava ameaça Trojan.Generic.Test, obteve %s", list[0].ThreatName)
	}

	// 5. Restaura o arquivo do cofre
	restoredRec, err := vault.RestoreFile(rec.ID)
	if err != nil {
		t.Fatalf("RestoreFile falhou: %v", err)
	}

	if restoredRec.ID != rec.ID {
		t.Errorf("esperava id restaurado %s, obteve %s", rec.ID, restoredRec.ID)
	}

	// 6. Confirma que o arquivo foi restaurado no caminho original com o conteúdo idêntico
	restoredBytes, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("arquivo restaurado não existe: %v", err)
	}

	if !bytes.Equal(restoredBytes, sampleContent) {
		t.Errorf("conteúdo restaurado difere do original")
	}

	// 7. Confirma que o cofre foi esvaziado
	if len(vault.List()) != 0 {
		t.Errorf("esperava cofre vazio após restauração")
	}
}

func TestQuarantineAndDelete(t *testing.T) {
	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "vault")

	vault, err := NewVault(vaultDir)
	if err != nil {
		t.Fatalf("falha ao criar cofre: %v", err)
	}

	testFile := filepath.Join(tempDir, "malware_to_delete.exe")
	_ = os.WriteFile(testFile, []byte("DELETE_ME"), 0644)

	rec, err := vault.QuarantineFile(testFile, "Ransomware.Shadow", "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00", 0)
	if err != nil {
		t.Fatalf("QuarantineFile falhou: %v", err)
	}

	if err := vault.DeleteFile(rec.ID); err != nil {
		t.Fatalf("DeleteFile falhou: %v", err)
	}

	if len(vault.List()) != 0 {
		t.Errorf("esperava cofre vazio após exclusão permanente")
	}

	vaultFilePath := filepath.Join(vaultDir, rec.VaultFile)
	if _, err := os.Stat(vaultFilePath); !os.IsNotExist(err) {
		t.Errorf("arquivo físico .sec ainda existe após DeleteFile")
	}
}
