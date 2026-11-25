package quarantine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	vaultMagicHeader = "SECVAULT1\n"
	keyFileName      = "vault.key"
)

// QuarantineRecord contém os metadados forenses de um arquivo em quarentena criptografada.
type QuarantineRecord struct {
	ID            string    `json:"id"`
	FileName      string    `json:"file_name"`
	OriginalPath  string    `json:"original_path"`
	ThreatName    string    `json:"threat_name"`
	SHA256        string    `json:"sha256"`
	FileSize      int64     `json:"file_size"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	VaultFile     string    `json:"vault_file"`
}

// Vault gerencia o armazenamento seguro e criptografado de malwares neutralizados.
type Vault struct {
	dir     string
	key     []byte
	mu      sync.RWMutex
	records map[string]QuarantineRecord
}

// NewVault inicializa o diretório do cofre e carrega ou gera a chave AES-256.
func NewVault(vaultDir string) (*Vault, error) {
	if vaultDir == "" {
		programData := os.Getenv("ProgramData")
		if programData != "" {
			vaultDir = filepath.Join(programData, "SecureGo", "Quarantine")
		} else {
			vaultDir = filepath.Join(".", "quarantine")
		}
	}

	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return nil, fmt.Errorf("falha ao criar pasta de quarentena: %w", err)
	}

	key, err := getOrCreateKey(vaultDir)
	if err != nil {
		return nil, err
	}

	v := &Vault{
		dir:     vaultDir,
		key:     key,
		records: make(map[string]QuarantineRecord),
	}

	// Carrega índice de arquivos já existentes no cofre
	_ = v.reloadIndex()

	return v, nil
}

// Dir retorna o caminho do diretório do cofre.
func (v *Vault) Dir() string {
	return v.dir
}

func getOrCreateKey(vaultDir string) ([]byte, error) {
	keyPath := filepath.Join(vaultDir, keyFileName)
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		return data, nil
	}

	// Gera nova chave criptográfica AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("falha ao gerar chave aleatória para o cofre: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("falha ao salvar chave do cofre: %w", err)
	}

	return key, nil
}

// reloadIndex lê os metadados de todos os arquivos .sec no cofre.
func (v *Vault) reloadIndex() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return err
	}

	v.records = make(map[string]QuarantineRecord)

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sec" {
			continue
		}

		fullPath := filepath.Join(v.dir, entry.Name())
		rec, err := readVaultHeader(fullPath)
		if err == nil && rec != nil {
			v.records[rec.ID] = *rec
		}
	}

	return nil
}

// readVaultHeader extrai apenas os metadados do cabeçalho sem decodificar o arquivo inteiro.
func readVaultHeader(vaultFilePath string) (*QuarantineRecord, error) {
	f, err := os.Open(vaultFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	magicBuf := make([]byte, len(vaultMagicHeader))
	if _, err := io.ReadFull(f, magicBuf); err != nil || string(magicBuf) != vaultMagicHeader {
		return nil, fmt.Errorf("cabeçalho de cofre inválido")
	}

	var headerLen uint32
	if err := binary.Read(f, binary.BigEndian, &headerLen); err != nil {
		return nil, err
	}

	headerJSON := make([]byte, headerLen)
	if _, err := io.ReadFull(f, headerJSON); err != nil {
		return nil, err
	}

	var rec QuarantineRecord
	if err := json.Unmarshal(headerJSON, &rec); err != nil {
		return nil, err
	}

	return &rec, nil
}

// QuarantineFile isola o arquivo malicioso, finaliza o processo associado (se fornecido)
// e salva o payload criptografado com AES-GCM no cofre.
func (v *Vault) QuarantineFile(filePath, threatName, sha256 string, pid uint32) (*QuarantineRecord, error) {
	if filePath == "" {
		return nil, fmt.Errorf("caminho de arquivo inválido para quarentena")
	}

	// 1. Se houver processo ativo em execução, finaliza-o primeiro
	if pid > 0 {
		_ = TerminateProcessByID(pid)
	}

	// 2. Lê o arquivo original antes da remoção
	plainBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler arquivo original para quarentena: %w", err)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	// 3. Criptografa o arquivo com AES-256-GCM
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("falha ao inicializar cifra AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("falha ao instanciar modo GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("falha ao gerar nonce: %w", err)
	}

	cipherBytes := gcm.Seal(nil, nonce, plainBytes, nil)

	// 4. Monta o registro de quarentena
	id := fmt.Sprintf("q_%d_%x", time.Now().UnixNano(), sha256[:8])
	vaultFileName := id + ".sec"
	vaultFilePath := filepath.Join(v.dir, vaultFileName)

	rec := QuarantineRecord{
		ID:            id,
		FileName:      filepath.Base(filePath),
		OriginalPath:  filePath,
		ThreatName:    threatName,
		SHA256:        sha256,
		FileSize:      fileInfo.Size(),
		QuarantinedAt: time.Now(),
		VaultFile:     vaultFileName,
	}

	headerJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}

	// 5. Grava arquivo no cofre: [Magic][HeaderLen][HeaderJSON][Nonce][Ciphertext]
	out, err := os.OpenFile(vaultFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar arquivo no cofre: %w", err)
	}
	defer out.Close()

	if _, err := out.WriteString(vaultMagicHeader); err != nil {
		return nil, err
	}

	headerLen := uint32(len(headerJSON))
	if err := binary.Write(out, binary.BigEndian, headerLen); err != nil {
		return nil, err
	}

	if _, err := out.Write(headerJSON); err != nil {
		return nil, err
	}

	if _, err := out.Write(nonce); err != nil {
		return nil, err
	}

	if _, err := out.Write(cipherBytes); err != nil {
		return nil, err
	}

	// 6. Remove com segurança o arquivo original infectado do disco
	_ = os.Remove(filePath)

	v.mu.Lock()
	v.records[id] = rec
	v.mu.Unlock()

	return &rec, nil
}

// RestoreFile restaura o arquivo do cofre para sua localização original no disco.
func (v *Vault) RestoreFile(id string) (*QuarantineRecord, error) {
	v.mu.RLock()
	rec, exists := v.records[id]
	v.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("item de quarentena '%s' não encontrado", id)
	}

	vaultFilePath := filepath.Join(v.dir, rec.VaultFile)
	data, err := os.ReadFile(vaultFilePath)
	if err != nil {
		return nil, fmt.Errorf("falha ao ler arquivo do cofre: %w", err)
	}

	magicLen := len(vaultMagicHeader)
	if len(data) < magicLen+4 {
		return nil, fmt.Errorf("tamanho de arquivo do cofre inválido")
	}

	headerLen := binary.BigEndian.Uint32(data[magicLen : magicLen+4])
	offset := magicLen + 4 + int(headerLen)

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < offset+nonceSize {
		return nil, fmt.Errorf("dados corrompidos no cofre")
	}

	nonce := data[offset : offset+nonceSize]
	ciphertext := data[offset+nonceSize:]

	plainBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("falha ao descriptografar arquivo do cofre: %w", err)
	}

	// Assegura que o diretório de destino existe
	destDir := filepath.Dir(rec.OriginalPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("falha ao recriar diretório original: %w", err)
	}

	if err := os.WriteFile(rec.OriginalPath, plainBytes, 0755); err != nil {
		return nil, fmt.Errorf("falha ao restaurar arquivo no destino original: %w", err)
	}

	// Remove do cofre após restauração bem-sucedida
	_ = os.Remove(vaultFilePath)

	v.mu.Lock()
	delete(v.records, id)
	v.mu.Unlock()

	return &rec, nil
}

// DeleteFile exclui definitivamente o arquivo em quarentena do cofre.
func (v *Vault) DeleteFile(id string) error {
	v.mu.Lock()
	rec, exists := v.records[id]
	if exists {
		delete(v.records, id)
	}
	v.mu.Unlock()

	if !exists {
		return fmt.Errorf("item de quarentena '%s' não encontrado", id)
	}

	vaultFilePath := filepath.Join(v.dir, rec.VaultFile)
	return os.Remove(vaultFilePath)
}

// List retorna a lista de todos os arquivos atualmente retidos na quarentena.
func (v *Vault) List() []QuarantineRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	list := make([]QuarantineRecord, 0, len(v.records))
	for _, rec := range v.records {
		list = append(list, rec)
	}
	return list
}

// Get busca um registro específico por ID.
func (v *Vault) Get(id string) (*QuarantineRecord, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	rec, exists := v.records[id]
	if !exists {
		return nil, false
	}
	return &rec, true
}
