package cache

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Verdict representa o veredito da análise de um hash.
type Verdict string

const (
	VerdictSafe       Verdict = "SAFE"       // Seguro / Limpo
	VerdictMalicious  Verdict = "MALICIOUS"  // Malicioso confirmado
	VerdictSuspicious Verdict = "SUSPICIOUS" // Suspeito (poucos motores)
	VerdictPending    Verdict = "PENDING"    // Pendente de verificação dupla (passou apenas por 1 serviço)
	VerdictUnknown    Verdict = "UNKNOWN"    // Não catalogado (verificado em AMBOS e ausente em ambos)
)

// HashRecord armazena todas as informações persistidas de um executável analisado.
type HashRecord struct {
	SHA256       string    `json:"sha256"`
	FileName     string    `json:"file_name"`
	FilePath     string    `json:"file_path"`
	Verdict      Verdict   `json:"verdict"`
	ThreatName   string    `json:"threat_name"`
	Positives    int       `json:"positives"`
	TotalEngines int       `json:"total_engines"`
	Source       string    `json:"source"`
	CheckedAt    time.Time `json:"checked_at"`
	MBChecked    bool      `json:"mb_checked"` // Verificado no MalwareBazaar
	VTChecked    bool      `json:"vt_checked"` // Verificado no VirusTotal
}

// Store gerencia o banco de dados SQLite local de hashes.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewStore inicializa ou abre o banco de dados local no caminho especificado.
func NewStore(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("falha ao criar pasta do banco: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("falha ao abrir banco sqlite: %w", err)
	}

	// Ativa WAL mode para alto desempenho de leitura e concorrência
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("falha ao configurar pragma sqlite: %w", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS hash_cache (
		sha256 TEXT PRIMARY KEY,
		file_name TEXT,
		file_path TEXT,
		verdict TEXT NOT NULL,
		threat_name TEXT,
		positives INTEGER DEFAULT 0,
		total_engines INTEGER DEFAULT 0,
		source TEXT,
		checked_at DATETIME NOT NULL,
		mb_checked INTEGER DEFAULT 0,
		vt_checked INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_hash_verdict ON hash_cache(verdict);
	CREATE INDEX IF NOT EXISTS idx_hash_checked_at ON hash_cache(checked_at);

	CREATE TABLE IF NOT EXISTS app_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("falha ao criar tabela de hash_cache: %w", err)
	}

	// Migração segura para bancos existentes sem perda de dados
	_, _ = db.Exec(`ALTER TABLE hash_cache ADD COLUMN mb_checked INTEGER DEFAULT 0;`)
	_, _ = db.Exec(`ALTER TABLE hash_cache ADD COLUMN vt_checked INTEGER DEFAULT 0;`)

	return &Store{db: db}, nil
}

// Get busca um registro pelo hash SHA-256.
func (s *Store) Get(sha256 string) (*HashRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT sha256, file_name, file_path, verdict, threat_name, positives, total_engines, source, checked_at, mb_checked, vt_checked
		FROM hash_cache
		WHERE sha256 = ?
	`, sha256)

	var rec HashRecord
	var checkedAtStr string
	var mbInt, vtInt int
	err := row.Scan(
		&rec.SHA256,
		&rec.FileName,
		&rec.FilePath,
		&rec.Verdict,
		&rec.ThreatName,
		&rec.Positives,
		&rec.TotalEngines,
		&rec.Source,
		&checkedAtStr,
		&mbInt,
		&vtInt,
	)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	rec.MBChecked = mbInt != 0
	rec.VTChecked = vtInt != 0

	// Faz parse do timestamp
	rec.CheckedAt, _ = time.Parse(time.RFC3339, checkedAtStr)
	if rec.CheckedAt.IsZero() {
		rec.CheckedAt, _ = time.Parse("2006-01-02 15:04:05-07:00", checkedAtStr)
	}
	if rec.CheckedAt.IsZero() {
		rec.CheckedAt, _ = time.Parse("2006-01-02 15:04:05", checkedAtStr)
	}

	return &rec, true, nil
}

// Save insere ou atualiza o veredito de um hash.
func (s *Store) Save(record *HashRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record.CheckedAt.IsZero() {
		record.CheckedAt = time.Now()
	}

	mbInt := 0
	if record.MBChecked {
		mbInt = 1
	}
	vtInt := 0
	if record.VTChecked {
		vtInt = 1
	}

	stmt := `
	INSERT INTO hash_cache (sha256, file_name, file_path, verdict, threat_name, positives, total_engines, source, checked_at, mb_checked, vt_checked)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(sha256) DO UPDATE SET
		file_name = excluded.file_name,
		file_path = excluded.file_path,
		verdict = excluded.verdict,
		threat_name = excluded.threat_name,
		positives = excluded.positives,
		total_engines = excluded.total_engines,
		source = excluded.source,
		checked_at = excluded.checked_at,
		mb_checked = excluded.mb_checked,
		vt_checked = excluded.vt_checked;
	`

	_, err := s.db.Exec(stmt,
		record.SHA256,
		record.FileName,
		record.FilePath,
		string(record.Verdict),
		record.ThreatName,
		record.Positives,
		record.TotalEngines,
		record.Source,
		record.CheckedAt.Format(time.RFC3339),
		mbInt,
		vtInt,
	)
	return err
}

// IsSafe verifica se o hash existe no banco e está classificado como seguro (SAFE).
func (s *Store) IsSafe(sha256 string) bool {
	rec, exists, err := s.Get(sha256)
	if err != nil || !exists || rec == nil {
		return false
	}
	return rec.Verdict == VerdictSafe
}

// ListAll retorna os registros mais recentes salvos no banco.
func (s *Store) ListAll(limit, offset int) ([]*HashRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT sha256, file_name, file_path, verdict, threat_name, positives, total_engines, source, checked_at, mb_checked, vt_checked
		FROM hash_cache
		ORDER BY checked_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*HashRecord
	for rows.Next() {
		var rec HashRecord
		var checkedAtStr string
		var mbInt, vtInt int
		if err := rows.Scan(
			&rec.SHA256,
			&rec.FileName,
			&rec.FilePath,
			&rec.Verdict,
			&rec.ThreatName,
			&rec.Positives,
			&rec.TotalEngines,
			&rec.Source,
			&checkedAtStr,
			&mbInt,
			&vtInt,
		); err != nil {
			return nil, err
		}
		rec.MBChecked = mbInt != 0
		rec.VTChecked = vtInt != 0
		rec.CheckedAt, _ = time.Parse(time.RFC3339, checkedAtStr)
		records = append(records, &rec)
	}

	return records, rows.Err()
}

// Stats retorna contadores consolidados do banco local de hashes.
type Stats struct {
	Total      int `json:"total"`
	Safe       int `json:"safe"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Unknown    int `json:"unknown"`
}

// GetStats calcula estatísticas gerais dos hashes cadastrados.
func (s *Store) GetStats() (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats Stats
	rows, err := s.db.Query(`SELECT verdict, COUNT(*) FROM hash_cache GROUP BY verdict`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var verdict string
		var count int
		if err := rows.Scan(&verdict, &count); err != nil {
			return stats, err
		}
		stats.Total += count
		switch Verdict(verdict) {
		case VerdictSafe:
			stats.Safe += count
		case VerdictMalicious:
			stats.Malicious += count
		case VerdictSuspicious:
			stats.Suspicious += count
		default:
			stats.Unknown += count
		}
	}

	return stats, nil
}

// GetConfig lê uma chave de configuração do banco.
func (s *Store) GetConfig(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow(`SELECT value FROM app_config WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SetConfig grava ou atualiza uma chave de configuração no banco.
func (s *Store) SetConfig(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stmt := `INSERT INTO app_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`
	_, err := s.db.Exec(stmt, key, value)
	return err
}

// Close encerra a conexão com o banco de dados.
func (s *Store) Close() error {
	return s.db.Close()
}
