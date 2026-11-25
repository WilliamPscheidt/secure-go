package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/hasher"
	"secure-go/internal/threatintel"
)

// FileScanResult detalha a avaliação de um arquivo no escaneamento de disco.
type FileScanResult struct {
	FilePath     string        `json:"file_path"`
	FileName     string        `json:"file_name"`
	FileSize     int64         `json:"file_size"`
	SHA256       string        `json:"sha256"`
	Verdict      cache.Verdict `json:"verdict"` // SAFE ("Seguro"), MALICIOUS, etc.
	ThreatName   string        `json:"threat_name,omitempty"`
	Source       string        `json:"source"`
	Details      string        `json:"details,omitempty"`
	Error        string        `json:"error,omitempty"`
	ScannedAt    time.Time     `json:"scanned_at"`
}

// DiskScanSummary consolida as estatísticas finais de uma varredura de diretório/disco.
type DiskScanSummary struct {
	TargetDirectory string        `json:"target_directory"`
	Duration        time.Duration `json:"duration"`
	TotalFilesFound int           `json:"total_files_found"`
	FilesScanned    int           `json:"files_scanned"`
	SafeFiles       int           `json:"safe_files"`
	MaliciousFiles  int           `json:"malicious_files"`
	SuspiciousFiles int           `json:"suspicious_files"`
	UnknownFiles    int           `json:"unknown_files"`
	ErrorsCount     int           `json:"errors_count"`
}

// DiskScanner gerencia a varredura concorrente de diretórios e discos.
type DiskScanner struct {
	engine     *threatintel.Engine
	numWorkers int
	extensions map[string]bool
	mu         sync.RWMutex
	cancelFunc context.CancelFunc
	isScanning bool

	// Callbacks em tempo real para a interface
	onFileScanned func(res *FileScanResult)
	onProgress    func(scanned, total int, currentFile string)
	onCompleted   func(summary *DiskScanSummary)
}

// NewDiskScanner inicializa o scanner de disco apontando para o motor de inteligência e cache.
func NewDiskScanner(engine *threatintel.Engine, workers int) *DiskScanner {
	if workers <= 0 {
		workers = 4
	}

	// Extensões de arquivos executáveis e de script padrão para inspeção
	defaultExts := map[string]bool{
		".exe": true, ".dll": true, ".sys": true, ".scr": true,
		".bat": true, ".cmd": true, ".ps1": true, ".vbs": true,
		".js":  true, ".com": true, ".msi": true, ".cpl": true,
	}

	return &DiskScanner{
		engine:     engine,
		numWorkers: workers,
		extensions: defaultExts,
	}
}

// SetCallbacks configura as escutas de eventos da varredura.
func (ds *DiskScanner) SetCallbacks(
	onFileScanned func(res *FileScanResult),
	onProgress func(scanned, total int, currentFile string),
	onCompleted func(summary *DiskScanSummary),
) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.onFileScanned = onFileScanned
	ds.onProgress = onProgress
	ds.onCompleted = onCompleted
}

// IsScanning informa se há uma varredura de disco em andamento.
func (ds *DiskScanner) IsScanning() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.isScanning
}

// Cancel interrompe a varredura em execução.
func (ds *DiskScanner) Cancel() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.cancelFunc != nil {
		ds.cancelFunc()
		ds.cancelFunc = nil
	}
}

// ScanDirectory executa a varredura recursiva de uma pasta ou unidade de disco.
func (ds *DiskScanner) ScanDirectory(rootPath string, onlyExecutables bool) (*DiskScanSummary, error) {
	ds.mu.Lock()
	if ds.isScanning {
		ds.mu.Unlock()
		return nil, fmt.Errorf("já existe uma varredura de disco em andamento")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ds.cancelFunc = cancel
	ds.isScanning = true
	ds.mu.Unlock()

	defer func() {
		ds.mu.Lock()
		ds.isScanning = false
		ds.cancelFunc = nil
		ds.mu.Unlock()
	}()

	startTime := time.Now()
	summary := &DiskScanSummary{
		TargetDirectory: rootPath,
	}

	// 1. Coleta a lista de arquivos para analisar
	var filesToScan []string
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if walkErr != nil {
			return nil // Ignora pastas com acesso negado e prossegue
		}

		if d.IsDir() {
			return nil
		}

		if onlyExecutables {
			ext := strings.ToLower(filepath.Ext(path))
			if !ds.extensions[ext] {
				return nil
			}
		}

		filesToScan = append(filesToScan, path)
		return nil
	})

	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("erro ao indexar diretório: %w", err)
	}

	summary.TotalFilesFound = len(filesToScan)
	if ds.engine.Telemetry() != nil {
		ds.engine.Telemetry().Log(threatintel.LogLevelInfo, "Scanner", fmt.Sprintf("Iniciando varredura em %s (%d arquivos no alvo)...", rootPath, len(filesToScan)))
	}

	// 2. Fila concorrente com Worker Pool
	jobs := make(chan string, ds.numWorkers*2)
	results := make(chan *FileScanResult, ds.numWorkers*2)

	var wg sync.WaitGroup

	// Inicia os workers
	for w := 0; w < ds.numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res := ds.scanSingleFile(ctx, filePath)
					results <- res
				}
			}
		}()
	}

	// Goroutine para enviar os trabalhos
	go func() {
		for _, f := range filesToScan {
			select {
			case <-ctx.Done():
				break
			case jobs <- f:
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	// 3. Processamento dos resultados conforme chegam
	scannedCount := 0
	for res := range results {
		scannedCount++
		summary.FilesScanned++

		switch res.Verdict {
		case cache.VerdictSafe:
			summary.SafeFiles++
		case cache.VerdictMalicious:
			summary.MaliciousFiles++
		case cache.VerdictSuspicious:
			summary.SuspiciousFiles++
		default:
			if res.Error != "" {
				summary.ErrorsCount++
			} else {
				summary.UnknownFiles++
			}
		}

		ds.notifyFileScanned(res)
		ds.notifyProgress(scannedCount, summary.TotalFilesFound, res.FilePath)
	}

	summary.Duration = time.Since(startTime)
	if ds.engine.Telemetry() != nil {
		ds.engine.Telemetry().Log(threatintel.LogLevelSafe, "Scanner", fmt.Sprintf("Varredura de disco finalizada em %v (%d analisados, %d seguros, %d maliciosos)",
			summary.Duration.Round(time.Millisecond), summary.FilesScanned, summary.SafeFiles, summary.MaliciousFiles))
	}
	ds.notifyCompleted(summary)

	return summary, nil
}

// scanSingleFile analisa um arquivo individual aplicando a regra do banco local limpo como "Seguro".
func (ds *DiskScanner) scanSingleFile(ctx context.Context, filePath string) *FileScanResult {
	info, err := os.Stat(filePath)
	res := &FileScanResult{
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		ScannedAt: time.Now(),
	}

	if err != nil {
		res.Error = fmt.Sprintf("falha de acesso ao arquivo: %v", err)
		res.Verdict = cache.VerdictUnknown
		return res
	}

	res.FileSize = info.Size()

	// Calcula hash SHA-256
	sha256, err := hasher.ComputeFileSHA256(filePath)
	if err != nil {
		res.Error = fmt.Sprintf("falha ao calcular hash: %v", err)
		res.Verdict = cache.VerdictUnknown
		return res
	}
	res.SHA256 = sha256

	// >>> REGRA ESSENCIAL: VERIFICAÇÃO DIRETA NO BANCO LOCAL DE LIMPOS <<<
	// Se o hash já foi verificado como limpo anteriormente, define imediatamente como "Seguro"
	// sem consultar nenhuma API externa.
	if ds.engine.Store().IsSafe(sha256) {
		res.Verdict = cache.VerdictSafe
		res.Source = "Banco Local (Seguro)"
		res.Details = "Arquivo verificado previamente e catalogado como Seguro no banco de dados local"
		return res
	}

	// Verifica se já estava catalogado no banco como Malicioso ou Não Catalogado
	if rec, exists, _ := ds.engine.Store().Get(sha256); exists && rec != nil {
		if rec.Verdict == cache.VerdictMalicious {
			res.Verdict = cache.VerdictMalicious
			res.ThreatName = rec.ThreatName
			res.Source = "Banco Local (Malicioso)"
			res.Details = fmt.Sprintf("Ameaça conhecida: %s (detectado via %s)", rec.ThreatName, rec.Source)
			return res
		} else if rec.Verdict == cache.VerdictUnknown {
			res.Verdict = cache.VerdictUnknown
			res.Source = "Banco Local (Não Catalogado)"
			res.Details = "Arquivo não consta nos catálogos de ameaças nem possui confirmação limpa."
			return res
		}
	}

	// Caso não esteja no banco local, consulta o motor de inteligência (MalwareBazaar / VirusTotal)
	analysis, err := ds.engine.AnalyzeHash(ctx, sha256, res.FileName, filePath, false)
	if err != nil {
		res.Error = fmt.Sprintf("erro na consulta de inteligência: %v", err)
		res.Verdict = cache.VerdictUnknown
		return res
	}

	res.Verdict = analysis.Verdict
	res.ThreatName = analysis.ThreatName
	res.Source = analysis.Source
	res.Details = analysis.Details

	return res
}

func (ds *DiskScanner) notifyFileScanned(res *FileScanResult) {
	ds.mu.RLock()
	cb := ds.onFileScanned
	ds.mu.RUnlock()
	if cb != nil {
		cb(res)
	}
}

func (ds *DiskScanner) notifyProgress(scanned, total int, currentFile string) {
	ds.mu.RLock()
	cb := ds.onProgress
	ds.mu.RUnlock()
	if cb != nil {
		cb(scanned, total, currentFile)
	}
}

func (ds *DiskScanner) notifyCompleted(summary *DiskScanSummary) {
	ds.mu.RLock()
	cb := ds.onCompleted
	ds.mu.RUnlock()
	if cb != nil {
		cb(summary)
	}
}
