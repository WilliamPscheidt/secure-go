package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"secure-go/internal/cache"
	"secure-go/internal/hasher"
	"secure-go/internal/notifier"
	"secure-go/internal/threatintel"
)

var monitoredExtensions = map[string]bool{
	".exe": true,
	".dll": true,
	".sys": true,
	".scr": true,
	".bat": true,
	".cmd": true,
	".ps1": true,
	".vbs": true,
	".js":  true,
	".msi": true,
	".hta": true,
	".cpl": true,
	".iso": true,
}

// FileWatcher monitora pastas críticas do sistema operacional em tempo real contra criação de novos executáveis.
type FileWatcher struct {
	watcher   *fsnotify.Watcher
	engine    *threatintel.Engine
	notifier  *notifier.Notifier
	dirs      []string
	mu        sync.RWMutex
	running   bool
	cancelFn  context.CancelFunc
	recentMap map[string]time.Time
}

// NewFileWatcher inicializa o monitor de diretórios sensíveis (Downloads, Temp, Startup).
func NewFileWatcher(engine *threatintel.Engine, notif *notifier.Notifier) *FileWatcher {
	var defaultDirs []string

	// 1. Pasta de Downloads do usuário
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		downloads := filepath.Join(userProfile, "Downloads")
		if _, err := os.Stat(downloads); err == nil {
			defaultDirs = append(defaultDirs, downloads)
		}
	}

	// 2. Pasta Temp do sistema
	tempDir := os.TempDir()
	if _, err := os.Stat(tempDir); err == nil {
		defaultDirs = append(defaultDirs, tempDir)
	}

	// 3. Pasta de Inicialização do Windows (Startup)
	if appData := os.Getenv("APPDATA"); appData != "" {
		startup := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
		if _, err := os.Stat(startup); err == nil {
			defaultDirs = append(defaultDirs, startup)
		}
	}

	return &FileWatcher{
		engine:    engine,
		notifier:  notif,
		dirs:      defaultDirs,
		recentMap: make(map[string]time.Time),
	}
}

// WatchedDirs retorna a lista de diretórios vigiados.
func (fw *FileWatcher) WatchedDirs() []string {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	copied := make([]string, len(fw.dirs))
	copy(copied, fw.dirs)
	return copied
}

// IsRunning verifica se o monitor está em execução ativa.
func (fw *FileWatcher) IsRunning() bool {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	return fw.running
}

// Start inicia o monitoramento contínuo em segundo plano.
func (fw *FileWatcher) Start() error {
	fw.mu.Lock()
	if fw.running {
		fw.mu.Unlock()
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fw.mu.Unlock()
		return fmt.Errorf("falha ao inicializar fsnotify: %w", err)
	}

	fw.watcher = watcher
	ctx, cancel := context.WithCancel(context.Background())
	fw.cancelFn = cancel
	fw.running = true

	// Adiciona as pastas ao watcher
	for _, dir := range fw.dirs {
		_ = watcher.Add(dir)
	}
	fw.mu.Unlock()

	telemetry := fw.engine.Telemetry()
	if telemetry != nil {
		telemetry.Log(threatintel.LogLevelInfo, "FileWatcher", fmt.Sprintf("🛡 File Watcher ativado. Vigiando %d diretórios em tempo real.", len(fw.dirs)))
	}

	go fw.loop(ctx)
	return nil
}

// Stop encerra o monitoramento.
func (fw *FileWatcher) Stop() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.running {
		return
	}

	if fw.cancelFn != nil {
		fw.cancelFn()
	}
	if fw.watcher != nil {
		_ = fw.watcher.Close()
	}
	fw.running = false

	telemetry := fw.engine.Telemetry()
	if telemetry != nil {
		telemetry.Log(threatintel.LogLevelInfo, "FileWatcher", "⏸ File Watcher pausado.")
	}
}

func (fw *FileWatcher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				// Erro silencioso ou log
			}
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			// Interessa criação ou modificação de arquivo
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				ext := strings.ToLower(filepath.Ext(event.Name))
				if monitoredExtensions[ext] {
					go fw.handleNewFile(event.Name)
				}
			}
		}
	}
}

func (fw *FileWatcher) handleNewFile(filePath string) {
	// Debounce: ignora se analisado nos últimos 5 segundos
	fw.mu.Lock()
	if last, exists := fw.recentMap[filePath]; exists && time.Since(last) < 5*time.Second {
		fw.mu.Unlock()
		return
	}
	fw.recentMap[filePath] = time.Now()
	// Limpeza periódica do cache de debounce
	if len(fw.recentMap) > 200 {
		fw.recentMap = make(map[string]time.Time)
	}
	fw.mu.Unlock()

	// Aguarda 500ms para o processo de gravação do arquivo liberar o lock
	time.Sleep(500 * time.Millisecond)

	stat, err := os.Stat(filePath)
	if err != nil || stat.IsDir() || stat.Size() == 0 {
		return
	}

	hash, err := hasher.ComputeFileSHA256(filePath)
	if err != nil {
		// Tenta mais uma vez após 1s se estiver bloqueado por download em andamento
		time.Sleep(1 * time.Second)
		hash, err = hasher.ComputeFileSHA256(filePath)
		if err != nil {
			return
		}
	}

	fileName := filepath.Base(filePath)
	telemetry := fw.engine.Telemetry()

	if telemetry != nil {
		telemetry.Log(threatintel.LogLevelAPI, "FileWatcher", fmt.Sprintf("🔍 Novo arquivo detectado para inspeção: %s (%s)", fileName, filepath.Dir(filePath)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := fw.engine.AnalyzeHash(ctx, hash, fileName, filePath, false)
	if err != nil {
		return
	}

	if result.Verdict == cache.VerdictMalicious {
		if telemetry != nil {
			telemetry.Log(threatintel.LogLevelDanger, "FileWatcher", fmt.Sprintf("🚨 AMEAÇA EM TEMPO REAL DETECTADA: %s (%s)", fileName, result.ThreatName))
		}
		if fw.notifier != nil {
			_ = fw.notifier.Alert("🚨 AMEAÇA DETECTADA EM DISCO!", fmt.Sprintf("Arquivo: %s\nAmeaça: %s\nLocal: %s", fileName, result.ThreatName, filePath))
		}
	} else if result.Verdict == cache.VerdictSafe {
		if telemetry != nil {
			telemetry.Log(threatintel.LogLevelSafe, "FileWatcher", fmt.Sprintf("✔ Arquivo verificado e seguro: %s", fileName))
		}
	}
}
