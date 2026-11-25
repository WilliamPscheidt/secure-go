package scheduler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
	"secure-go/internal/process"
	"secure-go/internal/threatintel"
)

// ScanReport resume as métricas do ciclo de varredura executado.
type ScanReport struct {
	StartTime       time.Time             `json:"start_time"`
	Duration        time.Duration         `json:"duration"`
	TotalProcesses  int                   `json:"total_processes"`
	CachedSafe      int                   `json:"cached_safe"`
	NewlyChecked    int                   `json:"newly_checked"`
	ThreatsDetected int                   `json:"threats_detected"`
	SuspiciousCount int                   `json:"suspicious_count"`
	Uncataloged     int                   `json:"uncataloged"`
	ErrorsCount     int                   `json:"errors_count"`
	ThreatsList     []process.ProcessInfo `json:"threats_list,omitempty"`
}

// Scheduler coordena a execução contínua da análise a cada 30 minutos (ou intervalo customizado).
type Scheduler struct {
	engine     *threatintel.Engine
	notifier   *notifier.Notifier
	interval   time.Duration
	ticker     *time.Ticker
	stopChan   chan struct{}
	triggerNow chan struct{}
	running    bool
	isScanning bool
	mu         sync.RWMutex

	lastReport   *ScanReport
	nextScanTime time.Time

	// Callbacks para atualizar a interface gráfica
	onStatusChange  func(status string)
	onReportReady   func(report *ScanReport)
	onThreatFound   func(p process.ProcessInfo, threatName string)
}

// NewScheduler inicializa o agendador com intervalo configurável (padrão: 30 minutos).
func NewScheduler(engine *threatintel.Engine, notif *notifier.Notifier, interval time.Duration) *Scheduler {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &Scheduler{
		engine:     engine,
		notifier:   notif,
		interval:   interval,
		stopChan:   make(chan struct{}),
		triggerNow: make(chan struct{}, 1),
	}
}

// SetCallbacks registra funções que serão notificadas para atualização da GUI.
func (s *Scheduler) SetCallbacks(
	onStatusChange func(status string),
	onReportReady func(report *ScanReport),
	onThreatFound func(p process.ProcessInfo, threatName string),
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStatusChange = onStatusChange
	s.onReportReady = onReportReady
	s.onThreatFound = onThreatFound
}

// SetInterval atualiza o intervalo da varredura periódica.
func (s *Scheduler) SetInterval(interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = interval
	if s.ticker != nil {
		s.ticker.Reset(interval)
		s.nextScanTime = time.Now().Add(interval)
	}
}

// Interval retorna o intervalo configurado atual.
func (s *Scheduler) Interval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interval
}

// NextScanTime retorna quando ocorrerá a próxima varredura.
func (s *Scheduler) NextScanTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextScanTime
}

// LastReport retorna o último relatório gerado.
func (s *Scheduler) LastReport() *ScanReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReport
}

// IsScanning informa se há uma varredura em andamento no momento.
func (s *Scheduler) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isScanning
}

// Start inicia o loop em segundo plano do agendador.
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.ticker = time.NewTicker(s.interval)
	s.nextScanTime = time.Now().Add(s.interval)
	s.mu.Unlock()

	go s.loop()

	// Dispara primeira varredura inicial logo após inicializar
	s.TriggerNow()
}

// Stop encerra o loop do agendador.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	if s.ticker != nil {
		s.ticker.Stop()
	}
	close(s.stopChan)
}

// TriggerNow solicita uma execução imediata fora do ciclo do timer.
func (s *Scheduler) TriggerNow() {
	select {
	case s.triggerNow <- struct{}{}:
	default:
	}
}

func (s *Scheduler) loop() {
	for {
		select {
		case <-s.stopChan:
			return
		case <-s.ticker.C:
			s.mu.Lock()
			s.nextScanTime = time.Now().Add(s.interval)
			s.mu.Unlock()
			s.RunCycle(context.Background())
		case <-s.triggerNow:
			s.RunCycle(context.Background())
		}
	}
}

// RunCycle executa um ciclo completo de análise de processos.
func (s *Scheduler) RunCycle(ctx context.Context) *ScanReport {
	s.mu.Lock()
	if s.isScanning {
		s.mu.Unlock()
		return nil
	}
	s.isScanning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.isScanning = false
		s.mu.Unlock()
	}()

	s.notifyStatus("Varrendo processos em execução...")

	startTime := time.Now()
	report := &ScanReport{
		StartTime: startTime,
	}

	procs, err := process.ListRunningProcesses()
	if err != nil {
		log.Printf("[SCHEDULER] Erro ao listar processos: %v", err)
		report.ErrorsCount++
		s.notifyStatus("Erro ao listar processos do sistema")
		return report
	}

	report.TotalProcesses = len(procs)
	if s.engine.Telemetry() != nil {
		s.engine.Telemetry().Log(threatintel.LogLevelInfo, "Scheduler", fmt.Sprintf("Iniciando varredura periódica de %d processos...", len(procs)))
	}

	// Mapa para evitar duplicar verificações de processos com mesmo hash neste ciclo
	seenHashes := make(map[string]bool)

	for _, p := range procs {
		if p.SHA256 == "" {
			if p.Error != "" {
				report.ErrorsCount++
			}
			continue
		}

		if seenHashes[p.SHA256] {
			continue
		}
		seenHashes[p.SHA256] = true

		// 1. Checagem direta no banco local
		rec, exists, _ := s.engine.Store().Get(p.SHA256)
		if exists && rec != nil {
			if rec.Verdict == cache.VerdictSafe {
				report.CachedSafe++
				continue
			} else if rec.Verdict == cache.VerdictMalicious {
				report.ThreatsDetected++
				report.ThreatsList = append(report.ThreatsList, p)
				s.notifyThreat(p, rec.ThreatName)
				_ = s.notifier.SendMalwareAlert(p.Name, p.PID, rec.ThreatName, p.SHA256)
				continue
			}
		}

		// 2. Hash novo/não catalogado: consulta o Engine
		report.NewlyChecked++
		res, err := s.engine.AnalyzeHash(ctx, p.SHA256, p.Name, p.ExePath, false)
		if err != nil {
			log.Printf("[SCHEDULER] Erro ao analisar hash %s (%s): %v", p.SHA256, p.Name, err)
			report.ErrorsCount++
			continue
		}

		if res.Verdict == cache.VerdictMalicious {
			report.ThreatsDetected++
			report.ThreatsList = append(report.ThreatsList, p)
			s.notifyThreat(p, res.ThreatName)
			_ = s.notifier.SendMalwareAlert(p.Name, p.PID, res.ThreatName, p.SHA256)
		} else if res.Verdict == cache.VerdictSuspicious {
			report.SuspiciousCount++
		} else if res.Verdict == cache.VerdictSafe {
			report.CachedSafe++
		} else {
			report.Uncataloged++
		}
	}

	report.Duration = time.Since(startTime)

	s.mu.Lock()
	s.lastReport = report
	s.mu.Unlock()

	summary := fmt.Sprintf("Concluído: %d processos analisados (%d seguros, %d não catalogados, %d ameaças)",
		report.TotalProcesses, report.CachedSafe, report.Uncataloged, report.ThreatsDetected)
	s.notifyStatus(summary)
	if s.engine.Telemetry() != nil {
		s.engine.Telemetry().Log(threatintel.LogLevelSafe, "Scheduler", summary)
	}

	s.mu.RLock()
	cbReport := s.onReportReady
	s.mu.RUnlock()
	if cbReport != nil {
		go cbReport(report)
	}

	return report
}

func (s *Scheduler) notifyStatus(msg string) {
	s.mu.RLock()
	cb := s.onStatusChange
	s.mu.RUnlock()
	if cb != nil {
		go cb(msg)
	}
}

func (s *Scheduler) notifyThreat(p process.ProcessInfo, threatName string) {
	s.mu.RLock()
	cb := s.onThreatFound
	s.mu.RUnlock()
	if cb != nil {
		go cb(p, threatName)
	}
}
