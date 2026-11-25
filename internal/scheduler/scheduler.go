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

// Callback types para notificações em tempo real
type ProgressCallback func(current, total int, currentItem string)
type StatusCallback func(status string)
type ReportCallback func(report *ScanReport)
type ThreatCallback func(p process.ProcessInfo, threatName string)

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

	// Listeners para atualizar a interface gráfica
	statusListeners   []StatusCallback
	progressListeners []ProgressCallback
	reportListeners   []ReportCallback
	threatListeners   []ThreatCallback
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

// AddProgressListener registra callback para acompanhar progresso de cada processo escaneado.
func (s *Scheduler) AddProgressListener(cb ProgressCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.progressListeners = append(s.progressListeners, cb)
}

// AddStatusListener registra callback para mensagens de status geral.
func (s *Scheduler) AddStatusListener(cb StatusCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statusListeners = append(s.statusListeners, cb)
}

// AddReportListener registra callback para relatório final pronto.
func (s *Scheduler) AddReportListener(cb ReportCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportListeners = append(s.reportListeners, cb)
}

// AddThreatListener registra callback para ameaças encontradas.
func (s *Scheduler) AddThreatListener(cb ThreatCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threatListeners = append(s.threatListeners, cb)
}

// SetCallbacks registra funções para compatibilidade com implementações anteriores.
func (s *Scheduler) SetCallbacks(
	onStatusChange func(status string),
	onReportReady func(report *ScanReport),
	onThreatFound func(p process.ProcessInfo, threatName string),
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if onStatusChange != nil {
		s.statusListeners = append(s.statusListeners, onStatusChange)
	}
	if onReportReady != nil {
		s.reportListeners = append(s.reportListeners, onReportReady)
	}
	if onThreatFound != nil {
		s.threatListeners = append(s.threatListeners, onThreatFound)
	}
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

	totalProcs := len(procs)
	report.TotalProcesses = totalProcs
	if s.engine.Telemetry() != nil {
		s.engine.Telemetry().Log(threatintel.LogLevelInfo, "Scheduler", fmt.Sprintf("Iniciando varredura de %d processos ativos...", totalProcs))
	}

	// Mapa para evitar duplicar verificações de processos com mesmo hash neste ciclo
	seenHashes := make(map[string]bool)

	for i, p := range procs {
		s.notifyProgress(i+1, totalProcs, p.Name)

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

		// 1. Checagem direta no banco local (Fast-Path Cache)
		rec, exists, _ := s.engine.Store().Get(p.SHA256)
		if exists && rec != nil {
			switch rec.Verdict {
			case cache.VerdictSafe:
				report.CachedSafe++
				continue
			case cache.VerdictMalicious:
				report.ThreatsDetected++
				report.ThreatsList = append(report.ThreatsList, p)
				s.notifyThreat(p, rec.ThreatName)
				_ = s.notifier.SendMalwareAlert(p.Name, p.PID, rec.ThreatName, p.SHA256)
				continue
			case cache.VerdictSuspicious:
				report.SuspiciousCount++
				continue
			case cache.VerdictUnknown:
				report.Uncataloged++
				continue
			}
		}

		// 2. Hash novo/nunca visto: consulta o Engine
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

	s.notifyReport(report)
	return report
}

func (s *Scheduler) notifyStatus(msg string) {
	s.mu.RLock()
	listeners := make([]StatusCallback, len(s.statusListeners))
	copy(listeners, s.statusListeners)
	s.mu.RUnlock()
	for _, cb := range listeners {
		if cb != nil {
			go cb(msg)
		}
	}
}

func (s *Scheduler) notifyProgress(current, total int, item string) {
	s.mu.RLock()
	listeners := make([]ProgressCallback, len(s.progressListeners))
	copy(listeners, s.progressListeners)
	s.mu.RUnlock()
	for _, cb := range listeners {
		if cb != nil {
			go cb(current, total, item)
		}
	}
}

func (s *Scheduler) notifyReport(report *ScanReport) {
	s.mu.RLock()
	listeners := make([]ReportCallback, len(s.reportListeners))
	copy(listeners, s.reportListeners)
	s.mu.RUnlock()
	for _, cb := range listeners {
		if cb != nil {
			go cb(report)
		}
	}
}

func (s *Scheduler) notifyThreat(p process.ProcessInfo, threatName string) {
	s.mu.RLock()
	listeners := make([]ThreatCallback, len(s.threatListeners))
	copy(listeners, s.threatListeners)
	s.mu.RUnlock()
	for _, cb := range listeners {
		if cb != nil {
			go cb(p, threatName)
		}
	}
}
