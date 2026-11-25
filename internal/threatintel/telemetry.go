package threatintel

import (
	"sync"
	"time"
)

// LogLevel define a severidade e estilo visual do evento no feed ao vivo.
type LogLevel string

const (
	LogLevelInfo    LogLevel = "INFO"    // Neutro / Informativo (Cinza/Ciano)
	LogLevelSafe    LogLevel = "SAFE"    // Seguro / Limpo (Verde Neon)
	LogLevelAPI     LogLevel = "API"     // Consulta de API em trânsito (Azul/Esmeralda)
	LogLevelWarn    LogLevel = "WARN"    // Suspeito / Alerta suave (Âmbar)
	LogLevelDanger  LogLevel = "DANGER"  // Malware detectado (Vermelho Neon)
)

// LogItem representa uma linha de evento no terminal de atividades do dashboard.
type LogItem struct {
	Timestamp time.Time `json:"timestamp"`
	Level     LogLevel  `json:"level"`
	Source    string    `json:"source"` // "Cache", "MalwareBazaar", "VirusTotal", "Scheduler", "Scanner"
	Message   string    `json:"message"`
}

// TelemetryState resume o estado em tempo real das transmissões de API e filas.
type TelemetryState struct {
	// MalwareBazaar Telemetria
	MBActive      bool   `json:"mb_active"`
	MBCurrentFile string `json:"mb_current_file"`
	MBCurrentHash string `json:"mb_current_hash"`
	MBQueries     int    `json:"mb_queries"`

	// VirusTotal Telemetria & Cronômetro
	VTActive      bool   `json:"vt_active"`
	VTCurrentFile string `json:"vt_current_file"`
	VTCurrentHash string `json:"vt_current_hash"`
	VTQueueLen    int    `json:"vt_queue_len"`
	VTSecondsLeft int    `json:"vt_seconds_left"` // Contagem regressiva: 15..0
	VTIntervalSec int    `json:"vt_interval_sec"` // Total do ciclo (15s)
	VTQueries     int    `json:"vt_queries"`

	// Status geral
	TotalCheckedToday int `json:"total_checked_today"`
	CacheHitsToday    int `json:"cache_hits_today"`
}

// TelemetryHub gerencia o estado das requisições e alimenta o dashboard em tempo real.
type TelemetryHub struct {
	state       TelemetryState
	logs        []LogItem
	maxLogs     int
	mu          sync.RWMutex
	onUpdate    func(state TelemetryState)
	onLogAdded  func(item LogItem)
}

// NewTelemetryHub instancia o hub central de telemetria.
func NewTelemetryHub() *TelemetryHub {
	return &TelemetryHub{
		state: TelemetryState{
			VTIntervalSec: 15,
		},
		maxLogs: 150,
	}
}

// SetListeners registra callbacks para notificações em tempo real na interface gráfica.
func (th *TelemetryHub) SetListeners(onUpdate func(state TelemetryState), onLogAdded func(item LogItem)) {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.onUpdate = onUpdate
	th.onLogAdded = onLogAdded
}

// Log registra uma nova mensagem no feed do dashboard.
func (th *TelemetryHub) Log(level LogLevel, source, message string) {
	th.mu.Lock()
	item := LogItem{
		Timestamp: time.Now(),
		Level:     level,
		Source:    source,
		Message:   message,
	}

	th.logs = append(th.logs, item)
	if len(th.logs) > th.maxLogs {
		th.logs = th.logs[1:]
	}

	cb := th.onLogAdded
	th.mu.Unlock()

	if cb != nil {
		cb(item)
	}
}

// GetLogs retorna os logs recentes registrados.
func (th *TelemetryHub) GetLogs() []LogItem {
	th.mu.RLock()
	defer th.mu.RUnlock()
	copied := make([]LogItem, len(th.logs))
	copy(copied, th.logs)
	return copied
}

// GetState retorna uma cópia do estado atual.
func (th *TelemetryHub) GetState() TelemetryState {
	th.mu.RLock()
	defer th.mu.RUnlock()
	return th.state
}

// StartMBQuery sinaliza início de envio para o MalwareBazaar.
func (th *TelemetryHub) StartMBQuery(fileName, hash string) {
	th.mu.Lock()
	th.state.MBActive = true
	th.state.MBCurrentFile = fileName
	th.state.MBCurrentHash = hash
	th.state.MBQueries++
	st := th.state
	cb := th.onUpdate
	th.mu.Unlock()

	th.Log(LogLevelAPI, "MalwareBazaar", "Enviando hash para verificação: "+fileName)
	if cb != nil {
		cb(st)
	}
}

// EndMBQuery sinaliza término da consulta ao MalwareBazaar.
func (th *TelemetryHub) EndMBQuery() {
	th.mu.Lock()
	th.state.MBActive = false
	th.state.MBCurrentFile = ""
	th.state.MBCurrentHash = ""
	st := th.state
	cb := th.onUpdate
	th.mu.Unlock()

	if cb != nil {
		cb(st)
	}
}

// SetVTCountdown atualiza o cronômetro regressivo da janela de 15 segundos do VirusTotal.
func (th *TelemetryHub) SetVTCountdown(secondsLeft, totalSec int, fileName, hash string, queueLen int) {
	th.mu.Lock()
	th.state.VTActive = secondsLeft > 0 || fileName != ""
	th.state.VTCurrentFile = fileName
	th.state.VTCurrentHash = hash
	th.state.VTSecondsLeft = secondsLeft
	th.state.VTIntervalSec = totalSec
	th.state.VTQueueLen = queueLen
	st := th.state
	cb := th.onUpdate
	th.mu.Unlock()

	if cb != nil {
		cb(st)
	}
}

// StartVTQuery sinaliza envio da requisição ao VirusTotal.
func (th *TelemetryHub) StartVTQuery(fileName, hash string) {
	th.mu.Lock()
	th.state.VTActive = true
	th.state.VTCurrentFile = fileName
	th.state.VTCurrentHash = hash
	th.state.VTSecondsLeft = 0
	th.state.VTQueries++
	st := th.state
	cb := th.onUpdate
	th.mu.Unlock()

	th.Log(LogLevelAPI, "VirusTotal", "Enviando hash para análise em 70+ motores: "+fileName)
	if cb != nil {
		cb(st)
	}
}

// EndVTQuery sinaliza término do envio ao VirusTotal.
func (th *TelemetryHub) EndVTQuery() {
	th.mu.Lock()
	th.state.VTActive = false
	th.state.VTCurrentFile = ""
	th.state.VTCurrentHash = ""
	th.state.VTSecondsLeft = 0
	st := th.state
	cb := th.onUpdate
	th.mu.Unlock()

	if cb != nil {
		cb(st)
	}
}

// RecordCacheHit registra que um hash foi resolvido sem chamada externa.
func (th *TelemetryHub) RecordCacheHit(fileName string, safe bool) {
	th.mu.Lock()
	th.state.CacheHitsToday++
	th.state.TotalCheckedToday++
	th.mu.Unlock()

	if safe {
		th.Log(LogLevelSafe, "Cache", "Hit de cache seguro (0ms): "+fileName)
	} else {
		th.Log(LogLevelWarn, "Cache", "Hit de cache no banco local: "+fileName)
	}
}
