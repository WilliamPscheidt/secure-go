package threatintel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"secure-go/internal/cache"
)

// Engine coordena o cache local persistente e as fontes de inteligência contra ameaças.
type Engine struct {
	store        *cache.Store
	mbClient     *MalwareBazaarClient
	vtClient     *VirusTotalClient
	telemetry    *TelemetryHub
	mu           sync.RWMutex
	onNewVerdict func(rec *cache.HashRecord)
}

// NewEngine cria um novo motor unificado de análise de ameaças.
func NewEngine(store *cache.Store, vtAPIKey string) *Engine {
	th := NewTelemetryHub()
	mb := NewMalwareBazaarClient()
	mb.SetTelemetry(th)
	vt := NewVirusTotalClient(vtAPIKey)
	vt.SetTelemetry(th)

	return &Engine{
		store:     store,
		mbClient:  mb,
		vtClient:  vt,
		telemetry: th,
	}
}

// Telemetry retorna o hub de eventos e telemetria ao vivo.
func (e *Engine) Telemetry() *TelemetryHub {
	return e.telemetry
}

// SetVirusTotalKey atualiza a chave da API do VirusTotal em tempo de execução.
func (e *Engine) SetVirusTotalKey(key string) {
	e.vtClient.SetAPIKey(key)
}

// SetOnNewVerdictCallback define um listener para quando um novo hash for avaliado e salvo.
func (e *Engine) SetOnNewVerdictCallback(cb func(rec *cache.HashRecord)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onNewVerdict = cb
}

// Store retorna a referência do banco de dados local.
func (e *Engine) Store() *cache.Store {
	return e.store
}

// HasVirusTotalKey verifica se uma chave do VT está configurada.
func (e *Engine) HasVirusTotalKey() bool {
	return e.vtClient.HasAPIKey()
}

// AnalyzeHash processa o hash através das camadas: Cache Local -> MalwareBazaar -> VirusTotal.
func (e *Engine) AnalyzeHash(ctx context.Context, sha256, fileName, filePath string, forceRecheck bool) (*ScanResult, error) {
	if sha256 == "" {
		return &ScanResult{
			Verdict: cache.VerdictUnknown,
			Details: "Hash SHA-256 não fornecido",
		}, nil
	}

	// 1. Camada 1: Cache Local Persistente (se não for reanálise forçada)
	if !forceRecheck {
		if rec, exists, err := e.store.Get(sha256); err == nil && exists && rec != nil {
			if e.telemetry != nil {
				e.telemetry.RecordCacheHit(fileName, rec.Verdict == cache.VerdictSafe)
			}
			return &ScanResult{
				SHA256:       rec.SHA256,
				Verdict:      rec.Verdict,
				ThreatName:   rec.ThreatName,
				Positives:    rec.Positives,
				TotalEngines: rec.TotalEngines,
				Source:       rec.Source + " (Cache Local)",
				Details:      fmt.Sprintf("Verificado em %s via %s", rec.CheckedAt.Format("02/01/2006 15:04"), rec.Source),
			}, nil
		}
	}

	// 2. Camada 2: MalwareBazaar (Consulta gratuita, rápida e sem cota estrita)
	mbResult, mbErr := e.mbClient.CheckHashWithFile(ctx, sha256, fileName)
	if mbErr == nil && mbResult != nil && mbResult.Verdict == cache.VerdictMalicious {
		// Ameaça confirmada na base do MalwareBazaar!
		record := &cache.HashRecord{
			SHA256:       sha256,
			FileName:     fileName,
			FilePath:     filePath,
			Verdict:      cache.VerdictMalicious,
			ThreatName:   mbResult.ThreatName,
			Positives:    1,
			TotalEngines: 1,
			Source:       "MalwareBazaar",
			CheckedAt:    time.Now(),
		}
		_ = e.store.Save(record)
		e.notifyNewVerdict(record)
		if e.telemetry != nil {
			e.telemetry.Log(LogLevelDanger, "MalwareBazaar", fmt.Sprintf("🚨 AMEAÇA DETECTADA: %s (%s)", mbResult.ThreatName, fileName))
		}
		return mbResult, nil
	}

	// 3. Camada 3: VirusTotal (Se a chave de API estiver cadastrada)
	if e.vtClient.HasAPIKey() {
		vtResult, vtErr := e.vtClient.CheckHashWithFile(ctx, sha256, fileName)
		if vtErr == nil && vtResult != nil {
			record := &cache.HashRecord{
				SHA256:       sha256,
				FileName:     fileName,
				FilePath:     filePath,
				Verdict:      vtResult.Verdict,
				ThreatName:   vtResult.ThreatName,
				Positives:    vtResult.Positives,
				TotalEngines: vtResult.TotalEngines,
				Source:       "VirusTotal",
				CheckedAt:    time.Now(),
			}
			_ = e.store.Save(record)
			e.notifyNewVerdict(record)

			if e.telemetry != nil {
				if vtResult.Verdict == cache.VerdictMalicious {
					e.telemetry.Log(LogLevelDanger, "VirusTotal", fmt.Sprintf("🚨 MALWARE CONFIRMADO: %s (%s)", vtResult.ThreatName, fileName))
				} else if vtResult.Verdict == cache.VerdictSafe {
					e.telemetry.Log(LogLevelSafe, "VirusTotal", fmt.Sprintf("✔ LIMPO CONFIRMADO por %d motores: %s", vtResult.TotalEngines, fileName))
				} else {
					e.telemetry.Log(LogLevelInfo, "VirusTotal", fmt.Sprintf("ℹ Resultado VirusTotal: %s (%s)", vtResult.Verdict, fileName))
				}
			}
			return vtResult, nil
		}
	}

	// 4. Se não for malware conhecido e o arquivo não possuir veredito confirmado limpo no VirusTotal:
	// Definimos o status como NÃO CATALOGADO (VerdictUnknown), pois ausência de assinatura não garante que seja seguro.
	finalVerdict := cache.VerdictUnknown
	finalSource := "Não Catalogado"
	finalDetails := "Hash inédito: não consta nas bases de malware do MalwareBazaar e não possui análise confirmada no VirusTotal."

	record := &cache.HashRecord{
		SHA256:       sha256,
		FileName:     fileName,
		FilePath:     filePath,
		Verdict:      finalVerdict,
		ThreatName:   "",
		Positives:    0,
		TotalEngines: 0,
		Source:       finalSource,
		CheckedAt:    time.Now(),
	}
	_ = e.store.Save(record)
	e.notifyNewVerdict(record)
	return &ScanResult{
		SHA256:       sha256,
		Verdict:      finalVerdict,
		Source:       finalSource,
		TotalEngines: 0,
		Details:      finalDetails,
	}, nil
}

func (e *Engine) notifyNewVerdict(rec *cache.HashRecord) {
	e.mu.RLock()
	cb := e.onNewVerdict
	e.mu.RUnlock()
	if cb != nil {
		go cb(rec)
	}
}
