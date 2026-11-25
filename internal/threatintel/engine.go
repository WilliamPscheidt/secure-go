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
	store         *cache.Store
	mbClient      *MalwareBazaarClient
	vtClient      *VirusTotalClient
	mu            sync.RWMutex
	onNewVerdict  func(rec *cache.HashRecord)
}

// NewEngine cria um novo motor unificado de análise de ameaças.
func NewEngine(store *cache.Store, vtAPIKey string) *Engine {
	return &Engine{
		store:    store,
		mbClient: NewMalwareBazaarClient(),
		vtClient: NewVirusTotalClient(vtAPIKey),
	}
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
	mbResult, mbErr := e.mbClient.CheckHash(ctx, sha256)
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
		return mbResult, nil
	}

	// 3. Camada 3: VirusTotal (Se a chave de API estiver cadastrada)
	if e.vtClient.HasAPIKey() {
		vtResult, vtErr := e.vtClient.CheckHash(ctx, sha256)
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
