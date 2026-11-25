package threatintel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"secure-go/internal/cache"
	"secure-go/internal/heuristics"
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
	if e.telemetry != nil {
		e.telemetry.TriggerStateUpdate()
	}
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

// WhitelistHash marca um hash manualmente como confiável (SAFE).
func (e *Engine) WhitelistHash(sha256, fileName, filePath string) error {
	err := e.store.WhitelistHash(sha256, fileName, filePath)
	if err == nil {
		rec, found, _ := e.store.Get(sha256)
		if found && rec != nil {
			e.notifyNewVerdict(rec)
		}
		if e.telemetry != nil {
			short := sha256
			if len(short) > 10 {
				short = short[:10] + "..."
			}
			e.telemetry.Log(LogLevelSafe, "Whitelist", fmt.Sprintf("✔ Hash adicionado à Whitelist: %s (%s)", fileName, short))
		}
	}
	return err
}

// BlacklistHash marca um hash manualmente como malicioso (MALICIOUS).
func (e *Engine) BlacklistHash(sha256, fileName, filePath, threatName string) error {
	err := e.store.BlacklistHash(sha256, fileName, filePath, threatName)
	if err == nil {
		rec, found, _ := e.store.Get(sha256)
		if found && rec != nil {
			e.notifyNewVerdict(rec)
		}
		if e.telemetry != nil {
			short := sha256
			if len(short) > 10 {
				short = short[:10] + "..."
			}
			e.telemetry.Log(LogLevelDanger, "Blacklist", fmt.Sprintf("🚨 Hash adicionado à Blacklist: %s (%s)", fileName, short))
		}
	}
	return err
}

// DeleteHash remove um registro de hash do banco de dados local.
func (e *Engine) DeleteHash(sha256 string) error {
	return e.store.DeleteHash(sha256)
}

// AnalyzeHash processa o hash através das camadas: Cache Local -> MalwareBazaar E VirusTotal.
// REGRA: Para ser classificado como "Não Catalogado" (UNKNOWN), o hash deve ter passado
// obrigatoriamente por AMBOS os verificadores (MalwareBazaar e VirusTotal).
// Se passou apenas por um, permanece como PENDENTE de verificação dupla e deve ser submetido ao outro.
func (e *Engine) AnalyzeHash(ctx context.Context, sha256, fileName, filePath string, forceRecheck bool) (*ScanResult, error) {
	if sha256 == "" {
		return &ScanResult{
			Verdict: cache.VerdictUnknown,
			Details: "Hash SHA-256 não fornecido",
		}, nil
	}

	// 1. Camada 1: Cache Local Persistente
	var cachedRec *cache.HashRecord
	if !forceRecheck {
		if rec, exists, err := e.store.Get(sha256); err == nil && exists && rec != nil {
			cachedRec = rec

			// Se já for MALICIOSO ou SEGURO confirmado, retorna imediatamente
			if rec.Verdict == cache.VerdictMalicious || rec.Verdict == cache.VerdictSafe {
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

			// Se já passou por AMBOS os verificadores (MalwareBazaar E VirusTotal):
			if rec.MBChecked && rec.VTChecked {
				if e.telemetry != nil {
					e.telemetry.RecordCacheHit(fileName, false)
				}
				return &ScanResult{
					SHA256:       rec.SHA256,
					Verdict:      rec.Verdict,
					ThreatName:   rec.ThreatName,
					Positives:    rec.Positives,
					TotalEngines: rec.TotalEngines,
					Source:       rec.Source + " (Cache Local)",
					Details:      fmt.Sprintf("Dupla validação concluída em %s (MB+VT)", rec.CheckedAt.Format("02/01/2006 15:04")),
				}, nil
			}

			// Se tiver passado por apenas um (ex: MBChecked=true mas VTChecked=false):
			// O usuário especificou: "Se tiver passado apenas por um, deve passar pelo outro também."
			// Portanto não encerramos aqui: prosseguimos para consultar o verificador restante!
		}
	}

	// 1.1 Camada Heurística & Certificados Digitais Authenticode (Economiza cota de API)
	if filePath != "" {
		if _, statErr := os.Stat(filePath); statErr == nil {
			// A) Verificação de Assinatura Authenticode nativa
			sigInfo := heuristics.VerifyAuthenticode(filePath)
			if sigInfo.IsTrusted {
				record := &cache.HashRecord{
					SHA256:       sha256,
					FileName:     fileName,
					FilePath:     filePath,
					Verdict:      cache.VerdictSafe,
					ThreatName:   "",
					Positives:    0,
					TotalEngines: 0,
					Source:       "Authenticode (Assinatura Válida)",
					CheckedAt:    time.Now(),
					MBChecked:    true,
					VTChecked:    true,
				}
				_ = e.store.Save(record)
				e.notifyNewVerdict(record)
				if e.telemetry != nil {
					e.telemetry.Log(LogLevelSafe, "Authenticode", fmt.Sprintf("✔ Assinatura digital válida (Authenticode): %s. Cota de API poupada!", fileName))
				}
				return &ScanResult{
					SHA256:       sha256,
					Verdict:      cache.VerdictSafe,
					Source:       "Authenticode (Assinatura Válida)",
					Details:      "Certificado digital Authenticode válido e confiável pelo Windows. Dispensa consulta externa e poupa cota.",
				}, nil
			} else if sigInfo.Status == heuristics.SigStatusCorrupt {
				// ALERTA GRAVE: Binário adulterado após a assinatura!
				record := &cache.HashRecord{
					SHA256:       sha256,
					FileName:     fileName,
					FilePath:     filePath,
					Verdict:      cache.VerdictMalicious,
					ThreatName:   "Authenticode: Digest Corrompido/Adulterado",
					Positives:    1,
					TotalEngines: 1,
					Source:       "Heurística (Adulteração de Binário)",
					CheckedAt:    time.Now(),
					MBChecked:    true,
					VTChecked:    true,
				}
				_ = e.store.Save(record)
				e.notifyNewVerdict(record)
				if e.telemetry != nil {
					e.telemetry.Log(LogLevelDanger, "Heurística", fmt.Sprintf("🚨 ARQUIVO ADULTERADO: Digest corrompido em %s (%s)", fileName, filePath))
				}
				return &ScanResult{
					SHA256:       sha256,
					Verdict:      cache.VerdictMalicious,
					ThreatName:   "Adulteração de Binário (Digest Corrupt)",
					Positives:    1,
					TotalEngines: 1,
					Source:       "Heurística Authenticode",
					Details:      "O arquivo possui assinatura digital inválida/adulterada (modificado após ter sido assinado).",
				}, nil
			}

			// B) Análise Heurística de Seções PE & Entropia (Packers)
			peRes := heuristics.AnalyzePE(filePath)
			if peRes.IsSuspicious && e.telemetry != nil {
				e.telemetry.Log(LogLevelWarn, "Heurística/PE", fmt.Sprintf("⚠ Indicador suspeito em %s: %s (Entropia: %.2f)", fileName, strings.Join(peRes.Indicators, "; "), peRes.MaxEntropy))
			}
		}
	}

	mbChecked := false
	vtChecked := false
	var currentThreat string
	var currentPositives, currentTotalEngines int

	if cachedRec != nil {
		mbChecked = cachedRec.MBChecked
		vtChecked = cachedRec.VTChecked
		currentThreat = cachedRec.ThreatName
		currentPositives = cachedRec.Positives
		currentTotalEngines = cachedRec.TotalEngines
	}

	// 2. Verificador 1: MalwareBazaar (Consulta Abuse.ch)
	if !mbChecked {
		mbResult, mbErr := e.mbClient.CheckHashWithFile(ctx, sha256, fileName)
		if mbErr == nil && mbResult != nil {
			mbChecked = true
			if mbResult.Verdict == cache.VerdictMalicious {
				// Ameaça confirmada no MalwareBazaar!
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
					MBChecked:    true,
					VTChecked:    vtChecked,
				}
				_ = e.store.Save(record)
				e.notifyNewVerdict(record)
				if e.telemetry != nil {
					e.telemetry.Log(LogLevelDanger, "MalwareBazaar", fmt.Sprintf("🚨 AMEAÇA DETECTADA: %s (%s)", mbResult.ThreatName, fileName))
				}
				return mbResult, nil
			}
		}
	}

	// 3. Verificador 2: VirusTotal (70+ motores antivírus)
	if !vtChecked && e.vtClient.HasAPIKey() {
		vtResult, vtErr := e.vtClient.CheckHashWithFile(ctx, sha256, fileName)
		if vtErr == nil && vtResult != nil {
			vtChecked = true
			currentPositives = vtResult.Positives
			currentTotalEngines = vtResult.TotalEngines

			if vtResult.Verdict == cache.VerdictMalicious {
				record := &cache.HashRecord{
					SHA256:       sha256,
					FileName:     fileName,
					FilePath:     filePath,
					Verdict:      cache.VerdictMalicious,
					ThreatName:   vtResult.ThreatName,
					Positives:    vtResult.Positives,
					TotalEngines: vtResult.TotalEngines,
					Source:       "VirusTotal",
					CheckedAt:    time.Now(),
					MBChecked:    mbChecked,
					VTChecked:    true,
				}
				_ = e.store.Save(record)
				e.notifyNewVerdict(record)
				if e.telemetry != nil {
					e.telemetry.Log(LogLevelDanger, "VirusTotal", fmt.Sprintf("🚨 MALWARE CONFIRMADO: %s (%s)", vtResult.ThreatName, fileName))
				}
				return vtResult, nil
			} else if vtResult.Verdict == cache.VerdictSafe {
				record := &cache.HashRecord{
					SHA256:       sha256,
					FileName:     fileName,
					FilePath:     filePath,
					Verdict:      cache.VerdictSafe,
					ThreatName:   "",
					Positives:    0,
					TotalEngines: vtResult.TotalEngines,
					Source:       "VirusTotal",
					CheckedAt:    time.Now(),
					MBChecked:    mbChecked,
					VTChecked:    true,
				}
				_ = e.store.Save(record)
				e.notifyNewVerdict(record)
				if e.telemetry != nil {
					e.telemetry.Log(LogLevelSafe, "VirusTotal", fmt.Sprintf("✔ LIMPO CONFIRMADO por %d motores: %s", vtResult.TotalEngines, fileName))
				}
				return vtResult, nil
			}
		}
	}

	// 4. REGRA REQUISITADA:
	// Para ser "Não Catalogado" (UNKNOWN), deve ter passado por AMBOS os verificadores (Bazaar e VirusTotal).
	// Se tiver passado apenas por um, seu status é PENDENTE de verificação dupla.
	var finalVerdict cache.Verdict
	var finalSource string
	var finalDetails string

	if mbChecked && vtChecked {
		finalVerdict = cache.VerdictUnknown
		finalSource = "MalwareBazaar + VirusTotal"
		finalDetails = "Hash verificado em ambas as bases (MalwareBazaar e VirusTotal). Não catalogado em nenhum dos serviços."
		if e.telemetry != nil {
			e.telemetry.Log(LogLevelInfo, "DuplaChecagem", fmt.Sprintf("✔ Dupla verificação concluída para %s (MB e VT)", fileName))
		}
	} else if mbChecked && !vtChecked {
		finalVerdict = cache.VerdictPending
		finalSource = "MalwareBazaar (Pendente VirusTotal)"
		finalDetails = "Verificado no MalwareBazaar. Aguardando análise no VirusTotal para validação dupla."
	} else if !mbChecked && vtChecked {
		finalVerdict = cache.VerdictPending
		finalSource = "VirusTotal (Pendente MalwareBazaar)"
		finalDetails = "Verificado no VirusTotal. Aguardando análise no MalwareBazaar para validação dupla."
	} else {
		finalVerdict = cache.VerdictPending
		finalSource = "Pendente"
		finalDetails = "Aguardando envio para verificação nos serviços de inteligência."
	}

	record := &cache.HashRecord{
		SHA256:       sha256,
		FileName:     fileName,
		FilePath:     filePath,
		Verdict:      finalVerdict,
		ThreatName:   currentThreat,
		Positives:    currentPositives,
		TotalEngines: currentTotalEngines,
		Source:       finalSource,
		CheckedAt:    time.Now(),
		MBChecked:    mbChecked,
		VTChecked:    vtChecked,
	}
	_ = e.store.Save(record)
	e.notifyNewVerdict(record)

	return &ScanResult{
		SHA256:       sha256,
		Verdict:      finalVerdict,
		Source:       finalSource,
		TotalEngines: currentTotalEngines,
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
