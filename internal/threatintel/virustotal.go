package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"secure-go/internal/cache"
)

// VirusTotalClient implementa o cliente da API v3 do VirusTotal com Rate Limiting.
type VirusTotalClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	limiterMu  sync.Mutex
	lastCall   time.Time
	interval   time.Duration // Padrão: 15s para respeitar 4 req/minuto
}

// NewVirusTotalClient instancia o cliente com a chave informada.
func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		baseURL:  "https://www.virustotal.com/api/v3/files/",
		interval: 15 * time.Second, // Garante máximo de 4 req/min
	}
}

func (v *VirusTotalClient) Name() string {
	return "VirusTotal"
}

func (v *VirusTotalClient) SetAPIKey(key string) {
	v.limiterMu.Lock()
	defer v.limiterMu.Unlock()
	v.apiKey = key
}

func (v *VirusTotalClient) HasAPIKey() bool {
	v.limiterMu.Lock()
	defer v.limiterMu.Unlock()
	return v.apiKey != ""
}

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
			MeaningfulName string `json:"meaningful_name"`
		} `json:"attributes"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// CheckHash consulta o hash na API v3 do VirusTotal respeitando o rate limiter.
func (v *VirusTotalClient) CheckHash(ctx context.Context, sha256 string) (*ScanResult, error) {
	if !v.HasAPIKey() {
		return nil, fmt.Errorf("chave de API do VirusTotal não configurada")
	}

	// Rate Limiting seguro: aguarda intervalo de segurança se necessário
	v.limiterMu.Lock()
	elapsed := time.Since(v.lastCall)
	if elapsed < v.interval {
		waitDur := v.interval - elapsed
		v.limiterMu.Unlock()
		select {
		case <-time.After(waitDur):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		v.limiterMu.Lock()
	}
	v.lastCall = time.Now()
	v.limiterMu.Unlock()

	reqURL := v.baseURL + sha256
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar requisição VirusTotal: %w", err)
	}
	req.Header.Set("x-apikey", v.apiKey)
	req.Header.Set("User-Agent", "SecureGo-Antimalware/1.0")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro de conexão com VirusTotal: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ScanResult{
			SHA256:  sha256,
			Verdict: cache.VerdictUnknown,
			Source:  "VirusTotal",
			Details: "Arquivo nunca visto no VirusTotal (404 Not Found)",
		}, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("cota de requisições do VirusTotal excedida (429 Too Many Requests)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VirusTotal retornou código http %d", resp.StatusCode)
	}

	var vtResp vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil, fmt.Errorf("erro ao decodificar JSON do VirusTotal: %w", err)
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	total := stats.Harmless + stats.Malicious + stats.Suspicious + stats.Undetected + stats.Timeout
	positives := stats.Malicious

	result := &ScanResult{
		SHA256:       sha256,
		Positives:    positives,
		TotalEngines: total,
		Source:       "VirusTotal",
		ThreatName:   vtResp.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
	}

	// Critério de veredito:
	// >= 2 motores maliciosos: MALICIOUS
	// 1 motor malicioso ou motores suspeitos: SUSPICIOUS
	// 0 motores maliciosos e pelo menos 1 harmless/undetected: SAFE
	if positives >= 2 {
		result.Verdict = cache.VerdictMalicious
		if result.ThreatName == "" {
			result.ThreatName = fmt.Sprintf("Detecções: %d/%d motores", positives, total)
		}
	} else if positives == 1 || stats.Suspicious > 0 {
		result.Verdict = cache.VerdictSuspicious
		if result.ThreatName == "" {
			result.ThreatName = fmt.Sprintf("Suspeito: %d malicioso, %d suspeito em %d motores", positives, stats.Suspicious, total)
		}
	} else {
		result.Verdict = cache.VerdictSafe
	}

	result.Details = fmt.Sprintf("Engines: %d/%d (Limpo: %d, Malicioso: %d, Suspeito: %d)",
		positives, total, stats.Harmless+stats.Undetected, stats.Malicious, stats.Suspicious)

	return result, nil
}
