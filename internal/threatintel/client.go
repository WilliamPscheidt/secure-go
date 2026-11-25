package threatintel

import (
	"context"
	"secure-go/internal/cache"
)

// ScanResult representa o resultado unificado da consulta a um serviço de inteligência.
type ScanResult struct {
	SHA256       string        `json:"sha256"`
	Verdict      cache.Verdict `json:"verdict"`
	ThreatName   string        `json:"threat_name"`
	Positives    int           `json:"positives"`
	TotalEngines int           `json:"total_engines"`
	Source       string        `json:"source"`
	Details      string        `json:"details,omitempty"`
}

// Client define a interface para qualquer provedor de análise de hash.
type Client interface {
	Name() string
	CheckHash(ctx context.Context, sha256 string) (*ScanResult, error)
}
