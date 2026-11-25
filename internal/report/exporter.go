package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"secure-go/internal/cache"
)

// ReportSummary resume os totais de itens analisados no relatório.
type ReportSummary struct {
	Total      int `json:"total"`
	Safe       int `json:"safe"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Unknown    int `json:"unknown"`
}

// AuditReport representa a estrutura consolidada para exportação em JSON.
type AuditReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Application string              `json:"application"`
	Summary     ReportSummary       `json:"summary"`
	Records     []*cache.HashRecord `json:"records"`
}

// ExportToCSV exporta a lista de registros de hashes para um arquivo CSV estruturado.
func ExportToCSV(records []*cache.HashRecord, destPath string) error {
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("falha ao criar arquivo CSV: %w", err)
	}
	defer f.Close()

	// Escreve BOM UTF-8 para garantir compatibilidade com Microsoft Excel
	_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"SHA-256",
		"Nome do Arquivo",
		"Caminho no Disco",
		"Veredito",
		"Nome da Ameaça",
		"Positivos",
		"Total Motores",
		"Fonte de Análise",
		"Data/Hora de Verificação",
		"Checado MalwareBazaar",
		"Checado VirusTotal",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range records {
		mbStr := "Não"
		if r.MBChecked {
			mbStr = "Sim"
		}
		vtStr := "Não"
		if r.VTChecked {
			vtStr = "Sim"
		}

		row := []string{
			r.SHA256,
			r.FileName,
			r.FilePath,
			string(r.Verdict),
			r.ThreatName,
			strconv.Itoa(r.Positives),
			strconv.Itoa(r.TotalEngines),
			r.Source,
			r.CheckedAt.Format("02/01/2006 15:04:05"),
			mbStr,
			vtStr,
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ExportToJSON exporta a lista de hashes com sumário de ameaças em formato JSON legível.
func ExportToJSON(records []*cache.HashRecord, destPath string) error {
	var summary ReportSummary
	summary.Total = len(records)

	for _, r := range records {
		switch r.Verdict {
		case cache.VerdictSafe:
			summary.Safe++
		case cache.VerdictMalicious:
			summary.Malicious++
		case cache.VerdictSuspicious:
			summary.Suspicious++
		default:
			summary.Unknown++
		}
	}

	report := AuditReport{
		GeneratedAt: time.Now(),
		Application: "SecureGo - Monitor em Tempo Real & Analisador de Ameaças",
		Summary:     summary,
		Records:     records,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao serializar relatório JSON: %w", err)
	}

	return os.WriteFile(destPath, data, 0644)
}
