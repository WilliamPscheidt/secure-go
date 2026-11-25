package heuristics

import (
	"debug/pe"
	"io"
	"math"
	"os"
	"strings"
)

// SectionInfo armazena dados de uma seção do cabeçalho PE.
type SectionInfo struct {
	Name    string  `json:"name"`
	Size    uint32  `json:"size"`
	Entropy float64 `json:"entropy"`
}

// PEAnalysisResult resume os indicadores heurísticos extraídos de um executável PE.
type PEAnalysisResult struct {
	IsValidPE    bool          `json:"is_valid_pe"`
	Architecture string        `json:"architecture"` // x86, x64, ARM
	Sections     []SectionInfo `json:"sections"`
	MaxEntropy   float64       `json:"max_entropy"`
	IsPacked     bool          `json:"is_packed"`
	PackerName   string        `json:"packer_name,omitempty"`
	IsSuspicious bool          `json:"is_suspicious"`
	Indicators   []string      `json:"indicators,omitempty"`
}

var knownPackerSections = map[string]string{
	"upx0":     "UPX (Ultimate Packer for eXecutables)",
	"upx1":     "UPX (Ultimate Packer for eXecutables)",
	"upx2":     "UPX (Ultimate Packer for eXecutables)",
	".aspack":  "ASPack Crypter",
	".themida": "Themida / WinLicense Protector",
	".vmp0":    "VMProtect Obfuscator",
	".vmp1":    "VMProtect Obfuscator",
	"pec2":     "PECompact",
	"fsg!":     "FSG Fast Small Good",
	".nsp0":    "NsPack Crypter",
	"mpress1":  "MPRESS Packer",
}

// CalculateEntropy calcula a entropia de Shannon de uma sequência de bytes (0.0 a 8.0).
// Valores acima de 7.1 em seções de código indicam alta compressão ou criptografia/ofuscação.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var count [256]int
	for _, b := range data {
		count[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, c := range count {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// AnalyzePE examina o executável portátil (PE), calculando entropia de seções e identificando packers.
func AnalyzePE(filePath string) PEAnalysisResult {
	res := PEAnalysisResult{
		IsValidPE: false,
	}

	f, err := os.Open(filePath)
	if err != nil {
		return res
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return res
	}
	defer peFile.Close()

	res.IsValidPE = true

	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		res.Architecture = "x64 (AMD64)"
	case pe.IMAGE_FILE_MACHINE_I386:
		res.Architecture = "x86 (32-bit)"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		res.Architecture = "ARM64"
	default:
		res.Architecture = "Outra / Desconhecida"
	}

	var maxEntropy float64

	for _, sec := range peFile.Sections {
		name := strings.TrimRight(strings.ToLower(sec.Name), "\x00")

		// Lê até 512KB da seção para calcular entropia com alta precisão e sem consumir muita memória
		limitReader := io.LimitReader(sec.Open(), 512*1024)
		secData, _ := io.ReadAll(limitReader)

		secEntropy := CalculateEntropy(secData)
		if secEntropy > maxEntropy {
			maxEntropy = secEntropy
		}

		res.Sections = append(res.Sections, SectionInfo{
			Name:    sec.Name,
			Size:    sec.Size,
			Entropy: math.Round(secEntropy*100) / 100,
		})

		// 1. Checa assinaturas de seções de packers conhecidos
		if packer, found := knownPackerSections[name]; found {
			res.IsPacked = true
			if res.PackerName == "" {
				res.PackerName = packer
			}
			res.Indicators = append(res.Indicators, "Seção empacotada detectada: "+sec.Name+" ("+packer+")")
		}

		// 2. Se a seção de código (.text) tiver entropia anormalmente alta (> 7.2)
		if strings.Contains(name, "text") || strings.Contains(name, "code") {
			if secEntropy > 7.2 {
				res.IsPacked = true
				res.Indicators = append(res.Indicators, "Alta entropia na seção de código (> 7.2): provável ofuscação/crypter")
			}
		}
	}

	res.MaxEntropy = math.Round(maxEntropy*100) / 100

	if res.MaxEntropy > 7.35 {
		res.IsSuspicious = true
		res.Indicators = append(res.Indicators, "Entropia global muito elevada (suspeita de carga maliciosa embutida)")
	}

	if res.IsPacked && res.PackerName != "" {
		res.IsSuspicious = true
	}

	return res
}
