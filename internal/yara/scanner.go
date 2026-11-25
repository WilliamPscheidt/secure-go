package yara

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maxScanFileSize = 50 * 1024 * 1024 // 50MB limite de leitura em memória

// Scanner gerencia e executa conjuntos de regras YARA contra buffers de memória e arquivos no disco.
type Scanner struct {
	rules []Rule
	mu    sync.RWMutex
}

// NewScanner inicializa um novo motor de varredura YARA offline.
func NewScanner() *Scanner {
	return &Scanner{
		rules: []Rule{},
	}
}

// AddRule adiciona uma regra compilada ao motor.
func (s *Scanner) AddRule(r Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, r)
}

// AddRulesFromSource compila e adiciona regras a partir de uma string com código YARA.
func (s *Scanner) AddRulesFromSource(src string) (int, error) {
	parsed, err := ParseRuleString(src)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, parsed...)
	return len(parsed), nil
}

// AddRulesFromFile carrega e compila regras a partir de um arquivo .yar ou .yara.
func (s *Scanner) AddRulesFromFile(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("falha ao ler arquivo de regras YARA: %w", err)
	}
	return s.AddRulesFromSource(string(data))
}

// AddRulesFromDir carrega recursivamente todos os arquivos .yar e .yara de uma pasta.
func (s *Scanner) AddRulesFromDir(dirPath string) (int, error) {
	var totalAdded int
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yar" || ext == ".yara" {
			n, pErr := s.AddRulesFromFile(path)
			if pErr == nil {
				totalAdded += n
			}
		}
		return nil
	})
	return totalAdded, err
}

// Count retorna o número total de regras YARA ativas no motor.
func (s *Scanner) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// Rules retorna uma cópia da lista de regras cadastradas.
func (s *Scanner) Rules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]Rule, len(s.rules))
	copy(cp, s.rules)
	return cp
}

// matchHexWithMask verifica se pattern coincide com data considerando máscara (0x00 = wildcard ??)
func matchHexWithMask(data, pattern, mask []byte) (bool, int) {
	pLen := len(pattern)
	dLen := len(data)
	if dLen < pLen {
		return false, -1
	}

	for i := 0; i <= dLen-pLen; i++ {
		matched := true
		for j := 0; j < pLen; j++ {
			if mask[j] == 0xFF && data[i+j] != pattern[j] {
				matched = false
				break
			}
		}
		if matched {
			return true, i
		}
	}
	return false, -1
}

// ScanBytes avalia o conteúdo em bytes contra todas as regras YARA carregadas.
func (s *Scanner) ScanBytes(data []byte) ([]Match, error) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	if len(rules) == 0 || len(data) == 0 {
		return nil, nil
	}

	// Pré-computa versão minúscula de data para buscas rápidas nocase
	dataLower := bytes.ToLower(data)

	var matches []Match

	for _, rule := range rules {
		var matchedPatterns []string
		firstOffset := int64(-1)

		for _, pat := range rule.Patterns {
			patMatched := false
			matchPos := -1

			switch pat.Type {
			case PatternText:
				// 1. Verificação ASCII
				if pat.Modifiers.Ascii {
					if pat.Modifiers.Nocase {
						patLower := bytes.ToLower(pat.Bytes)
						if idx := bytes.Index(dataLower, patLower); idx != -1 {
							patMatched = true
							matchPos = idx
						}
					} else {
						if idx := bytes.Index(data, pat.Bytes); idx != -1 {
							patMatched = true
							matchPos = idx
						}
					}
				}

				// 2. Verificação WIDE (UTF-16LE)
				if !patMatched && pat.Modifiers.Wide {
					wideBytes := toWideBytes(pat.Raw)
					if pat.Modifiers.Nocase {
						patLower := bytes.ToLower(wideBytes)
						if idx := bytes.Index(dataLower, patLower); idx != -1 {
							patMatched = true
							matchPos = idx
						}
					} else {
						if idx := bytes.Index(data, wideBytes); idx != -1 {
							patMatched = true
							matchPos = idx
						}
					}
				}

			case PatternHex:
				if len(pat.Mask) > 0 {
					ok, idx := matchHexWithMask(data, pat.Bytes, pat.Mask)
					if ok {
						patMatched = true
						matchPos = idx
					}
				} else {
					if idx := bytes.Index(data, pat.Bytes); idx != -1 {
						patMatched = true
						matchPos = idx
					}
				}

			case PatternRegex:
				if pat.Regex != nil {
					loc := pat.Regex.FindIndex(data)
					if loc != nil {
						patMatched = true
						matchPos = loc[0]
					}
				}
			}

			if patMatched {
				matchedPatterns = append(matchedPatterns, pat.ID)
				if firstOffset == -1 || int64(matchPos) < firstOffset {
					firstOffset = int64(matchPos)
				}
			}
		}

		// Avaliação da Condição
		isRuleMatched := false
		if rule.ConditionStr != "" {
			isRuleMatched = EvalCondition(rule.ConditionStr, matchedPatterns, len(rule.Patterns))
		} else {
			switch rule.ConditionType {
			case ConditionAll:
				isRuleMatched = len(matchedPatterns) == len(rule.Patterns) && len(rule.Patterns) > 0
			case ConditionAtLeastN:
				isRuleMatched = len(matchedPatterns) >= rule.ConditionN && rule.ConditionN > 0
			case ConditionAny:
				fallthrough
			default:
				isRuleMatched = len(matchedPatterns) > 0
			}
		}

		if isRuleMatched {
			matches = append(matches, Match{
				RuleName:        rule.Name,
				Description:     rule.Meta.Description,
				ThreatLevel:     rule.Meta.ThreatLevel,
				Author:          rule.Meta.Author,
				Tags:            rule.Tags,
				MatchedPatterns: matchedPatterns,
				Offset:          firstOffset,
			})
		}
	}

	return matches, nil
}

// ScanFile lê o arquivo no disco (até 50MB) e o inspeciona contra as regras YARA.
func (s *Scanner) ScanFile(filePath string) ([]Match, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("erro ao abrir arquivo para varredura YARA: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.IsDir() || stat.Size() == 0 {
		return nil, nil
	}

	limitReader := io.LimitReader(f, maxScanFileSize)
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler arquivo: %w", err)
	}

	return s.ScanBytes(data)
}
