package yara

import (
	"regexp"
)

type PatternType int

const (
	PatternText PatternType = iota
	PatternHex
	PatternRegex
)

// PatternModifier contém sinalizadores de modificação de strings no YARA.
type PatternModifier struct {
	Nocase bool
	Wide   bool
	Ascii  bool
}

// Pattern representa uma string, sequência hexadecimal ou expressão regular dentro de uma regra YARA.
type Pattern struct {
	ID        string          // e.g. "$s1", "$h1"
	Type      PatternType     // PatternText, PatternHex, PatternRegex
	Raw       string          // Representação textual original
	Bytes     []byte          // Bytes compilados para busca rápida
	Mask      []byte          // Máscara de bytes para wildcards (0xFF = exato, 0x00 = wildcard ??)
	Regex     *regexp.Regexp  // Regex compilado
	Modifiers PatternModifier
}

// RuleMeta armazena metadados descritivos da regra YARA.
type RuleMeta struct {
	Author      string `json:"author"`
	Description string `json:"description"`
	ThreatLevel string `json:"threat_level"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Reference   string `json:"reference,omitempty"`
	Date        string `json:"date,omitempty"`
}

// ConditionType define o tipo de avaliação lógica dos padrões encontrados.
type ConditionType int

const (
	ConditionAny ConditionType = iota // "any of them"
	ConditionAll                       // "all of them"
	ConditionAtLeastN                  // "N of them" (ex: "2 of them")
	ConditionCustom                    // Expressão booleana customizada
)

// Rule define uma regra YARA completa compilada.
type Rule struct {
	Name          string        `json:"name"`
	Tags          []string      `json:"tags,omitempty"`
	Meta          RuleMeta      `json:"meta"`
	Patterns      []Pattern     `json:"-"`
	PatternCount  int           `json:"pattern_count"`
	ConditionType ConditionType `json:"condition_type"`
	ConditionN    int           `json:"condition_n"`
	ConditionStr  string        `json:"condition"`
}

// Match descreve uma correspondência de ameaça identificada pelo motor YARA.
type Match struct {
	RuleName        string   `json:"rule_name"`
	Description     string   `json:"description"`
	ThreatLevel     string   `json:"threat_level"`
	Author          string   `json:"author"`
	Tags            []string `json:"tags,omitempty"`
	MatchedPatterns []string `json:"matched_patterns"`
	Offset          int64    `json:"offset,omitempty"`
}
