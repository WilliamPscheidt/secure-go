package yara

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reAnyOfGroup = regexp.MustCompile(`(?i)any\s+of\s*\(([^)]+)\)`)
	reAllOfGroup = regexp.MustCompile(`(?i)all\s+of\s*\(([^)]+)\)`)
	reNOfGroup   = regexp.MustCompile(`(?i)(\d+)\s+of\s*\(([^)]+)\)`)
	reAnyOfThem  = regexp.MustCompile(`(?i)\bany\s+of\s+them\b`)
	reAllOfThem  = regexp.MustCompile(`(?i)\ball\s+of\s+them\b`)
	reNOfThem    = regexp.MustCompile(`(?i)\b(\d+)\s+of\s+them\b`)
	reDollarID   = regexp.MustCompile(`\$[a-zA-Z0-9_]+`)
)

// EvalCondition avalia a condição lógica da regra YARA a partir dos IDs correspondidos.
func EvalCondition(condStr string, matchedIDs []string, totalPatterns int) bool {
	matchedMap := make(map[string]bool, len(matchedIDs))
	for _, id := range matchedIDs {
		matchedMap[id] = true
	}

	cond := strings.TrimSpace(condStr)
	if cond == "" {
		return len(matchedIDs) > 0
	}

	// 1. Substituir "any of ($a, $b, ...)"
	cond = reAnyOfGroup.ReplaceAllStringFunc(cond, func(match string) string {
		sub := reAnyOfGroup.FindStringSubmatch(match)
		if len(sub) > 1 {
			ids := reDollarID.FindAllString(sub[1], -1)
			for _, id := range ids {
				if matchedMap[id] {
					return " true "
				}
			}
		}
		return " false "
	})

	// 2. Substituir "all of ($a, $b, ...)"
	cond = reAllOfGroup.ReplaceAllStringFunc(cond, func(match string) string {
		sub := reAllOfGroup.FindStringSubmatch(match)
		if len(sub) > 1 {
			ids := reDollarID.FindAllString(sub[1], -1)
			if len(ids) == 0 {
				return " false "
			}
			for _, id := range ids {
				if !matchedMap[id] {
					return " false "
				}
			}
			return " true "
		}
		return " false "
	})

	// 3. Substituir "N of ($a, $b, ...)"
	cond = reNOfGroup.ReplaceAllStringFunc(cond, func(match string) string {
		sub := reNOfGroup.FindStringSubmatch(match)
		if len(sub) > 2 {
			n, _ := strconv.Atoi(sub[1])
			ids := reDollarID.FindAllString(sub[2], -1)
			count := 0
			for _, id := range ids {
				if matchedMap[id] {
					count++
				}
			}
			if count >= n {
				return " true "
			}
		}
		return " false "
	})

	// 4. Substituir "all of them"
	cond = reAllOfThem.ReplaceAllStringFunc(cond, func(match string) string {
		if len(matchedIDs) == totalPatterns && totalPatterns > 0 {
			return " true "
		}
		return " false "
	})

	// 5. Substituir "any of them"
	cond = reAnyOfThem.ReplaceAllStringFunc(cond, func(match string) string {
		if len(matchedIDs) > 0 {
			return " true "
		}
		return " false "
	})

	// 6. Substituir "N of them"
	cond = reNOfThem.ReplaceAllStringFunc(cond, func(match string) string {
		sub := reNOfThem.FindStringSubmatch(match)
		if len(sub) > 1 {
			n, _ := strconv.Atoi(sub[1])
			if len(matchedIDs) >= n {
				return " true "
			}
		}
		return " false "
	})

	// 7. Substituir variáveis individuais "$s1", etc.
	cond = reDollarID.ReplaceAllStringFunc(cond, func(id string) string {
		if matchedMap[id] {
			return " true "
		}
		return " false "
	})

	// 8. Tokenizar e avaliar a expressão booleana resultante
	tokens := tokenizeBoolExpr(cond)
	parser := &boolParser{tokens: tokens, pos: 0}
	return parser.parseExpr()
}

func tokenizeBoolExpr(s string) []string {
	var tokens []string
	var current strings.Builder

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '(', ')':
			flush()
			tokens = append(tokens, string(ch))
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			current.WriteByte(ch)
		}
	}
	flush()
	return tokens
}

type boolParser struct {
	tokens []string
	pos    int
}

func (p *boolParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *boolParser) next() string {
	tok := p.peek()
	p.pos++
	return tok
}

func (p *boolParser) parseExpr() bool {
	if len(p.tokens) == 0 {
		return false
	}
	return p.parseOr()
}

func (p *boolParser) parseOr() bool {
	val := p.parseAnd()
	for {
		tok := strings.ToLower(p.peek())
		if tok == "or" || tok == "||" {
			p.next()
			right := p.parseAnd()
			val = val || right
		} else {
			break
		}
	}
	return val
}

func (p *boolParser) parseAnd() bool {
	val := p.parseNot()
	for {
		tok := strings.ToLower(p.peek())
		if tok == "and" || tok == "&&" {
			p.next()
			right := p.parseNot()
			val = val && right
		} else {
			break
		}
	}
	return val
}

func (p *boolParser) parseNot() bool {
	tok := strings.ToLower(p.peek())
	if tok == "not" || tok == "!" {
		p.next()
		return !p.parseNot()
	}
	return p.parseAtom()
}

func (p *boolParser) parseAtom() bool {
	tok := strings.ToLower(p.peek())
	if tok == "(" {
		p.next()
		val := p.parseExpr()
		if p.peek() == ")" {
			p.next()
		}
		return val
	}
	p.next()
	return tok == "true" || tok == "1"
}
