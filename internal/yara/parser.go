package yara

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// StripComments remove comentários de linha única (//) e multi-linha (/* */).
func StripComments(input string) string {
	// Remove multi-line comments
	reMulti := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	cleaned := reMulti.ReplaceAllString(input, "")

	// Remove single-line comments
	var lines []string
	for _, line := range strings.Split(cleaned, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if idx := strings.Index(line, "//"); idx != -1 {
			// Certifica-se de que não está dentro de aspas
			before := line[:idx]
			if strings.Count(before, "\"")%2 == 0 {
				line = before
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// unescapeString converte escapes como \n, \r, \t, \xNN e \"
func unescapeString(raw string) string {
	s := strings.ReplaceAll(raw, `\\`, `\`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\t`, "\t")
	return s
}

// toWideBytes converte uma string ASCII para sequência UTF-16LE em bytes.
func toWideBytes(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = byte(c)
		out[i*2+1] = 0x00
	}
	return out
}

// parseHexPattern converte { 4D 5A ?? 00 } em bytes e máscara de wildcards.
func parseHexPattern(raw string) ([]byte, []byte, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "{")
	trimmed = strings.TrimSuffix(trimmed, "}")
	tokens := strings.Fields(trimmed)

	var pattern []byte
	var mask []byte

	for _, token := range tokens {
		upper := strings.ToUpper(token)
		if upper == "??" || upper == "?" {
			pattern = append(pattern, 0x00)
			mask = append(mask, 0x00) // Wildcard
		} else {
			val, err := hex.DecodeString(upper)
			if err != nil || len(val) != 1 {
				return nil, nil, fmt.Errorf("token hex inválido: %s", token)
			}
			pattern = append(pattern, val[0])
			mask = append(mask, 0xFF) // Exato
		}
	}
	return pattern, mask, nil
}

type ruleBlock struct {
	name string
	tags string
	body string
}

func extractRuleBlocks(text string) []ruleBlock {
	var blocks []ruleBlock
	idx := 0
	length := len(text)

	for idx < length {
		rulePos := strings.Index(text[idx:], "rule ")
		if rulePos == -1 {
			break
		}
		ruleStart := idx + rulePos
		openBrace := strings.Index(text[ruleStart:], "{")
		if openBrace == -1 {
			break
		}
		openBracePos := ruleStart + openBrace

		header := text[ruleStart+5 : openBracePos]
		headerParts := strings.SplitN(header, ":", 2)
		name := strings.TrimSpace(headerParts[0])
		var tags string
		if len(headerParts) > 1 {
			tags = strings.TrimSpace(headerParts[1])
		}

		// Percorre o corpo contando chaves com suporte a strings
		depth := 1
		curr := openBracePos + 1
		inQuote := false

		for curr < length && depth > 0 {
			ch := text[curr]
			if ch == '"' && (curr == 0 || text[curr-1] != '\\') {
				inQuote = !inQuote
			} else if !inQuote {
				if ch == '{' {
					depth++
				} else if ch == '}' {
					depth--
				}
			}
			curr++
		}

		if depth == 0 {
			body := text[openBracePos+1 : curr-1]
			blocks = append(blocks, ruleBlock{
				name: name,
				tags: tags,
				body: body,
			})
			idx = curr
		} else {
			break
		}
	}
	return blocks
}

// ParseRuleString analisa uma string contendo uma ou mais regras YARA.
func ParseRuleString(yaraCode string) ([]Rule, error) {
	clean := StripComments(yaraCode)
	var rules []Rule

	blocks := extractRuleBlocks(clean)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("nenhuma regra YARA válida encontrada")
	}

	for _, b := range blocks {
		ruleName := b.name
		tagsStr := b.tags
		body := b.body

		var tags []string
		if tagsStr != "" {
			tags = strings.Fields(tagsStr)
		}

		rule := Rule{
			Name: ruleName,
			Tags: tags,
			Meta: RuleMeta{
				ThreatLevel: "HIGH", // Nível padrão se não especificado
			},
		}

		// 1. Extração do bloco meta:
		reMeta := regexp.MustCompile(`(?s)\bmeta\s*:(.*?)(?:\bstrings\s*:|\bcondition\s*:|\z)`)
		if metaMatch := reMeta.FindStringSubmatch(body); len(metaMatch) > 1 {
			metaLines := strings.Split(metaMatch[1], "\n")
			for _, line := range metaLines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.ToLower(strings.TrimSpace(parts[0]))
					val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
					switch key {
					case "author":
						rule.Meta.Author = val
					case "description":
						rule.Meta.Description = val
					case "threat_level", "severity":
						rule.Meta.ThreatLevel = strings.ToUpper(val)
					case "reference":
						rule.Meta.Reference = val
					case "date":
						rule.Meta.Date = val
					}
				}
			}
		}

		// 2. Extração do bloco strings:
		reStrings := regexp.MustCompile(`(?s)\bstrings\s*:(.*?)(?:\bcondition\s*:|\z)`)
		if strMatch := reStrings.FindStringSubmatch(body); len(strMatch) > 1 {
			lines := strings.Split(strMatch[1], "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "$") {
					continue
				}

				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}

				patID := strings.TrimSpace(parts[0])
				remainder := strings.TrimSpace(parts[1])

				// Padrão A: String de texto "$s = \"...\" [modifiers]"
				if strings.HasPrefix(remainder, "\"") {
					endQuote := strings.LastIndex(remainder, "\"")
					if endQuote > 0 {
						rawStr := unescapeString(remainder[1:endQuote])
						modStr := strings.ToLower(remainder[endQuote+1:])

						mod := PatternModifier{
							Nocase: strings.Contains(modStr, "nocase"),
							Wide:   strings.Contains(modStr, "wide"),
							Ascii:  strings.Contains(modStr, "ascii") || !strings.Contains(modStr, "wide"),
						}

						rule.Patterns = append(rule.Patterns, Pattern{
							ID:        patID,
							Type:      PatternText,
							Raw:       rawStr,
							Bytes:     []byte(rawStr),
							Modifiers: mod,
						})
					}
				} else if strings.HasPrefix(remainder, "{") {
					// Padrão B: Hexadecimal "$h = { 4D 5A ?? 00 }"
					endBrace := strings.Index(remainder, "}")
					if endBrace > 0 {
						hexBlock := remainder[:endBrace+1]
						bytes, mask, err := parseHexPattern(hexBlock)
						if err == nil {
							rule.Patterns = append(rule.Patterns, Pattern{
								ID:    patID,
								Type:  PatternHex,
								Raw:   hexBlock,
								Bytes: bytes,
								Mask:  mask,
							})
						}
					}
				} else if strings.HasPrefix(remainder, "/") {
					// Padrão C: Regex "$re = /pattern/ [nocase]"
					endSlash := strings.LastIndex(remainder, "/")
					if endSlash > 0 {
						regexBody := remainder[1:endSlash]
						modStr := strings.ToLower(remainder[endSlash+1:])
						if strings.Contains(modStr, "nocase") || strings.Contains(modStr, "i") {
							regexBody = "(?i)" + regexBody
						}
						compiled, err := regexp.Compile(regexBody)
						if err == nil {
							rule.Patterns = append(rule.Patterns, Pattern{
								ID:    patID,
								Type:  PatternRegex,
								Raw:   remainder[:endSlash+1],
								Regex: compiled,
							})
						}
					}
				}
			}
		}

		rule.PatternCount = len(rule.Patterns)

		// 3. Extração do bloco condition:
		reCondition := regexp.MustCompile(`(?s)\bcondition\s*:(.*)`)
		if condMatch := reCondition.FindStringSubmatch(body); len(condMatch) > 1 {
			condStr := strings.TrimSpace(condMatch[1])
			rule.ConditionStr = condStr
			lowerCond := strings.ToLower(condStr)

			if strings.TrimSpace(lowerCond) == "all of them" {
				rule.ConditionType = ConditionAll
			} else if strings.TrimSpace(lowerCond) == "any of them" {
				rule.ConditionType = ConditionAny
			} else if matchAtLeast := regexp.MustCompile(`^(\d+)\s+of\s+them$`).FindStringSubmatch(strings.TrimSpace(lowerCond)); len(matchAtLeast) > 1 {
				n, _ := strconv.Atoi(matchAtLeast[1])
				rule.ConditionType = ConditionAtLeastN
				rule.ConditionN = n
			} else {
				rule.ConditionType = ConditionCustom
			}
		} else {
			rule.ConditionType = ConditionAny
		}

		rules = append(rules, rule)
	}

	return rules, nil
}
