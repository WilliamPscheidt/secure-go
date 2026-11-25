package ui

import (
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/threatintel"
	"secure-go/internal/yara"
)

type YaraTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	rules        []yara.Rule
	filtered     []yara.Rule
	listWidget   *widget.List
	searchEntry  *widget.Entry
	lblTotal     *widget.Label
	lblCritical  *widget.Label
	lblHigh      *widget.Label
	lblOffline   *widget.Label
	mu           sync.RWMutex
}

func NewYaraTab(win fyne.Window, engine *threatintel.Engine) *YaraTab {
	yt := &YaraTab{
		window: win,
		engine: engine,
	}

	yt.initUI()
	yt.Refresh()
	return yt
}

func (yt *YaraTab) initUI() {
	yt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	yt.lblCritical = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	yt.lblHigh = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	yt.lblOffline = widget.NewLabelWithStyle("100% OFFLINE", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	yt.searchEntry = widget.NewEntry()
	yt.searchEntry.SetPlaceHolder("🔍 Filtrar regras por nome, severidade, tag ou descrição...")
	yt.searchEntry.OnChanged = func(q string) {
		yt.filterItems(q)
	}

	yt.listWidget = widget.NewList(
		func() int {
			yt.mu.RLock()
			defer yt.mu.RUnlock()
			return len(yt.filtered)
		},
		func() fyne.CanvasObject {
			titleLbl := widget.NewLabelWithStyle("Rule_Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			descLbl := widget.NewLabel("Descrição da regra heurística e padrões de assinatura...")
			badge := widget.NewLabel("[CRITICAL]")
			badge.TextStyle = fyne.TextStyle{Bold: true}

			return container.NewBorder(nil, nil, nil, badge,
				container.NewVBox(titleLbl, descLbl),
			)
		},
		func(id int, obj fyne.CanvasObject) {
			yt.mu.RLock()
			if id >= len(yt.filtered) {
				yt.mu.RUnlock()
				return
			}
			r := yt.filtered[id]
			yt.mu.RUnlock()

			box := obj.(*fyne.Container)
			badge := box.Objects[1].(*widget.Label)
			vbox := box.Objects[0].(*fyne.Container)
			titleLbl := vbox.Objects[0].(*widget.Label)
			descLbl := vbox.Objects[1].(*widget.Label)

			tagStr := ""
			if len(r.Tags) > 0 {
				tagStr = fmt.Sprintf(" [%s]", strings.Join(r.Tags, ", "))
			}
			titleLbl.SetText(fmt.Sprintf("%s%s  (%d padrões)", r.Name, tagStr, r.PatternCount))

			desc := r.Meta.Description
			if desc == "" {
				desc = "Sem descrição informada"
			}
			if r.Meta.Author != "" {
				desc = fmt.Sprintf("%s (Autor: %s)", desc, r.Meta.Author)
			}
			descLbl.SetText(desc)

			switch r.Meta.ThreatLevel {
			case "CRITICAL":
				badge.SetText("🚨 CRÍTICA")
			case "HIGH":
				badge.SetText("⚠️ ALTA")
			case "MEDIUM":
				badge.SetText("ℹ MÉDIA")
			default:
				badge.SetText("✔ PADRÃO")
			}
		},
	)

	yt.listWidget.OnSelected = func(id int) {
		yt.listWidget.Unselect(id)
		yt.mu.RLock()
		if id >= len(yt.filtered) {
			yt.mu.RUnlock()
			return
		}
		r := yt.filtered[id]
		yt.mu.RUnlock()

		yt.showRuleDetails(r)
	}
}

func (yt *YaraTab) Refresh() {
	scanner := yt.engine.YaraScanner()
	if scanner == nil {
		return
	}

	rules := scanner.Rules()
	total := len(rules)
	criticalCount := 0
	highCount := 0

	for _, r := range rules {
		if r.Meta.ThreatLevel == "CRITICAL" {
			criticalCount++
		} else if r.Meta.ThreatLevel == "HIGH" {
			highCount++
		}
	}

	yt.mu.Lock()
	yt.rules = rules
	yt.mu.Unlock()

	fyne.Do(func() {
		yt.lblTotal.SetText(fmt.Sprintf("%d", total))
		yt.lblCritical.SetText(fmt.Sprintf("%d", criticalCount))
		yt.lblHigh.SetText(fmt.Sprintf("%d", highCount))
		yt.filterItems(yt.searchEntry.Text)
	})
}

func (yt *YaraTab) filterItems(query string) {
	yt.mu.Lock()
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		yt.filtered = yt.rules
	} else {
		var res []yara.Rule
		for _, r := range yt.rules {
			match := strings.Contains(strings.ToLower(r.Name), q) ||
				strings.Contains(strings.ToLower(r.Meta.Description), q) ||
				strings.Contains(strings.ToLower(r.Meta.Author), q) ||
				strings.Contains(strings.ToLower(r.Meta.ThreatLevel), q) ||
				strings.Contains(strings.ToLower(strings.Join(r.Tags, " ")), q)
			if match {
				res = append(res, r)
			}
		}
		yt.filtered = res
	}
	yt.mu.Unlock()

	if yt.listWidget != nil {
		yt.listWidget.Refresh()
	}
}

func (yt *YaraTab) showRuleDetails(r yara.Rule) {
	content := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Regra: %s", r.Name), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("Severidade: %s", r.Meta.ThreatLevel)),
		widget.NewLabel(fmt.Sprintf("Autor: %s", r.Meta.Author)),
		widget.NewLabel(fmt.Sprintf("Descrição: %s", r.Meta.Description)),
		widget.NewLabel(fmt.Sprintf("Referência: %s", r.Meta.Reference)),
		widget.NewLabel(fmt.Sprintf("Total de Padrões Compilados: %d", r.PatternCount)),
		widget.NewLabel(fmt.Sprintf("Condição Lógica: %s", r.ConditionStr)),
	)

	dlg := dialog.NewCustom("Assinatura Heurística YARA", "Fechar", content, yt.window)
	dlg.Resize(fyne.NewSize(580, 260))
	dlg.Show()
}

func (yt *YaraTab) showAddRuleDialog() {
	entry := widget.NewMultiLineEntry()
	entry.SetPlaceHolder(`Cole aqui o código da regra YARA completa:

rule Exemplo_Malware {
    meta:
        description = "Detecta string suspeita"
        threat_level = "HIGH"
    strings:
        $s1 = "malicious_command" nocase
    condition:
        any of them
}`)

	form := dialog.NewForm("Adicionar Regra YARA Customizada", "Compilar e Salvar", "Cancelar", []*widget.FormItem{
		widget.NewFormItem("Código da Regra (.yar)", entry),
	}, func(confirmed bool) {
		if !confirmed {
			return
		}
		code := strings.TrimSpace(entry.Text)
		if code == "" {
			return
		}

		scanner := yt.engine.YaraScanner()
		if scanner == nil {
			dialog.ShowError(fmt.Errorf("motor YARA não inicializado"), yt.window)
			return
		}

		n, err := scanner.AddRulesFromSource(code)
		if err != nil {
			dialog.ShowError(fmt.Errorf("erro de sintaxe na regra YARA:\n%w", err), yt.window)
			return
		}

		dialog.ShowInformation("Regra Compilada", fmt.Sprintf("Sucesso! %d regra(s) YARA compilada(s) e adicionada(s) à memória do motor.", n), yt.window)
		yt.Refresh()
	}, yt.window)

	form.Resize(fyne.NewSize(620, 380))
	form.Show()
}

func (yt *YaraTab) showTestScanDialog() {
	filePathEntry := widget.NewEntry()
	filePathEntry.SetPlaceHolder("Caminho do arquivo para escanear (ex: C:\\temp\\amostra.exe)...")

	form := dialog.NewForm("Escanear Arquivo com Motor YARA", "Escanear Agora", "Cancelar", []*widget.FormItem{
		widget.NewFormItem("Caminho do Arquivo", filePathEntry),
	}, func(confirmed bool) {
		if !confirmed {
			return
		}
		path := strings.TrimSpace(filePathEntry.Text)
		if path == "" {
			return
		}

		scanner := yt.engine.YaraScanner()
		if scanner == nil {
			dialog.ShowError(fmt.Errorf("motor YARA indisponível"), yt.window)
			return
		}

		matches, err := scanner.ScanFile(path)
		if err != nil {
			dialog.ShowError(fmt.Errorf("falha ao escanear arquivo:\n%w", err), yt.window)
			return
		}

		if len(matches) == 0 {
			dialog.ShowInformation("Resultado YARA", fmt.Sprintf("✔ NENHUMA AMEAÇA DETECTADA!\n\nO arquivo '%s' passou por todas as %d regras YARA ativas sem correspondências.", path, scanner.Count()), yt.window)
		} else {
			var details []string
			for i, m := range matches {
				details = append(details, fmt.Sprintf("%d. Regra: %s [%s]\n   Descrição: %s\n   Padrões que bateram: %s",
					i+1, m.RuleName, m.ThreatLevel, m.Description, strings.Join(m.MatchedPatterns, ", ")))
			}
			msg := fmt.Sprintf("🚨 AMEAÇA CONFIRMADA POR YARA!\n\nArquivo: %s\nTotal de Regras Positivas: %d\n\n%s", path, len(matches), strings.Join(details, "\n\n"))
			dialog.ShowInformation("Alerta YARA", msg, yt.window)
		}
	}, yt.window)

	form.Resize(fyne.NewSize(580, 220))
	form.Show()
}

func (yt *YaraTab) Content() fyne.CanvasObject {
	cardTotal := NewMetricCard("REGRAS ATIVAS", "Assinaturas compiladas", yt.lblTotal, "YARA", ColorBluePrimary, ColorBlueAlpha)
	cardCrit := NewMetricCard("SEVERIDADE CRÍTICA", "Ransomware / Mimikatz", yt.lblCritical, "CRÍTICA", ColorDanger, ColorDangerBg)
	cardHigh := NewMetricCard("SEVERIDADE ALTA", "ReverseShells / WebShells", yt.lblHigh, "ALTA", ColorWarn, ColorWarnBg)
	cardOff := NewMetricCard("MODO DE OPERAÇÃO", "Zero consumo de API", yt.lblOffline, "OFFLINE", ColorCyan, ColorCyanAlpha)

	btnAddRule := widget.NewButtonWithIcon("Adicionar Regra (.yar)", theme.ContentAddIcon(), yt.showAddRuleDialog)
	btnAddRule.Importance = widget.HighImportance

	btnScanFile := widget.NewButtonWithIcon("Testar Arquivo com YARA", IconFASearch, yt.showTestScanDialog)

	btnReload := widget.NewButtonWithIcon("Recarregar", theme.ViewRefreshIcon(), yt.Refresh)

	toolbar := NewPanelCard("CENTRAL DE REGRAS YARA & INTELIGÊNCIA OFFLINE",
		container.NewHBox(btnAddRule, btnScanFile, btnReload),
		yt.searchEntry,
	)

	header := container.NewVBox(
		container.NewGridWithColumns(4,
			cardTotal,
			cardCrit,
			cardHigh,
			cardOff,
		),
		toolbar,
	)

	return container.NewBorder(header, nil, nil, nil, yt.listWidget)
}
