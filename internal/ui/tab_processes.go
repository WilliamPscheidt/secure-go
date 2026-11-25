package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/process"
	"secure-go/internal/scheduler"
	"secure-go/internal/threatintel"
)

type ProcessViewItem struct {
	PID      uint32
	Name     string
	ExePath  string
	SHA256   string
	Verdict  cache.Verdict
	Source   string
	Threat   string
	ErrStr   string
}

type ProcessTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	scheduler    *scheduler.Scheduler
	allItems     []ProcessViewItem
	filtered     []ProcessViewItem
	listWidget   *widget.List
	searchEntry  *widget.Entry
	statusLabel    *widget.Label
	lblTotal       *widget.Label
	lblSafe        *widget.Label
	lblUncataloged *widget.Label
	lblThreats     *widget.Label
	btnScanNow     *widget.Button
	mu           sync.RWMutex
}

func NewProcessTab(win fyne.Window, engine *threatintel.Engine, sched *scheduler.Scheduler) *ProcessTab {
	pt := &ProcessTab{
		window:    win,
		engine:    engine,
		scheduler: sched,
	}

	pt.initUI()
	pt.refreshProcesses()

	// Conecta listeners do scheduler para atualizar a interface em tempo real
	sched.AddStatusListener(func(status string) {
		pt.UpdateStatus(status)
	})
	sched.AddReportListener(func(report *scheduler.ScanReport) {
		pt.refreshProcesses()
	})
	sched.AddThreatListener(func(p process.ProcessInfo, threatName string) {
		pt.refreshProcesses()
	})

	return pt
}

func (pt *ProcessTab) initUI() {
	pt.statusLabel = widget.NewLabel("Monitorando em tempo real (intervalo: 30 minutos)")
	pt.statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	pt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	pt.lblSafe = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	pt.lblUncataloged = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	pt.lblThreats = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	pt.searchEntry = widget.NewEntry()
	pt.searchEntry.SetPlaceHolder("🔍 Filtrar processos por nome, PID ou hash...")
	pt.searchEntry.OnChanged = func(q string) {
		pt.filterItems(q)
	}

	pt.btnScanNow = widget.NewButtonWithIcon("Escanear Agora", theme.MediaPlayIcon(), func() {
		pt.btnScanNow.Disable()
		go func() {
			pt.scheduler.TriggerNow()
			time.Sleep(1 * time.Second)
			pt.btnScanNow.Enable()
		}()
	})
	pt.btnScanNow.Importance = widget.HighImportance

	pt.listWidget = widget.NewList(
		func() int {
			pt.mu.RLock()
			defer pt.mu.RUnlock()
			return len(pt.filtered)
		},
		func() fyne.CanvasObject {
			nameLabel := widget.NewLabelWithStyle("ProcessName.exe [PID: 0000]", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			pathLabel := widget.NewLabel("C:\\Windows\\System32\\process.exe")
			badge := widget.NewLabel("[SEGURO]")
			badge.TextStyle = fyne.TextStyle{Bold: true}

			return container.NewBorder(nil, nil, nil, badge,
				container.NewVBox(nameLabel, pathLabel),
			)
		},
		func(id int, obj fyne.CanvasObject) {
			pt.mu.RLock()
			if id >= len(pt.filtered) {
				pt.mu.RUnlock()
				return
			}
			item := pt.filtered[id]
			pt.mu.RUnlock()

			box := obj.(*fyne.Container)
			badge := box.Objects[1].(*widget.Label)
			vbox := box.Objects[0].(*fyne.Container)
			nameLbl := vbox.Objects[0].(*widget.Label)
			pathLbl := vbox.Objects[1].(*widget.Label)

			nameLbl.SetText(fmt.Sprintf("%s  [PID: %d]", item.Name, item.PID))

			displayPath := item.ExePath
			if displayPath == "" {
				displayPath = item.ErrStr
				if displayPath == "" {
					displayPath = "[Processo protegido do sistema / Sem acesso]"
				}
			}
			pathLbl.SetText(displayPath)

			switch item.Verdict {
			case cache.VerdictSafe:
				badge.SetText("✔ SEGURO (Cache)")
			case cache.VerdictMalicious:
				badge.SetText("🚨 MALICIOSO!")
			case cache.VerdictSuspicious:
				badge.SetText("⚠️ SUSPEITO")
			case cache.VerdictUnknown:
				badge.SetText("❔ NÃO CATALOGADO")
			default:
				if item.SHA256 != "" {
					badge.SetText("ℹ AGUARDANDO")
				} else {
					badge.SetText("🔒 SISTEMA")
				}
			}
		},
	)

	pt.listWidget.OnSelected = func(id int) {
		pt.listWidget.Unselect(id)
		pt.mu.RLock()
		if id >= len(pt.filtered) {
			pt.mu.RUnlock()
			return
		}
		item := pt.filtered[id]
		pt.mu.RUnlock()

		pt.showProcessDetails(item)
	}
}

func (pt *ProcessTab) Content() fyne.CanvasObject {
	cardTotal := NewMetricCard("TOTAL PROCESSOS", "Instâncias em execução", pt.lblTotal, "ATIVOS", ColorInfo, ColorInfoBg)
	cardSafe := NewMetricCard("SEGUROS", "Confirmados no banco local", pt.lblSafe, "✔ SEGUROS", ColorEmerald, ColorEmeraldAlpha)
	cardUncat := NewMetricCard("NÃO CATALOGADOS", "Sem assinatura nas bases", pt.lblUncataloged, "❔ INÉDITOS", ColorWarn, ColorWarnBg)
	cardThreats := NewMetricCard("AMEAÇAS", "Malware ativo detectado", pt.lblThreats, "🚨 AMEAÇAS", ColorDanger, ColorDangerBg)

	searchPanel := NewPanelCard("FILTRO E PESQUISA DE PROCESSOS", pt.btnScanNow, pt.searchEntry)

	header := container.NewVBox(
		pt.statusLabel,
		container.NewGridWithColumns(4,
			cardTotal,
			cardSafe,
			cardUncat,
			cardThreats,
		),
		searchPanel,
	)

	return container.NewBorder(header, nil, nil, nil, pt.listWidget)
}

func (pt *ProcessTab) UpdateStatus(status string) {
	fyne.Do(func() {
		pt.statusLabel.SetText(fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), status))
	})
}

func (pt *ProcessTab) refreshProcesses() {
	go func() {
		procs, err := process.ListRunningProcesses()
		if err != nil {
			return
		}

		var items []ProcessViewItem
		safeCount := 0
		uncatalogedCount := 0
		threatCount := 0

		for _, p := range procs {
			item := ProcessViewItem{
				PID:     p.PID,
				Name:    p.Name,
				ExePath: p.ExePath,
				SHA256:  p.SHA256,
				ErrStr:  p.Error,
			}

			if p.SHA256 != "" {
				if rec, exists, _ := pt.engine.Store().Get(p.SHA256); exists && rec != nil {
					item.Verdict = rec.Verdict
					item.Source = rec.Source
					item.Threat = rec.ThreatName
					if rec.Verdict == cache.VerdictSafe {
						safeCount++
					} else if rec.Verdict == cache.VerdictMalicious {
						threatCount++
					} else if rec.Verdict == cache.VerdictUnknown {
						uncatalogedCount++
					}
				} else {
					uncatalogedCount++
				}
			}

			items = append(items, item)
		}

		pt.mu.Lock()
		pt.allItems = items
		pt.mu.Unlock()

		fyne.Do(func() {
			pt.filterItems(pt.searchEntry.Text)
			pt.lblTotal.SetText(fmt.Sprintf("%d", len(items)))
			pt.lblSafe.SetText(fmt.Sprintf("%d", safeCount))
			pt.lblUncataloged.SetText(fmt.Sprintf("%d", uncatalogedCount))
			pt.lblThreats.SetText(fmt.Sprintf("%d", threatCount))
		})
	}()
}

func (pt *ProcessTab) filterItems(query string) {
	pt.mu.Lock()
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		pt.filtered = pt.allItems
	} else {
		var filtered []ProcessViewItem
		for _, it := range pt.allItems {
			if strings.Contains(strings.ToLower(it.Name), q) ||
				strings.Contains(fmt.Sprintf("%d", it.PID), q) ||
				strings.Contains(strings.ToLower(it.ExePath), q) ||
				strings.Contains(strings.ToLower(it.SHA256), q) {
				filtered = append(filtered, it)
			}
		}
		pt.filtered = filtered
	}
	pt.mu.Unlock()

	if pt.listWidget != nil {
		pt.listWidget.Refresh()
	}
}

func (pt *ProcessTab) showProcessDetails(item ProcessViewItem) {
	verdictStr := string(item.Verdict)
	if verdictStr == "" {
		verdictStr = "Desconhecido / Em fila"
	}

	content := fmt.Sprintf(
		"Nome: %s\nPID: %d\nCaminho: %s\n\nHash SHA-256:\n%s\n\nVeredito: %s\nOrigem: %s\nDetalhes da Ameaça: %s",
		item.Name, item.PID, item.ExePath, item.SHA256, verdictStr, item.Source, item.Threat,
	)

	dlg := dialog.NewInformation("Detalhes do Processo", content, pt.window)
	dlg.Resize(fyne.NewSize(580, 320))
	dlg.Show()
}
