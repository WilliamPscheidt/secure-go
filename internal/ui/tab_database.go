package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/report"
	"secure-go/internal/threatintel"
)

type DatabaseTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	records      []*cache.HashRecord
	filtered     []*cache.HashRecord
	listWidget   *widget.List
	searchEntry  *widget.Entry
	lblTotal       *widget.Label
	lblSafe        *widget.Label
	lblUncataloged *widget.Label
	lblMalicious   *widget.Label
	mu           sync.RWMutex
}

func NewDatabaseTab(win fyne.Window, engine *threatintel.Engine) *DatabaseTab {
	dt := &DatabaseTab{
		window: win,
		engine: engine,
	}

	dt.initUI()
	dt.Refresh()
	return dt
}

func (dt *DatabaseTab) initUI() {
	dt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblSafe = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblUncataloged = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblMalicious = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	dt.searchEntry = widget.NewEntry()
	dt.searchEntry.SetPlaceHolder("🔍 Buscar por hash SHA-256, executável ou veredito...")
	dt.searchEntry.OnChanged = func(q string) {
		dt.filterItems(q)
	}

	dt.listWidget = widget.NewList(
		func() int {
			dt.mu.RLock()
			defer dt.mu.RUnlock()
			return len(dt.filtered)
		},
		func() fyne.CanvasObject {
			nameLabel := widget.NewLabelWithStyle("Filename.exe", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			hashLabel := widget.NewLabel("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			badge := widget.NewLabel("[SEGURO]")
			badge.TextStyle = fyne.TextStyle{Bold: true}

			return container.NewBorder(nil, nil, nil, badge,
				container.NewVBox(nameLabel, hashLabel),
			)
		},
		func(id int, obj fyne.CanvasObject) {
			dt.mu.RLock()
			if id >= len(dt.filtered) {
				dt.mu.RUnlock()
				return
			}
			rec := dt.filtered[id]
			dt.mu.RUnlock()

			box := obj.(*fyne.Container)
			badge := box.Objects[1].(*widget.Label)
			vbox := box.Objects[0].(*fyne.Container)
			nameLbl := vbox.Objects[0].(*widget.Label)
			hashLbl := vbox.Objects[1].(*widget.Label)

			displayName := rec.FileName
			if displayName == "" {
				displayName = "Executável Desconhecido"
			}
			nameLbl.SetText(fmt.Sprintf("%s  (Fonte: %s)", displayName, rec.Source))
			hashLbl.SetText(fmt.Sprintf("SHA-256: %s", rec.SHA256))

			switch rec.Verdict {
			case cache.VerdictSafe:
				badge.SetText("✔ SEGURO")
			case cache.VerdictMalicious:
				badge.SetText("🚨 MALICIOSO!")
			case cache.VerdictSuspicious:
				badge.SetText("⚠️ SUSPEITO")
			case cache.VerdictUnknown:
				badge.SetText("❔ NÃO CATALOGADO (2/2)")
			case cache.VerdictPending:
				badge.SetText("⏳ PENDENTE DUPLA (1/2)")
			default:
				badge.SetText("❔ NÃO CATALOGADO")
			}
		},
	)

	dt.listWidget.OnSelected = func(id int) {
		dt.listWidget.Unselect(id)
		dt.mu.RLock()
		if id >= len(dt.filtered) {
			dt.mu.RUnlock()
			return
		}
		rec := dt.filtered[id]
		dt.mu.RUnlock()

		dt.showRecordActionsDialog(rec)
	}
}

func (dt *DatabaseTab) showRecordActionsDialog(rec *cache.HashRecord) {
	mbStatus := "Pendente"
	if rec.MBChecked {
		mbStatus = "Verificado (Sem assinatura de ameaça)"
	}
	vtStatus := "Pendente"
	if rec.VTChecked {
		vtStatus = "Verificado (70+ motores antivírus)"
	}

	details := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Arquivo: %s", rec.FileName), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("Caminho: %s", rec.FilePath)),
		widget.NewLabel(fmt.Sprintf("Hash SHA-256:\n%s", rec.SHA256)),
		widget.NewLabel(fmt.Sprintf("Veredito Atual: %s  |  Origem: %s", rec.Verdict, rec.Source)),
		widget.NewLabel(fmt.Sprintf("Detecções: %d/%d  |  Ameaça: %s", rec.Positives, rec.TotalEngines, rec.ThreatName)),
		widget.NewLabel(fmt.Sprintf("Status Bases: MB: %s | VT: %s", mbStatus, vtStatus)),
		widget.NewLabel(fmt.Sprintf("Data: %s", rec.CheckedAt.Format("02/01/2006 15:04:05"))),
	)

	var d dialog.Dialog

	btnCopy := widget.NewButton("Copiar Hash", func() {
		dt.window.Clipboard().SetContent(rec.SHA256)
		dialog.ShowInformation("Copiado", "Hash SHA-256 copiado para a área de transferência!", dt.window)
	})

	btnWhitelist := widget.NewButton("✔ Mover para Whitelist (Seguro)", func() {
		_ = dt.engine.WhitelistHash(rec.SHA256, rec.FileName, rec.FilePath)
		if d != nil {
			d.Hide()
		}
		dt.Refresh()
		dialog.ShowInformation("Atualizado", "Hash classificado como Seguro na Whitelist!", dt.window)
	})
	btnWhitelist.Importance = widget.HighImportance

	btnBlacklist := widget.NewButton("🚨 Mover para Blacklist (Ameaça)", func() {
		_ = dt.engine.BlacklistHash(rec.SHA256, rec.FileName, rec.FilePath, "Bloqueio manual pelo usuário")
		if d != nil {
			d.Hide()
		}
		dt.Refresh()
		dialog.ShowInformation("Atualizado", "Hash classificado como Ameaça na Blacklist!", dt.window)
	})
	btnBlacklist.Importance = widget.DangerImportance

	btnDelete := widget.NewButton("Excluir do Banco", func() {
		_ = dt.engine.DeleteHash(rec.SHA256)
		if d != nil {
			d.Hide()
		}
		dt.Refresh()
		dialog.ShowInformation("Removido", "Registro removido com sucesso do cache local.", dt.window)
	})

	actionsBox := container.NewVBox(
		details,
		container.NewGridWithColumns(2, btnWhitelist, btnBlacklist),
		container.NewGridWithColumns(2, btnCopy, btnDelete),
	)

	d = dialog.NewCustom("Gerenciar Hash & Inteligência (1-Clique)", "Fechar", actionsBox, dt.window)
	d.Resize(fyne.NewSize(580, 360))
	d.Show()
}

func (dt *DatabaseTab) exportCSV() {
	records, err := dt.engine.Store().ListAll(-1, 0)
	if err != nil || len(records) == 0 {
		dialog.ShowInformation("Aviso", "Não há registros no banco para exportar.", dt.window)
		return
	}

	destDir := os.Getenv("USERPROFILE")
	if destDir != "" {
		downloads := filepath.Join(destDir, "Downloads")
		if _, statErr := os.Stat(downloads); statErr == nil {
			destDir = downloads
		}
	}
	if destDir == "" {
		destDir = "."
	}

	fileName := fmt.Sprintf("securego_auditoria_%s.csv", time.Now().Format("20060102_150405"))
	outPath := filepath.Join(destDir, fileName)

	if err := report.ExportToCSV(records, outPath); err != nil {
		dialog.ShowError(fmt.Errorf("falha ao exportar CSV: %w", err), dt.window)
		return
	}

	dialog.ShowInformation("Exportação Concluída", fmt.Sprintf("Relatório CSV exportado com sucesso para:\n%s", outPath), dt.window)
}

func (dt *DatabaseTab) exportJSON() {
	records, err := dt.engine.Store().ListAll(-1, 0)
	if err != nil || len(records) == 0 {
		dialog.ShowInformation("Aviso", "Não há registros no banco para exportar.", dt.window)
		return
	}

	destDir := os.Getenv("USERPROFILE")
	if destDir != "" {
		downloads := filepath.Join(destDir, "Downloads")
		if _, statErr := os.Stat(downloads); statErr == nil {
			destDir = downloads
		}
	}
	if destDir == "" {
		destDir = "."
	}

	fileName := fmt.Sprintf("securego_auditoria_%s.json", time.Now().Format("20060102_150405"))
	outPath := filepath.Join(destDir, fileName)

	if err := report.ExportToJSON(records, outPath); err != nil {
		dialog.ShowError(fmt.Errorf("falha ao exportar JSON: %w", err), dt.window)
		return
	}

	dialog.ShowInformation("Exportação Concluída", fmt.Sprintf("Relatório JSON exportado com sucesso para:\n%s", outPath), dt.window)
}

func (dt *DatabaseTab) Refresh() {
	go func() {
		stats, err := dt.engine.Store().GetStats()
		records, _ := dt.engine.Store().ListAll(1000, 0)

		dt.mu.Lock()
		dt.records = records
		dt.mu.Unlock()

		fyne.Do(func() {
			if err == nil {
				dt.lblTotal.SetText(fmt.Sprintf("%d", stats.Total))
				dt.lblSafe.SetText(fmt.Sprintf("%d", stats.Safe))
				dt.lblUncataloged.SetText(fmt.Sprintf("%d", stats.Unknown))
				dt.lblMalicious.SetText(fmt.Sprintf("%d", stats.Malicious))
			}
			dt.filterItems(dt.searchEntry.Text)
		})
	}()
}

func (dt *DatabaseTab) filterItems(query string) {
	dt.mu.Lock()
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		dt.filtered = dt.records
	} else {
		var filtered []*cache.HashRecord
		for _, r := range dt.records {
			if strings.Contains(strings.ToLower(r.SHA256), q) ||
				strings.Contains(strings.ToLower(r.FileName), q) ||
				strings.Contains(strings.ToLower(string(r.Verdict)), q) ||
				strings.Contains(strings.ToLower(r.Source), q) {
				filtered = append(filtered, r)
			}
		}
		dt.filtered = filtered
	}
	dt.mu.Unlock()

	if dt.listWidget != nil {
		dt.listWidget.Refresh()
	}
}

func (dt *DatabaseTab) showAddSafeDialog() {
	hashEntry := widget.NewEntry()
	hashEntry.SetPlaceHolder("Cole aqui o hash SHA-256 completo (64 caracteres)...")

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("Ex: meu_software_interno.exe")

	form := dialog.NewForm("Adicionar Hash Confiável (Whitelist)", "Adicionar como Seguro", "Cancelar", []*widget.FormItem{
		widget.NewFormItem("Hash SHA-256", hashEntry),
		widget.NewFormItem("Nome / Descrição", nameEntry),
	}, func(confirmed bool) {
		if !confirmed {
			return
		}
		sha := strings.ToLower(strings.TrimSpace(hashEntry.Text))
		name := strings.TrimSpace(nameEntry.Text)
		if len(sha) != 64 {
			dialog.ShowError(fmt.Errorf("o hash SHA-256 precisa ter exatamente 64 caracteres hexadecimais"), dt.window)
			return
		}

		err := dt.engine.Store().Save(&cache.HashRecord{
			SHA256:       sha,
			FileName:     name,
			Verdict:      cache.VerdictSafe,
			Source:       "Whitelist Manual (Usuário)",
			CheckedAt:    time.Now(),
			TotalEngines: 1,
		})
		if err != nil {
			dialog.ShowError(fmt.Errorf("erro ao salvar no banco: %v", err), dt.window)
			return
		}

		dialog.ShowInformation("Sucesso", "Hash adicionado com sucesso como Seguro!", dt.window)
		dt.Refresh()
	}, dt.window)

	form.Resize(fyne.NewSize(540, 240))
	form.Show()
}

func (dt *DatabaseTab) Content() fyne.CanvasObject {
	cardTotal := NewMetricCard("CADASTRADOS", "Total no banco SQLite", dt.lblTotal, "TOTAL", ColorBluePrimary, ColorBlueAlpha)
	cardSafe := NewMetricCard("SEGUROS", "Whitelist e confirmados", dt.lblSafe, "✔ SEGUROS", ColorCyan, ColorCyanAlpha)
	cardUncat := NewMetricCard("NÃO CATALOGADOS", "Sem registro nas bases", dt.lblUncataloged, "❔ INÉDITOS", ColorWarn, ColorWarnBg)
	cardMal := NewMetricCard("MALICIOSOS", "Ameaças catalogadas", dt.lblMalicious, "🚨 AMEAÇAS", ColorDanger, ColorDangerBg)

	btnAdd := widget.NewButtonWithIcon("Adicionar Whitelist", theme.ContentAddIcon(), dt.showAddSafeDialog)
	btnAdd.Importance = widget.HighImportance

	btnExportCSV := widget.NewButtonWithIcon("Exportar CSV", IconFAFileCsv, dt.exportCSV)
	btnExportJSON := widget.NewButtonWithIcon("Exportar JSON", IconFADatabase, dt.exportJSON)
	btnRefresh := widget.NewButtonWithIcon("Recarregar", theme.ViewRefreshIcon(), dt.Refresh)

	toolbarPanel := NewPanelCard("PESQUISA E GESTÃO DO BANCO DE HASHES",
		container.NewHBox(btnAdd, btnExportCSV, btnExportJSON, btnRefresh),
		dt.searchEntry,
	)

	header := container.NewVBox(
		container.NewGridWithColumns(4,
			cardTotal,
			cardSafe,
			cardUncat,
			cardMal,
		),
		toolbarPanel,
	)

	return container.NewBorder(header, nil, nil, nil, dt.listWidget)
}
