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
	"secure-go/internal/threatintel"
)

type DatabaseTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	records      []*cache.HashRecord
	filtered     []*cache.HashRecord
	listWidget   *widget.List
	searchEntry  *widget.Entry
	lblTotal     *widget.Label
	lblSafe      *widget.Label
	lblMalicious *widget.Label
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
	dt.lblTotal = widget.NewLabelWithStyle("Hashes Cadastrados: 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblSafe = widget.NewLabelWithStyle("Hashes Seguros: 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblMalicious = widget.NewLabelWithStyle("Ameaças Confirmadas: 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	dt.searchEntry = widget.NewEntry()
	dt.searchEntry.SetPlaceHolder("Buscar por hash SHA-256, executável ou veredito...")
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
			default:
				badge.SetText("ℹ OUTRO")
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

		content := fmt.Sprintf(
			"Arquivo: %s\nCaminho: %s\n\nHash SHA-256:\n%s\n\nVeredito: %s\nOrigem: %s\nAmeaça: %s\nDetecções: %d/%d\nData da Verificação: %s",
			rec.FileName, rec.FilePath, rec.SHA256, rec.Verdict, rec.Source, rec.ThreatName, rec.Positives, rec.TotalEngines,
			rec.CheckedAt.Format("02/01/2006 15:04:05"),
		)
		dlg := dialog.NewInformation("Registro do Banco Local", content, dt.window)
		dlg.Resize(fyne.NewSize(580, 320))
		dlg.Show()
	}
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
				dt.lblTotal.SetText(fmt.Sprintf("Hashes Cadastrados: %d", stats.Total))
				dt.lblSafe.SetText(fmt.Sprintf("Hashes Seguros: %d", stats.Safe))
				dt.lblMalicious.SetText(fmt.Sprintf("Ameaças Confirmadas: %d", stats.Malicious))
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
	header := container.NewVBox(
		container.NewGridWithColumns(3,
			dt.lblTotal,
			dt.lblSafe,
			dt.lblMalicious,
		),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, container.NewHBox(
			widget.NewButtonWithIcon("Adicionar Confiável", theme.ContentAddIcon(), dt.showAddSafeDialog),
			widget.NewButtonWithIcon("Recarregar", theme.ViewRefreshIcon(), dt.Refresh),
		), dt.searchEntry),
		widget.NewSeparator(),
	)

	return container.NewBorder(header, nil, nil, nil, dt.listWidget)
}
