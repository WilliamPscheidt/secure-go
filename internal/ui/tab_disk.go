package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/scanner"
	"secure-go/internal/threatintel"
)

type DiskTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	diskScanner  *scanner.DiskScanner

	pathEntry    *widget.Entry
	btnBrowse    *widget.Button
	chkOnlyExec  *widget.Check
	btnStart     *widget.Button
	btnCancel    *widget.Button
	progressBar  *widget.ProgressBar
	statusLabel  *widget.Label

	lblSafe      *widget.Label
	lblMalicious *widget.Label
	lblTotal     *widget.Label

	results      []*scanner.FileScanResult
	resultsList  *widget.List
	mu           sync.RWMutex
}

func NewDiskTab(win fyne.Window, engine *threatintel.Engine) *DiskTab {
	dt := &DiskTab{
		window:      win,
		engine:      engine,
		diskScanner: scanner.NewDiskScanner(engine, 4),
	}

	dt.initUI()
	return dt
}

func (dt *DiskTab) initUI() {
	defaultDir, _ := os.UserHomeDir()
	if defaultDir == "" {
		defaultDir = "C:\\"
	}

	dt.pathEntry = widget.NewEntry()
	dt.pathEntry.SetText(defaultDir)

	dt.btnBrowse = widget.NewButtonWithIcon("Navegar...", theme.FolderOpenIcon(), func() {
		dlg := dialog.NewFolderOpen(func(lu fyne.ListableURI, err error) {
			if err == nil && lu != nil {
				dt.pathEntry.SetText(lu.Path())
			}
		}, dt.window)
		dlg.Resize(fyne.NewSize(600, 400))
		dlg.Show()
	})

	dt.chkOnlyExec = widget.NewCheck("Apenas executáveis e scripts (.exe, .dll, .bat, .sys, etc.)", nil)
	dt.chkOnlyExec.SetChecked(true)

	dt.progressBar = widget.NewProgressBar()
	dt.progressBar.SetValue(0)

	dt.statusLabel = widget.NewLabel("Selecione um diretório ou unidade de disco para iniciar a verificação.")
	dt.statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	dt.lblTotal = widget.NewLabelWithStyle("Arquivos: 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblSafe = widget.NewLabelWithStyle("Seguros (Limpos): 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblMalicious = widget.NewLabelWithStyle("Maliciosos: 0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	dt.btnStart = widget.NewButtonWithIcon("Iniciar Varredura", theme.MediaPlayIcon(), dt.startScan)
	dt.btnStart.Importance = widget.HighImportance

	dt.btnCancel = widget.NewButtonWithIcon("Cancelar", theme.MediaStopIcon(), func() {
		dt.diskScanner.Cancel()
		dt.statusLabel.SetText("Varredura cancelada pelo usuário.")
		dt.btnStart.Enable()
		dt.btnCancel.Disable()
	})
	dt.btnCancel.Disable()

	dt.resultsList = widget.NewList(
		func() int {
			dt.mu.RLock()
			defer dt.mu.RUnlock()
			return len(dt.results)
		},
		func() fyne.CanvasObject {
			nameLabel := widget.NewLabelWithStyle("Filename.exe", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			detailLabel := widget.NewLabel("Caminho do arquivo...")
			badge := widget.NewLabel("[SEGURO]")
			badge.TextStyle = fyne.TextStyle{Bold: true}

			return container.NewBorder(nil, nil, nil, badge,
				container.NewVBox(nameLabel, detailLabel),
			)
		},
		func(id int, obj fyne.CanvasObject) {
			dt.mu.RLock()
			if id >= len(dt.results) {
				dt.mu.RUnlock()
				return
			}
			res := dt.results[id]
			dt.mu.RUnlock()

			box := obj.(*fyne.Container)
			badge := box.Objects[1].(*widget.Label)
			vbox := box.Objects[0].(*fyne.Container)
			nameLbl := vbox.Objects[0].(*widget.Label)
			detailLbl := vbox.Objects[1].(*widget.Label)

			nameLbl.SetText(res.FileName)
			detailLbl.SetText(fmt.Sprintf("%s | Fonte: %s", res.FilePath, res.Source))

			switch res.Verdict {
			case cache.VerdictSafe:
				badge.SetText("✔ SEGURO")
			case cache.VerdictMalicious:
				badge.SetText("🚨 MALICIOSO!")
			case cache.VerdictSuspicious:
				badge.SetText("⚠️ SUSPEITO")
			default:
				badge.SetText("ℹ DESCONHECIDO")
			}
		},
	)

	dt.resultsList.OnSelected = func(id int) {
		dt.resultsList.Unselect(id)
		dt.mu.RLock()
		if id >= len(dt.results) {
			dt.mu.RUnlock()
			return
		}
		res := dt.results[id]
		dt.mu.RUnlock()

		content := fmt.Sprintf(
			"Arquivo: %s\nTamanho: %d bytes\nCaminho: %s\n\nHash SHA-256:\n%s\n\nVeredito: %s\nOrigem: %s\nDetalhes: %s",
			res.FileName, res.FileSize, res.FilePath, res.SHA256, res.Verdict, res.Source, res.Details,
		)
		dlg := dialog.NewInformation("Detalhes da Análise", content, dt.window)
		dlg.Resize(fyne.NewSize(580, 320))
		dlg.Show()
	}
}

func (dt *DiskTab) startScan() {
	targetPath := dt.pathEntry.Text
	if targetPath == "" {
		dialog.ShowError(fmt.Errorf("informe o caminho do diretório para escanear"), dt.window)
		return
	}

	dt.mu.Lock()
	dt.results = nil
	dt.mu.Unlock()
	dt.resultsList.Refresh()

	dt.btnStart.Disable()
	dt.btnCancel.Enable()
	dt.progressBar.SetValue(0)
	dt.statusLabel.SetText("Indexando arquivos para varredura...")

	safeCount := 0
	malCount := 0

	dt.diskScanner.SetCallbacks(
		func(res *scanner.FileScanResult) {
			dt.mu.Lock()
			dt.results = append(dt.results, res)
			if res.Verdict == cache.VerdictSafe {
				safeCount++
			} else if res.Verdict == cache.VerdictMalicious {
				malCount++
			}
			currTotal := len(dt.results)
			dt.mu.Unlock()

			// Atualiza UI periodicamente
			dt.lblSafe.SetText(fmt.Sprintf("Seguros (Limpos): %d", safeCount))
			dt.lblMalicious.SetText(fmt.Sprintf("Maliciosos: %d", malCount))
			dt.lblTotal.SetText(fmt.Sprintf("Arquivos: %d", currTotal))
			dt.resultsList.Refresh()
		},
		func(scanned, total int, currentFile string) {
			if total > 0 {
				dt.progressBar.SetValue(float64(scanned) / float64(total))
				dt.statusLabel.SetText(fmt.Sprintf("[%d / %d] Analisando: %s", scanned, total, currentFile))
			}
		},
		func(summary *scanner.DiskScanSummary) {
			dt.progressBar.SetValue(1.0)
			dt.statusLabel.SetText(fmt.Sprintf("Varredura Concluída em %v: %d escaneados (%d seguros, %d maliciosos)",
				summary.Duration.Round(time.Millisecond), summary.FilesScanned, summary.SafeFiles, summary.MaliciousFiles))
			dt.btnStart.Enable()
			dt.btnCancel.Disable()
		},
	)

	onlyExec := dt.chkOnlyExec.Checked
	go func() {
		_, err := dt.diskScanner.ScanDirectory(targetPath, onlyExec)
		if err != nil {
			dt.statusLabel.SetText(fmt.Sprintf("Erro na varredura: %v", err))
			dt.btnStart.Enable()
			dt.btnCancel.Disable()
		}
	}()
}

func (dt *DiskTab) Content() fyne.CanvasObject {
	pathBox := container.NewBorder(nil, nil, nil, dt.btnBrowse, dt.pathEntry)

	controlsBox := container.NewVBox(
		pathBox,
		container.NewHBox(dt.chkOnlyExec, dt.btnStart, dt.btnCancel),
		widget.NewSeparator(),
		container.NewGridWithColumns(3,
			dt.lblTotal,
			dt.lblSafe,
			dt.lblMalicious,
		),
		dt.progressBar,
		dt.statusLabel,
		widget.NewSeparator(),
	)

	return container.NewBorder(controlsBox, nil, nil, nil, dt.resultsList)
}
