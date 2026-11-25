package ui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/quarantine"
	"secure-go/internal/threatintel"
)

// QuarantineTab gerencia a interface visual do cofre de quarentena criptografada.
type QuarantineTab struct {
	window       fyne.Window
	vault        *quarantine.Vault
	engine       *threatintel.Engine
	container    *fyne.Container
	listHolder   *fyne.Container
	lblTotal     *widget.Label
	lblSize      *widget.Label
	lblAlgorithm *widget.Label
}

// NewQuarantineTab instancia a aba de gestão da quarentena.
func NewQuarantineTab(window fyne.Window, vault *quarantine.Vault, engine *threatintel.Engine) *QuarantineTab {
	qt := &QuarantineTab{
		window:       window,
		vault:        vault,
		engine:       engine,
		lblTotal:     widget.NewLabel("0"),
		lblSize:      widget.NewLabel("0 KB"),
		lblAlgorithm: widget.NewLabel("AES-256-GCM"),
		listHolder:   container.NewVBox(),
	}

	qt.buildUI()
	qt.Reload()
	return qt
}

func (qt *QuarantineTab) buildUI() {
	headerTitle := canvas.NewText("Cofre de Quarentena Criptografada (Vault)", ColorTextPrimary)
	headerTitle.TextSize = 16
	headerTitle.TextStyle = fyne.TextStyle{Bold: true}

	headerSub := canvas.NewText(
		"Arquivos isolados e criptografados com chave AES-256-GCM. Nenhum binário no cofre pode ser executado pelo Windows.",
		ColorTextSecondary,
	)
	headerSub.TextSize = 12

	btnRefresh := widget.NewButtonWithIcon("Atualizar Cofre", IconFASearch, func() {
		qt.Reload()
	})

	topHeader := container.NewBorder(nil, nil,
		container.NewVBox(headerTitle, headerSub),
		btnRefresh,
	)

	// Cards de Métricas
	cardTotal := NewMetricCard("ARQUIVOS ISOLADOS", "Retidos com segurança", qt.lblTotal, "OK", ColorDanger, ColorDangerAlpha)
	cardSize := NewMetricCard("VOLUME DO COFRE", "Armazenamento ocupado", qt.lblSize, "AES", ColorScoreGreen, ColorScoreGreenAlpha)
	cardAlgo := NewMetricCard("CRIPTOGRAFIA", "Padrão militar autenticado", qt.lblAlgorithm, "ATIVO", ColorCyan, ColorCyanAlpha)

	metricsGrid := container.NewGridWithColumns(3, cardTotal, cardSize, cardAlgo)

	// Painel de Arquivos Retidos
	listScroll := container.NewVScroll(qt.listHolder)
	listScroll.SetMinSize(fyne.NewSize(600, 360))

	panel := NewPanelCard("ARQUIVOS RETIDOS NA QUARENTENA", nil, listScroll)

	qt.container = container.NewVBox(
		topHeader,
		canvas.NewLine(ColorCardBorder),
		metricsGrid,
		panel,
	)
}

// Reload atualiza a lista de itens retidos no cofre.
func (qt *QuarantineTab) Reload() {
	if qt.vault == nil {
		return
	}

	items := qt.vault.List()
	qt.lblTotal.SetText(fmt.Sprintf("%d", len(items)))

	var totalBytes int64
	for _, it := range items {
		totalBytes += it.FileSize
	}

	if totalBytes < 1024 {
		qt.lblSize.SetText(fmt.Sprintf("%d B", totalBytes))
	} else if totalBytes < 1024*1024 {
		qt.lblSize.SetText(fmt.Sprintf("%.1f KB", float64(totalBytes)/1024))
	} else {
		qt.lblSize.SetText(fmt.Sprintf("%.2f MB", float64(totalBytes)/(1024*1024)))
	}

	qt.listHolder.Objects = nil

	if len(items) == 0 {
		emptyIcon := canvas.NewImageFromResource(IconFACheck)
		emptyIcon.SetMinSize(fyne.NewSize(32, 32))
		emptyText := canvas.NewText("✔ Nenhum arquivo na quarentena. O seu computador está limpo e seguro.", ColorScoreGreen)
		emptyText.TextSize = 13
		emptyBox := container.NewCenter(container.NewHBox(emptyIcon, emptyText))
		qt.listHolder.Add(container.NewPadded(emptyBox))
		qt.listHolder.Refresh()
		return
	}

	for _, rec := range items {
		currentRec := rec

		icon := canvas.NewImageFromResource(IconFAVault)
		icon.SetMinSize(fyne.NewSize(24, 24))

		nameLabel := canvas.NewText(currentRec.FileName, ColorTextPrimary)
		nameLabel.TextSize = 13
		nameLabel.TextStyle = fyne.TextStyle{Bold: true}

		threatPill := NewPillBadge(currentRec.ThreatName, ColorDanger, ColorDangerAlpha)

		dateLabel := canvas.NewText(
			fmt.Sprintf("Isolado em %s | Caminho original: %s", currentRec.QuarantinedAt.Format("02/01/2006 15:04"), currentRec.OriginalPath),
			ColorTextMuted,
		)
		dateLabel.TextSize = 11

		infoBox := container.NewVBox(
			container.NewHBox(nameLabel, threatPill),
			dateLabel,
		)

		btnRestore := widget.NewButtonWithIcon("Restaurar", IconFACheck, func() {
			dialog.ShowConfirm(
				"Restaurar Arquivo",
				fmt.Sprintf("Deseja realmente restaurar '%s' para seu local original?\n\nCaminho: %s", currentRec.FileName, currentRec.OriginalPath),
				func(confirm bool) {
					if !confirm {
						return
					}
					_, err := qt.vault.RestoreFile(currentRec.ID)
					if err != nil {
						dialog.ShowError(fmt.Errorf("erro ao restaurar: %w", err), qt.window)
						return
					}
					if qt.engine.Telemetry() != nil {
						qt.engine.Telemetry().Log(
							threatintel.LogLevelInfo,
							"Quarentena",
							fmt.Sprintf("Arquivo %s restaurado do cofre pelo usuário.", currentRec.FileName),
						)
					}
					dialog.ShowInformation("Restaurado com Sucesso", fmt.Sprintf("Arquivo '%s' restaurado com sucesso!", currentRec.FileName), qt.window)
					qt.Reload()
				},
				qt.window,
			)
		})
		btnRestore.Importance = widget.LowImportance

		btnDelete := widget.NewButtonWithIcon("Excluir", IconFABan, func() {
			dialog.ShowConfirm(
				"Excluir Permanentemente",
				fmt.Sprintf("Deseja apagar definitivamente o arquivo '%s' do cofre? Esta ação não pode ser desfeita.", currentRec.FileName),
				func(confirm bool) {
					if !confirm {
						return
					}
					err := qt.vault.DeleteFile(currentRec.ID)
					if err != nil {
						dialog.ShowError(fmt.Errorf("erro ao excluir: %w", err), qt.window)
						return
					}
					dialog.ShowInformation("Excluído com Sucesso", fmt.Sprintf("Arquivo '%s' apagado definitivamente.", currentRec.FileName), qt.window)
					qt.Reload()
				},
				qt.window,
			)
		})
		btnDelete.Importance = widget.DangerImportance

		rowCardBg := canvas.NewRectangle(ColorCardBg)
		rowCardBg.CornerRadius = 8
		rowCardBg.StrokeColor = ColorCardBorder
		rowCardBg.StrokeWidth = 0.8

		rowContent := container.NewBorder(
			nil, nil,
			container.NewHBox(icon, infoBox),
			container.NewHBox(btnRestore, btnDelete),
		)

		rowStack := container.NewStack(rowCardBg, container.NewPadded(rowContent))
		qt.listHolder.Add(rowStack)
	}

	qt.listHolder.Refresh()
}

// Content retorna a árvore de CanvasObjects da aba.
func (qt *QuarantineTab) Content() fyne.CanvasObject {
	return qt.container
}
