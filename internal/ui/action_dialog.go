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

// ShowThreatActionDialog exibe um diálogo interativo para o usuário decidir o destino da ameaça:
// "Mover para Quarentena" (criptografa e isola) ou "Adicionar à Whitelist" (marca como seguro).
func ShowThreatActionDialog(
	parent fyne.Window,
	vault *quarantine.Vault,
	engine *threatintel.Engine,
	fileName, filePath, threatName, sha256 string,
	pid uint32,
	onDone func(),
) {
	if parent == nil {
		return
	}

	headerIcon := canvas.NewImageFromResource(IconFABug)
	headerIcon.SetMinSize(fyne.NewSize(32, 32))

	titleText := canvas.NewText("🚨 AMEAÇA DETECTADA NO COMPUTADOR", ColorDanger)
	titleText.TextSize = 15
	titleText.TextStyle = fyne.TextStyle{Bold: true}

	headerBox := container.NewHBox(headerIcon, titleText)

	threatBadge := NewPillBadge(threatName, ColorDanger, ColorDangerAlpha)

	infoFile := widget.NewLabel(fmt.Sprintf("Arquivo: %s", fileName))
	infoFile.TextStyle = fyne.TextStyle{Bold: true}

	infoPath := widget.NewLabel(fmt.Sprintf("Caminho: %s", filePath))
	infoPath.Wrapping = fyne.TextWrapBreak

	var infoPID *widget.Label
	if pid > 0 {
		infoPID = widget.NewLabel(fmt.Sprintf("Processo Ativo (PID): %d", pid))
	} else {
		infoPID = widget.NewLabel("Origem: Arquivo em disco")
	}

	shortHash := sha256
	if len(shortHash) > 32 {
		shortHash = shortHash[:32] + "..."
	}
	infoHash := widget.NewLabel(fmt.Sprintf("SHA-256: %s", shortHash))

	descText := canvas.NewText(
		"O SecureGo identificou uma ameaça de segurança neste arquivo.\nEscolha a ação desejada antes que o programa cause danos:",
		ColorTextSecondary,
	)
	descText.TextSize = 12

	detailsBox := container.NewVBox(
		headerBox,
		canvas.NewLine(ColorCardBorder),
		threatBadge,
		infoFile,
		infoPath,
		infoPID,
		infoHash,
		canvas.NewLine(ColorCardBorder),
		descText,
	)

	var d dialog.Dialog

	btnQuarantine := widget.NewButtonWithIcon("Mover para Quarentena", IconFAVault, func() {
		if d != nil {
			d.Hide()
		}

		if vault == nil {
			dialog.ShowError(fmt.Errorf("módulo de quarentena indisponível"), parent)
			return
		}

		rec, err := vault.QuarantineFile(filePath, threatName, sha256, pid)
		if err != nil {
			dialog.ShowError(fmt.Errorf("falha ao mover para quarentena: %w", err), parent)
			return
		}

		if engine.Telemetry() != nil {
			engine.Telemetry().Log(
				threatintel.LogLevelSafe,
				"Quarentena",
				fmt.Sprintf("✔ AMEAÇA NEUTRALIZADA: %s isolado no cofre criptografado (ID: %s)", fileName, rec.ID),
			)
		}

		dialog.ShowInformation(
			"Arquivo em Quarentena",
			fmt.Sprintf("O arquivo %s foi criptografado com AES-256-GCM e isolado no cofre com sucesso!\n\nEle não pode mais ser executado pelo Windows e pode ser restaurado a qualquer momento na aba Quarentena.", fileName),
			parent,
		)

		if onDone != nil {
			onDone()
		}
	})
	btnQuarantine.Importance = widget.DangerImportance

	btnWhitelist := widget.NewButtonWithIcon("Adicionar à Whitelist", IconFACheck, func() {
		if d != nil {
			d.Hide()
		}

		err := engine.WhitelistHash(sha256, fileName, filePath)
		if err != nil {
			dialog.ShowError(fmt.Errorf("falha ao adicionar à Whitelist: %w", err), parent)
			return
		}

		if engine.Telemetry() != nil {
			engine.Telemetry().Log(
				threatintel.LogLevelSafe,
				"Whitelist",
				fmt.Sprintf("✔ HASH APROVADO: %s (%s) adicionado à Lista Branca pelo usuário", fileName, shortHash),
			)
		}

		dialog.ShowInformation(
			"Adicionado à Whitelist",
			fmt.Sprintf("O arquivo %s foi marcado como Seguro (SAFE) na sua base local e não será mais sinalizado.", fileName),
			parent,
		)

		if onDone != nil {
			onDone()
		}
	})
	btnWhitelist.Importance = widget.SuccessImportance

	btnCancel := widget.NewButton("Ignorar", func() {
		if d != nil {
			d.Hide()
		}
	})

	buttonsBox := container.NewHBox(btnQuarantine, btnWhitelist, btnCancel)
	content := container.NewVBox(detailsBox, container.NewPadded(buttonsBox))

	d = dialog.NewCustomWithoutButtons("Decisão de Segurança - Ameaça Detectada", content, parent)
	d.Resize(fyne.NewSize(520, 360))
	d.Show()
}
