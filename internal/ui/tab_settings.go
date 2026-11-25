package ui

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/notifier"
	"secure-go/internal/scheduler"
	"secure-go/internal/threatintel"
)

type SettingsTab struct {
	window       fyne.Window
	engine       *threatintel.Engine
	scheduler    *scheduler.Scheduler
	notifier     *notifier.Notifier

	vtKeyEntry   *widget.Entry
	btnSaveVT    *widget.Button
	intervalSel  *widget.Select
	lblVTStatus  *widget.Label
	lblMBStatus  *widget.Label
	lblDBStatus  *widget.Label
	btnTestAlert *widget.Button
}

func NewSettingsTab(win fyne.Window, engine *threatintel.Engine, sched *scheduler.Scheduler, notif *notifier.Notifier) *SettingsTab {
	st := &SettingsTab{
		window:    win,
		engine:    engine,
		scheduler: sched,
		notifier:  notif,
	}

	st.initUI()
	return st
}

func (st *SettingsTab) initUI() {
	// 1. Chave VirusTotal
	st.vtKeyEntry = widget.NewPasswordEntry()
	st.vtKeyEntry.SetPlaceHolder("Cole sua chave de API v3 do VirusTotal...")

	// Carrega chave salva se houver
	savedKey, _ := st.engine.Store().GetConfig("vt_api_key")
	if savedKey != "" {
		st.vtKeyEntry.SetText(savedKey)
		st.engine.SetVirusTotalKey(savedKey)
	}

	st.btnSaveVT = widget.NewButtonWithIcon("Salvar Chave", theme.DocumentSaveIcon(), func() {
		key := st.vtKeyEntry.Text
		if err := st.engine.Store().SetConfig("vt_api_key", key); err != nil {
			dialog.ShowError(fmt.Errorf("erro ao salvar chave: %v", err), st.window)
			return
		}
		st.engine.SetVirusTotalKey(key)
		st.updateStatusLabels()
		dialog.ShowInformation("Configuração Salva", "Chave do VirusTotal atualizada com sucesso!", st.window)
	})
	st.btnSaveVT.Importance = widget.HighImportance

	// 2. Intervalo do Agendador
	intervals := []string{"15 minutos", "30 minutos (Recomendado)", "60 minutos"}
	st.intervalSel = widget.NewSelect(intervals, func(selected string) {
		var dur time.Duration
		switch selected {
		case "15 minutos":
			dur = 15 * time.Minute
		case "60 minutos":
			dur = 60 * time.Minute
		default:
			dur = 30 * time.Minute
		}
		st.scheduler.SetInterval(dur)
		_ = st.engine.Store().SetConfig("scan_interval", selected)
	})

	savedInterval, _ := st.engine.Store().GetConfig("scan_interval")
	if savedInterval == "" {
		savedInterval = "30 minutos (Recomendado)"
	}
	st.intervalSel.SetSelected(savedInterval)

	// 3. Status dos Motores
	st.lblVTStatus = widget.NewLabel("")
	st.lblMBStatus = widget.NewLabel("✔ MalwareBazaar (Abuse.ch): Ativo (Ilimitado e Gratuito)")
	st.lblDBStatus = widget.NewLabel("✔ Banco Local SQLite: Ativo com cache persistente")
	st.updateStatusLabels()

	// 4. Teste de Notificação
	st.btnTestAlert = widget.NewButtonWithIcon("Testar Notificação na Área de Trabalho", theme.MailSendIcon(), func() {
		err := st.notifier.SendMalwareAlert("teste_simulado.exe", 9999, "Teste.Segurança.Alerta", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		if err != nil {
			dialog.ShowError(fmt.Errorf("falha ao disparar notificação: %v", err), st.window)
		} else {
			dialog.ShowInformation("Notificação Enviada", "Notificação de teste enviada para sua área de trabalho!", st.window)
		}
	})
}

func (st *SettingsTab) updateStatusLabels() {
	if st.engine.HasVirusTotalKey() {
		st.lblVTStatus.SetText("✔ VirusTotal v3: Configurado (Rate Limiter: máx. 4 requisições/min)")
	} else {
		st.lblVTStatus.SetText("⚠️ VirusTotal v3: Não configurado (Insira sua chave para ativar a consulta)")
	}
}

func (st *SettingsTab) Content() fyne.CanvasObject {
	cardVT := widget.NewCard("API VIRUSTOTAL v3", "Cota gratuita de 4 req/minuto com Rate Limiting integrado",
		container.NewVBox(
			widget.NewLabel("Hashes já analisados no banco local NÃO consomem sua cota diária do VirusTotal."),
			container.NewBorder(nil, nil, nil, st.btnSaveVT, st.vtKeyEntry),
		),
	)

	cardInterval := widget.NewCard("AGENDADOR DE MONITORAMENTO", "Frequência da varredura periódica em segundo plano",
		container.NewVBox(
			widget.NewLabel("Intervalo de verificação de processos ativos:"),
			st.intervalSel,
		),
	)

	cardStatus := widget.NewCard("INTEGRIDADE DOS MOTORES", "Status dos serviços de Threat Intelligence e Cache",
		container.NewVBox(
			st.lblMBStatus,
			st.lblVTStatus,
			st.lblDBStatus,
		),
	)

	cardTest := widget.NewCard("TESTE DE ALERTAS", "Validação de alertas sonoros e visuais (Windows Toast)",
		container.NewVBox(
			widget.NewLabel("Dispare uma notificação de teste para verificar se o Windows exibe os alertas:"),
			st.btnTestAlert,
		),
	)

	return container.NewVScroll(
		container.NewVBox(
			cardVT,
			cardInterval,
			cardStatus,
			cardTest,
		),
	)
}
