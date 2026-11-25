package ui

import (
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
	"secure-go/internal/process"
	"secure-go/internal/scheduler"
	"secure-go/internal/threatintel"
)

type DashboardTab struct {
	window    fyne.Window
	engine    *threatintel.Engine
	scheduler *scheduler.Scheduler
	notifier  *notifier.Notifier

	// Métricas principais
	lblTotal       *widget.Label
	lblSafe        *widget.Label
	lblUncataloged *widget.Label
	lblThreats     *widget.Label

	// Telemetria MalwareBazaar
	lblMBStatus   *widget.Label
	lblMBFile     *widget.Label
	barMBActivity *widget.ProgressBarInfinite

	// Telemetria VirusTotal
	lblVTStatus   *widget.Label
	lblVTFile     *widget.Label
	barVTProgress *widget.ProgressBar
	lblVTTimer    *widget.Label

	// Terminal de Eventos ao Vivo
	logEntries []threatintel.LogItem
	logList    *widget.List
	mu         sync.RWMutex
}

func NewDashboardTab(win fyne.Window, engine *threatintel.Engine, sched *scheduler.Scheduler, notif *notifier.Notifier) *DashboardTab {
	dt := &DashboardTab{
		window:    win,
		engine:    engine,
		scheduler: sched,
		notifier:  notif,
	}

	dt.initUI()
	dt.connectTelemetry()
	return dt
}

func (dt *DashboardTab) initUI() {
	// 1. Métricas principais do sistema
	dt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblSafe = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblUncataloged = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblThreats = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	// 2. Telemetria MalwareBazaar
	dt.lblMBStatus = widget.NewLabelWithStyle("● PRONTO / AGUARDANDO", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	dt.lblMBFile = widget.NewLabel("Nenhuma consulta em andamento")
	dt.lblMBFile.TextStyle = fyne.TextStyle{Italic: true}
	dt.barMBActivity = widget.NewProgressBarInfinite()
	dt.barMBActivity.Stop()

	// 3. Telemetria VirusTotal & Cronômetro
	dt.lblVTStatus = widget.NewLabelWithStyle("● TAXA SEGURA: 4 REQ/MINUTO", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	dt.lblVTFile = widget.NewLabel("Aguardando próximo arquivo...")
	dt.lblVTFile.TextStyle = fyne.TextStyle{Italic: true}
	dt.barVTProgress = widget.NewProgressBar()
	dt.barVTProgress.SetValue(1.0)
	dt.lblVTTimer = widget.NewLabelWithStyle("Pronto para envio imediato", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// 4. Terminal de Logs ao Vivo
	dt.logList = widget.NewList(
		func() int {
			dt.mu.RLock()
			defer dt.mu.RUnlock()
			return len(dt.logEntries)
		},
		func() fyne.CanvasObject {
			timeLbl := widget.NewLabel("[15:04:05]")
			srcLbl := widget.NewLabel("[SOURCE]")
			srcLbl.TextStyle = fyne.TextStyle{Bold: true}
			msgLbl := widget.NewLabel("Mensagem do log de atividades do antimalware...")

			return container.NewHBox(timeLbl, srcLbl, msgLbl)
		},
		func(id int, obj fyne.CanvasObject) {
			dt.mu.RLock()
			if id >= len(dt.logEntries) {
				dt.mu.RUnlock()
				return
			}
			item := dt.logEntries[id]
			dt.mu.RUnlock()

			box := obj.(*fyne.Container)
			timeLbl := box.Objects[0].(*widget.Label)
			srcLbl := box.Objects[1].(*widget.Label)
			msgLbl := box.Objects[2].(*widget.Label)

			timeLbl.SetText(item.Timestamp.Format("[15:04:05]"))
			srcLbl.SetText(fmt.Sprintf("[%s]", strings.ToUpper(item.Source)))
			msgLbl.SetText(item.Message)
		},
	)

	// Carrega logs iniciais do hub
	dt.logEntries = dt.engine.Telemetry().GetLogs()
	if len(dt.logEntries) == 0 {
		dt.engine.Telemetry().Log(threatintel.LogLevelSafe, "Sistema", "Central de Comando inicializada. Proteção ativa.")
	}
}

func (dt *DashboardTab) connectTelemetry() {
	dt.engine.Telemetry().SetListeners(
		// Atualização de estado das APIs e cronômetro
		func(st threatintel.TelemetryState) {
			fyne.Do(func() {
				// Atualiza MalwareBazaar
				if st.MBActive {
					dt.lblMBStatus.SetText("▲ TRANSMITINDO PARA MALWAREBAZAAR...")
					if st.MBCurrentFile != "" {
						dt.lblMBFile.SetText(fmt.Sprintf("Verificando: %s (hash: %.14s...)", st.MBCurrentFile, st.MBCurrentHash))
					}
					dt.barMBActivity.Start()
				} else {
					dt.lblMBStatus.SetText("● CONECTADO / AGUARDANDO")
					dt.lblMBFile.SetText(fmt.Sprintf("Total de consultas realizadas hoje: %d", st.MBQueries))
					dt.barMBActivity.Stop()
				}

				// Atualiza VirusTotal & Contagem Regressiva
				if st.VTSecondsLeft > 0 {
					// Em espera de Rate Limit
					dt.lblVTStatus.SetText(fmt.Sprintf("⏳ AGUARDANDO JANELA DE SEGURANÇA (%d seg)", st.VTSecondsLeft))
					if st.VTCurrentFile != "" {
						dt.lblVTFile.SetText(fmt.Sprintf("Na fila para envio: %s (hash: %.14s...)", st.VTCurrentFile, st.VTCurrentHash))
					}
					total := float64(st.VTIntervalSec)
					if total <= 0 {
						total = 15.0
					}
					// Progresso inverso (tempo restante)
					progress := 1.0 - (float64(st.VTSecondsLeft) / total)
					dt.barVTProgress.SetValue(progress)
					dt.lblVTTimer.SetText(fmt.Sprintf("Próximo envio em: 00:%02ds  |  Fila: %d arquivo(s)", st.VTSecondsLeft, st.VTQueueLen))
				} else if st.VTActive {
					// Enviando agora
					dt.lblVTStatus.SetText("🚀 ENVIANDO PARA O VIRUSTOTAL (70+ MOTORES)...")
					dt.lblVTFile.SetText(fmt.Sprintf("Processando: %s", st.VTCurrentFile))
					dt.barVTProgress.SetValue(1.0)
					dt.lblVTTimer.SetText("Recebendo veredito dos motores antivírus...")
				} else {
					dt.lblVTStatus.SetText("● PRONTO (RATE LIMIT 4 REQ/MINUTO ATIVO)")
					dt.lblVTFile.SetText(fmt.Sprintf("Total de análises no VirusTotal: %d", st.VTQueries))
					dt.barVTProgress.SetValue(1.0)
					dt.lblVTTimer.SetText("Pronto para envio imediato")
				}
			})
		},
		// Novo evento no feed
		func(item threatintel.LogItem) {
			dt.mu.Lock()
			dt.logEntries = append(dt.logEntries, item)
			if len(dt.logEntries) > 100 {
				dt.logEntries = dt.logEntries[1:]
			}
			dt.mu.Unlock()

			fyne.Do(func() {
				dt.logList.Refresh()
				dt.logList.ScrollToBottom()
			})
		},
	)

	// Atualiza métricas iniciais
	go dt.updateMetrics()
}

func (dt *DashboardTab) updateMetrics() {
	procs, err := process.ListRunningProcesses()
	if err != nil {
		return
	}

	safeCount := 0
	uncatCount := 0
	threatCount := 0

	for _, p := range procs {
		if p.SHA256 != "" {
			if rec, exists, _ := dt.engine.Store().Get(p.SHA256); exists && rec != nil {
				switch rec.Verdict {
				case cache.VerdictSafe:
					safeCount++
				case cache.VerdictMalicious:
					threatCount++
				default:
					uncatCount++
				}
			} else {
				uncatCount++
			}
		}
	}

	fyne.Do(func() {
		dt.lblTotal.SetText(fmt.Sprintf("%d", len(procs)))
		dt.lblSafe.SetText(fmt.Sprintf("%d", safeCount))
		dt.lblUncataloged.SetText(fmt.Sprintf("%d", uncatCount))
		dt.lblThreats.SetText(fmt.Sprintf("%d", threatCount))
	})
}

func (dt *DashboardTab) Content() fyne.CanvasObject {
	// 1. Hero Card de Proteção Ativa
	btnScanNow := widget.NewButtonWithIcon("Escanear Processos Agora", theme.MediaPlayIcon(), func() {
		dt.engine.Telemetry().Log(threatintel.LogLevelInfo, "Manual", "Disparando ciclo de análise sob demanda...")
		go dt.scheduler.TriggerNow()
		go dt.updateMetrics()
	})
	btnScanNow.Importance = widget.HighImportance

	heroTitle := canvas.NewText("STATUS DO SISTEMA: 100% PROTEGIDO", ColorEmerald)
	heroTitle.TextStyle = fyne.TextStyle{Bold: true}
	heroTitle.TextSize = 14

	heroSub := canvas.NewText("Monitoramento em tempo real a cada 30 min | Cache inteligente SQLite | Telemetria de APIs ativa", ColorTextSecondary)
	heroSub.TextSize = 11

	heroBody := container.NewBorder(nil, nil,
		container.NewVBox(heroTitle, heroSub),
		btnScanNow,
	)
	heroCard := NewPanelCard("CENTRAL DE MONITORAMENTO", NewPillBadge("TEMPO REAL", ColorEmerald, ColorEmeraldAlpha), heroBody)

	// 2. Métricas Principais (Cards com badges modernos e cores suaves)
	cardTotal := NewMetricCard("PROCESSOS DO SISTEMA", "Instâncias em execução", dt.lblTotal, "ATIVOS", ColorInfo, ColorInfoBg)
	cardSafe := NewMetricCard("HASHES SEGUROS", "Confirmados limpos em cache", dt.lblSafe, "✔ SEGUROS", ColorEmerald, ColorEmeraldAlpha)
	cardUncat := NewMetricCard("NÃO CATALOGADOS", "Sem assinatura nas bases", dt.lblUncataloged, "❔ INÉDITOS", ColorWarn, ColorWarnBg)
	cardThreats := NewMetricCard("AMEAÇAS CONFIRMADAS", "Malware ativo detectado", dt.lblThreats, "🚨 AMEAÇAS", ColorDanger, ColorDangerBg)

	metricsGrid := container.NewGridWithColumns(4, cardTotal, cardSafe, cardUncat, cardThreats)

	// 3. Cartões de Telemetria com Fundo Elevado
	mbBody := container.NewVBox(
		dt.lblMBStatus,
		dt.lblMBFile,
		dt.barMBActivity,
	)
	cardMB := NewPanelCard("🌐 MALWAREBAZAAR (ABUSE.CH)", NewPillBadge("GRATUITO / ILIMITADO", ColorEmerald, ColorEmeraldAlpha), mbBody)

	vtBody := container.NewVBox(
		dt.lblVTStatus,
		dt.lblVTFile,
		dt.barVTProgress,
		dt.lblVTTimer,
	)
	cardVT := NewPanelCard("🛡️ VIRUSTOTAL v3 (70+ MOTORES)", NewPillBadge("RATE LIMIT 4/MIN", ColorInfo, ColorInfoBg), vtBody)

	telemetryGrid := container.NewGridWithColumns(2, cardMB, cardVT)

	// 4. Ações Rápidas do Terminal
	btnTestAlert := widget.NewButtonWithIcon("Testar Alerta", theme.MailSendIcon(), func() {
		_ = dt.notifier.SendMalwareAlert("processo_teste.exe", 1234, "Teste.Dashboard.Alerta", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		dt.engine.Telemetry().Log(threatintel.LogLevelWarn, "Alerta", "Alerta sonoro e visual disparado na Área de Trabalho.")
		dialog.ShowInformation("Alerta Disparado", "Notificação de teste enviada para sua Área de Trabalho!", dt.window)
	})

	btnClearLogs := widget.NewButtonWithIcon("Limpar Console", theme.DeleteIcon(), func() {
		dt.mu.Lock()
		dt.logEntries = nil
		dt.mu.Unlock()
		dt.logList.Refresh()
	})

	actionsBox := container.NewHBox(btnTestAlert, btnClearLogs)

	headerTerminal := container.NewBorder(nil, nil,
		widget.NewLabelWithStyle("⚡ LIVE THREAT STREAM & TELEMETRIA", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		actionsBox,
	)

	topContainer := container.NewVBox(
		heroCard,
		metricsGrid,
		telemetryGrid,
		headerTerminal,
	)

	return container.NewBorder(topContainer, nil, nil, nil, dt.logList)
}
