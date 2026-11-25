package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
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

	// Hero Card e Progresso Geral da Varredura
	heroTitle       *canvas.Text
	heroSub         *canvas.Text
	btnScanNow      *widget.Button
	barScanProgress *widget.ProgressBar
	lblScanDetail   *widget.Label

	// Métricas principais
	lblTotal       *widget.Label
	lblSafe        *widget.Label
	lblUncataloged *widget.Label
	lblThreats     *widget.Label

	// Telemetria MalwareBazaar
	lblMBStatus   *widget.Label
	lblMBFile     *widget.Label
	barMBActivity *widget.ProgressBar

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
	dt.connectScheduler()
	return dt
}

func (dt *DashboardTab) initUI() {
	// 0. Hero Card e Barra Geral de Progresso
	dt.heroTitle = canvas.NewText("STATUS DO SISTEMA: 100% PROTEGIDO", ColorCyan)
	dt.heroTitle.TextStyle = fyne.TextStyle{Bold: true}
	dt.heroTitle.TextSize = 14

	dt.heroSub = canvas.NewText("Monitoramento em tempo real a cada 30 min | Cache inteligente SQLite | Telemetria de APIs ativa", ColorTextSecondary)
	dt.heroSub.TextSize = 11

	dt.btnScanNow = widget.NewButtonWithIcon("Escanear Processos Agora", IconFAPlay, func() {
		dt.btnScanNow.Disable()
		dt.btnScanNow.SetText("Iniciando...")
		dt.barScanProgress.SetValue(0.0)
		dt.lblScanDetail.SetText("Iniciando varredura e mapeamento de processos...")
		dt.engine.Telemetry().Log(threatintel.LogLevelInfo, "Manual", "Disparando ciclo de análise de processos sob demanda...")
		go func() {
			dt.scheduler.TriggerNow()
		}()
	})
	dt.btnScanNow.Importance = widget.HighImportance

	dt.barScanProgress = widget.NewProgressBar()
	dt.barScanProgress.SetValue(0.0)

	dt.lblScanDetail = widget.NewLabel("● Sistema monitorado em tempo real | Aguardando próximo ciclo de varredura")
	dt.lblScanDetail.TextStyle = fyne.TextStyle{Italic: true}

	// 1. Métricas principais do sistema
	dt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblSafe = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblUncataloged = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	dt.lblThreats = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	// 2. Telemetria MalwareBazaar (Barra de progresso real)
	dt.lblMBStatus = widget.NewLabelWithStyle("● CONECTADO / AGUARDANDO", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	dt.lblMBFile = widget.NewLabel("Nenhuma consulta em andamento | Base Abuse.ch pronta")
	dt.lblMBFile.TextStyle = fyne.TextStyle{Italic: true}
	dt.barMBActivity = widget.NewProgressBar()
	dt.barMBActivity.SetValue(0.0)

	// 3. Telemetria VirusTotal & Cronômetro
	if dt.engine.HasVirusTotalKey() {
		dt.lblVTStatus = widget.NewLabelWithStyle("● TAXA SEGURA: 4 REQ/MINUTO ATIVA", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		dt.lblVTFile = widget.NewLabel("Aguardando próximo arquivo na fila...")
		dt.lblVTTimer = widget.NewLabelWithStyle("Pronto para envio imediato", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	} else {
		dt.lblVTStatus = widget.NewLabelWithStyle("○ VIRUSTOTAL DESATIVADO (SEM CHAVE)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		dt.lblVTFile = widget.NewLabel("Configure uma chave em 'Configurações' para ativar análise com 70+ antivírus")
		dt.lblVTTimer = widget.NewLabelWithStyle("Sem envio pendente", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	}
	dt.lblVTFile.TextStyle = fyne.TextStyle{Italic: true}
	dt.barVTProgress = widget.NewProgressBar()
	dt.barVTProgress.SetValue(0.0)

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

func (dt *DashboardTab) connectScheduler() {
	dt.scheduler.AddProgressListener(func(current, total int, currentItem string) {
		pct := float64(current) / float64(total)
		fyne.Do(func() {
			dt.barScanProgress.SetValue(pct)
			dt.lblScanDetail.SetText(fmt.Sprintf("Analisando processo %d de %d (%d%%): %s", current, total, int(pct*100), currentItem))
			dt.btnScanNow.Disable()
			dt.btnScanNow.SetText("Varrendo...")
		})
	})

	dt.scheduler.AddReportListener(func(report *scheduler.ScanReport) {
		fyne.Do(func() {
			dt.barScanProgress.SetValue(1.0)
			dt.btnScanNow.Enable()
			dt.btnScanNow.SetText("Escanear Processos Agora")
			dt.lblScanDetail.SetText(fmt.Sprintf("✔ Varredura concluída: %d processos analisados em %v", report.TotalProcesses, report.Duration.Round(10*time.Millisecond)))
			dt.updateMetrics()

			if report.ThreatsDetected > 0 {
				dt.heroTitle.Text = fmt.Sprintf("ALERTA CRÍTICO: %d AMEAÇA(S) DETECTADA(S)!", report.ThreatsDetected)
				dt.heroTitle.Color = ColorDanger
			} else {
				dt.heroTitle.Text = "STATUS DO SISTEMA: 100% PROTEGIDO"
				dt.heroTitle.Color = ColorCyan
			}
			dt.heroTitle.Refresh()
		})
	})
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
					dt.barMBActivity.SetValue(1.0)
				} else {
					dt.lblMBStatus.SetText("● CONECTADO / AGUARDANDO")
					dt.lblMBFile.SetText(fmt.Sprintf("Total de consultas realizadas hoje: %d  |  Pronto", st.MBQueries))
					dt.barMBActivity.SetValue(0.0)
				}

				// Atualiza VirusTotal & Contagem Regressiva
				hasKey := dt.engine.HasVirusTotalKey()
				if !hasKey {
					dt.lblVTStatus.SetText("○ VIRUSTOTAL DESATIVADO (SEM CHAVE)")
					dt.lblVTFile.SetText("Insira uma chave API v3 em 'Configurações' para ativar")
					dt.barVTProgress.SetValue(0.0)
					dt.lblVTTimer.SetText("Sem chave de API configurada")
				} else if st.VTSecondsLeft > 0 {
					// Em espera de Rate Limit
					dt.lblVTStatus.SetText(fmt.Sprintf("⏳ AGUARDANDO JANELA DE SEGURANÇA (%d seg)", st.VTSecondsLeft))
					if st.VTCurrentFile != "" {
						dt.lblVTFile.SetText(fmt.Sprintf("Na fila para envio: %s (hash: %.14s...)", st.VTCurrentFile, st.VTCurrentHash))
					}
					total := float64(st.VTIntervalSec)
					if total <= 0 {
						total = 15.0
					}
					// Progresso da contagem regressiva (preenche conforme o tempo passa)
					progress := (total - float64(st.VTSecondsLeft)) / total
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
					dt.barVTProgress.SetValue(0.0)
					dt.lblVTTimer.SetText("Pronto para envio imediato")
				}
			})
		},
		// Novo evento no feed
		func(item threatintel.LogItem) {
			dt.mu.Lock()
			dt.logEntries = append(dt.logEntries, item)
			if len(dt.logEntries) > 120 {
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
				case cache.VerdictUnknown:
					if rec.MBChecked && rec.VTChecked {
						uncatCount++
					}
				default:
					// Pendente de validação dupla
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
	// 1. Coluna Esquerda: SECURITY (Cards modulares estilo Malwarebytes & Purrweb)
	cardScanner := NewSecurityRowCard(
		IconFAShield,
		"Scanner do Sistema",
		"Varredura periódica a cada 30 min | Cache SQLite",
		dt.btnScanNow,
		container.NewVBox(dt.barScanProgress, dt.lblScanDetail),
	)

	cardHistory := NewSecurityRowCard(
		IconFADatabase,
		"Histórico de Detecções & Hashes",
		"Processos em execução e dupla checagem em cache",
		NewPillBadge("BANCO SQLite", ColorBluePrimary, ColorBlueAlpha),
		nil,
	)

	cardRealTime := NewSecurityRowCard(
		IconFAEye,
		"Proteção Contínua (File Watcher)",
		"Vigiando Downloads, Temp e Inicialização",
		NewPillBadge("● ATIVA", ColorScoreGreen, ColorScoreGreenBg),
		nil,
	)

	cardNetwork := NewSecurityRowCard(
		IconFANetwork,
		"Threat Network & Conexões Ativas",
		"Mapeamento de sockets TCP e anti-C2/LOLBin ativo",
		NewPillBadge("SUPERVISIONADO", ColorCyan, ColorCyanAlpha),
		nil,
	)

	securityCol := container.NewVBox(
		NewSectionHeader("SECURITY (SEGURANÇA DO SISTEMA)"),
		cardScanner,
		cardHistory,
		cardRealTime,
		cardNetwork,
	)

	// 2. Coluna Direita: TRUSTED ADVISOR (Score de Proteção 100% com Arco Visual)
	scoreCard := NewProtectionScoreGauge(100, "Excelente")
	advisorCol := container.NewVBox(
		NewSectionHeader("TRUSTED ADVISOR (SAÚDE DO SISTEMA)"),
		scoreCard,
	)

	topHeroGrid := container.NewGridWithColumns(2, securityCol, advisorCol)

	// 3. Métricas Principais (Cards com badges modernos e cores suaves)
	cardTotal := NewMetricCard("PROCESSOS DO SISTEMA", "Instâncias em execução", dt.lblTotal, "ATIVOS", ColorBluePrimary, ColorBlueAlpha)
	cardSafe := NewMetricCard("HASHES SEGUROS", "Confirmados limpos em cache", dt.lblSafe, "✔ SEGUROS", ColorCyan, ColorCyanAlpha)
	cardUncat := NewMetricCard("NÃO CATALOGADOS", "Sem assinatura nas bases", dt.lblUncataloged, "❔ INÉDITOS", ColorWarn, ColorWarnBg)
	cardThreats := NewMetricCard("AMEAÇAS CONFIRMADAS", "Malware ativo detectado", dt.lblThreats, "🚨 AMEAÇAS", ColorDanger, ColorDangerBg)

	metricsGrid := container.NewGridWithColumns(4, cardTotal, cardSafe, cardUncat, cardThreats)

	// 4. Cartões de Telemetria com Fundo Elevado e Barras Reais
	mbBody := container.NewVBox(
		dt.lblMBStatus,
		dt.lblMBFile,
		dt.barMBActivity,
	)
	cardMB := NewPanelCard("🌐 MALWAREBAZAAR (ABUSE.CH)", NewPillBadge("GRATUITO / ILIMITADO", ColorCyan, ColorCyanAlpha), mbBody)

	vtBody := container.NewVBox(
		dt.lblVTStatus,
		dt.lblVTFile,
		dt.barVTProgress,
		dt.lblVTTimer,
	)
	cardVT := NewPanelCard("🛡️ VIRUSTOTAL v3 (70+ MOTORES)", NewPillBadge("RATE LIMIT 4/MIN", ColorBluePrimary, ColorBlueAlpha), vtBody)

	telemetryGrid := container.NewGridWithColumns(2, cardMB, cardVT)

	// 5. Ações Rápidas do Terminal com Ícones FontAwesome
	btnTestAlert := widget.NewButtonWithIcon("Testar Alerta", IconFABell, func() {
		_ = dt.notifier.SendMalwareAlert("processo_teste.exe", 1234, "Teste.Dashboard.Alerta", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		dt.engine.Telemetry().Log(threatintel.LogLevelWarn, "Alerta", "Alerta sonoro e visual disparado na Área de Trabalho.")
		dialog.ShowInformation("Alerta Disparado", "Notificação de teste enviada para sua Área de Trabalho!", dt.window)
	})

	btnClearLogs := widget.NewButtonWithIcon("Limpar Console", IconFATrash, func() {
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

	dashboardScrollContent := container.NewVBox(
		topHeroGrid,
		metricsGrid,
		telemetryGrid,
		headerTerminal,
	)

	return container.NewBorder(dashboardScrollContent, nil, nil, nil, dt.logList)
}
