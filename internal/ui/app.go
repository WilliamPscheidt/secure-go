package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
	"secure-go/internal/process"
	"secure-go/internal/quarantine"
	"secure-go/internal/scheduler"
	"secure-go/internal/threatintel"
	"secure-go/internal/watcher"
)

type App struct {
	fyneApp     fyne.App
	window      fyne.Window
	engine      *threatintel.Engine
	scheduler   *scheduler.Scheduler
	notifier    *notifier.Notifier
	fileWatcher *watcher.FileWatcher
	vault       *quarantine.Vault
}

func NewApp(engine *threatintel.Engine, sched *scheduler.Scheduler, notif *notifier.Notifier) *App {
	a := app.NewWithID("com.securego.antimalware")
	a.Settings().SetTheme(NewCustomTheme())

	w := a.NewWindow("SecureGo - Monitor em Tempo Real & Analisador de Ameaças")
	w.Resize(fyne.NewSize(1060, 700))
	w.SetMaster()

	// Inicia Cofre de Quarentena Criptografada AES-256
	vault, _ := quarantine.NewVault("")

	// Inicia FileWatcher em tempo real para pastas críticas (Downloads, Temp, Startup)
	fileWatcher := watcher.NewFileWatcher(engine, notif)
	_ = fileWatcher.Start()

	dashboardTab := NewDashboardTab(w, engine, sched, notif)
	processTab := NewProcessTab(w, engine, sched)
	networkTab := NewNetworkTab(w, engine)
	diskTab := NewDiskTab(w, engine, vault)
	yaraTab := NewYaraTab(w, engine)
	quarantineTab := NewQuarantineTab(w, vault, engine)
	databaseTab := NewDatabaseTab(w, engine)
	settingsTab := NewSettingsTab(w, engine, sched, notif)

	// Callback do engine para atualizar banco quando um novo hash for avaliado
	engine.SetOnNewVerdictCallback(func(rec *cache.HashRecord) {
		databaseTab.Refresh()
		dashboardTab.updateMetrics()
	})

	// Listener de ameaças do agendador (Scheduler): solicita permissão do usuário antes da quarentena
	sched.AddThreatListener(func(p process.ProcessInfo, threatName string) {
		fyne.Do(func() {
			ShowThreatActionDialog(
				w,
				vault,
				engine,
				p.Name,
				p.ExePath,
				threatName,
				p.SHA256,
				p.PID,
				func() {
					quarantineTab.Reload()
					databaseTab.Refresh()
					dashboardTab.updateMetrics()
				},
			)
		})
	})

	// Listener de ameaças do File Watcher em tempo real: solicita permissão do usuário
	fileWatcher.SetOnThreatFoundCallback(func(filePath, fileName, threatName, sha256 string) {
		fyne.Do(func() {
			ShowThreatActionDialog(
				w,
				vault,
				engine,
				fileName,
				filePath,
				threatName,
				sha256,
				0,
				func() {
					quarantineTab.Reload()
					databaseTab.Refresh()
					dashboardTab.updateMetrics()
				},
			)
		})
	})

	// Estrutura de Navegação em Sidebar Lateral (Estilo Malwarebytes & Purrweb)
	type navItem struct {
		title   string
		icon    fyne.Resource
		content fyne.CanvasObject
		btn     *widget.Button
	}

	items := []*navItem{
		{"Dashboard", IconFADashboard, dashboardTab.Content(), nil},
		{"Processos Ativos", IconFAProcesses, processTab.Content(), nil},
		{"Mapa de Rede", IconFANetwork, networkTab.Content(), nil},
		{"Scanner de Disco", IconFADisk, diskTab.Content(), nil},
		{"Regras YARA", IconFACode, yaraTab.Content(), nil},
		{"Quarentena", IconFAVault, quarantineTab.Content(), nil},
		{"Banco de Hashes", IconFADatabase, databaseTab.Content(), nil},
		{"Configurações", IconFAGear, settingsTab.Content(), nil},
	}

	contentArea := container.NewStack(items[0].content)

	selectTab := func(idx int) {
		for i, it := range items {
			if i == idx {
				it.btn.Importance = widget.HighImportance
			} else {
				it.btn.Importance = widget.LowImportance
			}
			it.btn.Refresh()
		}
		contentArea.Objects = []fyne.CanvasObject{items[idx].content}
		contentArea.Refresh()
	}

	var navButtons []fyne.CanvasObject
	for i := range items {
		idx := i
		btn := widget.NewButtonWithIcon(items[i].title, items[i].icon, func() {
			selectTab(idx)
		})
		btn.Alignment = widget.ButtonAlignLeading
		if i == 0 {
			btn.Importance = widget.HighImportance
		} else {
			btn.Importance = widget.LowImportance
		}
		items[i].btn = btn
		navButtons = append(navButtons, btn)
	}

	sidebarNavList := container.NewVBox(navButtons...)

	sidebarBg := canvas.NewRectangle(ColorSidebarBg)
	sidebarBg.SetMinSize(fyne.NewSize(195, 0))

	sidebarHeader := container.NewVBox(
		NewSectionHeader("MENU PRINCIPAL"),
	)

	statusPill := NewPillBadge("● PROTEÇÃO ATIVA", ColorScoreGreen, ColorScoreGreenBg)

	versionLbl := canvas.NewText("SecureGo Enterprise v2.5", ColorTextMuted)
	versionLbl.TextSize = 10

	engineLbl := canvas.NewText("Heurística + SQLite WAL", ColorTextMuted)
	engineLbl.TextSize = 9

	sidebarFooter := container.NewVBox(
		canvas.NewLine(ColorCardBorder),
		container.NewCenter(statusPill),
		container.NewCenter(versionLbl),
		container.NewCenter(engineLbl),
	)

	sidebarContent := container.NewBorder(sidebarHeader, sidebarFooter, nil, nil, sidebarNavList)
	sidebar := container.NewStack(sidebarBg, container.NewPadded(sidebarContent))

	// Separador vertical sutil entre a barra lateral e a área principal
	vDivider := canvas.NewLine(ColorCardBorder)

	mainLayout := container.NewBorder(
		nil, nil,
		container.NewHBox(sidebar, vDivider),
		nil,
		container.NewPadded(contentArea),
	)

	// Barra superior estilizada com branding e indicador de proteção
	brandTitle := canvas.NewText("SECURE-GO", ColorBlueVibrant)
	brandTitle.TextStyle = fyne.TextStyle{Bold: true}
	brandTitle.TextSize = 14

	shieldImg := canvas.NewImageFromResource(IconFAShield)
	shieldImg.SetMinSize(fyne.NewSize(18, 18))

	brandSub := canvas.NewText("CYBER DEFENDER & THREAT MONITOR", ColorTextSecondary)
	brandSub.TextSize = 11

	topBannerStatusPill := NewPillBadge("● TEMPO REAL ATIVO (WATCHER + YARA + QUARENTENA)", ColorCyan, ColorCyanAlpha)

	headerBanner := container.NewVBox(
		container.NewPadded(
			container.NewBorder(nil, nil,
				container.NewHBox(shieldImg, brandTitle, canvas.NewText("|", ColorCardBorder), brandSub),
				topBannerStatusPill,
			),
		),
		canvas.NewLine(ColorCardBorder),
	)

	w.SetContent(container.NewBorder(headerBanner, nil, nil, nil, mainLayout))

	w.SetOnClosed(func() {
		fileWatcher.Stop()
	})

	return &App{
		fyneApp:     a,
		window:      w,
		engine:      engine,
		scheduler:   sched,
		notifier:    notif,
		fileWatcher: fileWatcher,
		vault:       vault,
	}
}

func (a *App) Run() {
	a.window.ShowAndRun()
}
