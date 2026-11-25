package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
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
}

func NewApp(engine *threatintel.Engine, sched *scheduler.Scheduler, notif *notifier.Notifier) *App {
	a := app.NewWithID("com.securego.antimalware")
	a.Settings().SetTheme(NewCustomTheme())

	w := a.NewWindow("SecureGo - Monitor em Tempo Real & Analisador de Ameaças")
	w.Resize(fyne.NewSize(1060, 700))
	w.SetMaster()

	// Inicia FileWatcher em tempo real para pastas críticas (Downloads, Temp, Startup)
	fileWatcher := watcher.NewFileWatcher(engine, notif)
	_ = fileWatcher.Start()

	dashboardTab := NewDashboardTab(w, engine, sched, notif)
	processTab := NewProcessTab(w, engine, sched)
	networkTab := NewNetworkTab(w, engine)
	diskTab := NewDiskTab(w, engine)
	databaseTab := NewDatabaseTab(w, engine)
	settingsTab := NewSettingsTab(w, engine, sched, notif)

	// Callback do engine para atualizar banco quando um novo hash for avaliado
	engine.SetOnNewVerdictCallback(func(rec *cache.HashRecord) {
		databaseTab.Refresh()
		dashboardTab.updateMetrics()
	})

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Painel Central (Dashboard)", IconFADashboard, dashboardTab.Content()),
		container.NewTabItemWithIcon("Processos Ativos", IconFAProcesses, processTab.Content()),
		container.NewTabItemWithIcon("Mapa de Rede", IconFANetwork, networkTab.Content()),
		container.NewTabItemWithIcon("Scanner de Disco", IconFADisk, diskTab.Content()),
		container.NewTabItemWithIcon("Banco de Hashes", IconFADatabase, databaseTab.Content()),
		container.NewTabItemWithIcon("Configurações", IconFAGear, settingsTab.Content()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// Barra superior estilizada com branding e indicador de proteção
	brandTitle := canvas.NewText("SECURE-GO", ColorBlueVibrant)
	brandTitle.TextStyle = fyne.TextStyle{Bold: true}
	brandTitle.TextSize = 14

	shieldImg := canvas.NewImageFromResource(IconFAShield)
	shieldImg.SetMinSize(fyne.NewSize(18, 18))

	brandSub := canvas.NewText("CYBER DEFENDER & THREAT MONITOR", ColorTextSecondary)
	brandSub.TextSize = 11

	statusPill := NewPillBadge("● TEMPO REAL ATIVO (WATCHER + HEURÍSTICA)", ColorCyan, ColorCyanAlpha)

	headerBanner := container.NewVBox(
		container.NewPadded(
			container.NewBorder(nil, nil,
				container.NewHBox(shieldImg, brandTitle, canvas.NewText("|", ColorCardBorder), brandSub),
				statusPill,
			),
		),
		canvas.NewLine(ColorCardBorder),
	)

	w.SetContent(container.NewBorder(headerBanner, nil, nil, nil, tabs))

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
	}
}

func (a *App) Run() {
	a.window.ShowAndRun()
}
