package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/cache"
	"secure-go/internal/notifier"
	"secure-go/internal/scheduler"
	"secure-go/internal/threatintel"
)

type App struct {
	fyneApp   fyne.App
	window    fyne.Window
	engine    *threatintel.Engine
	scheduler *scheduler.Scheduler
	notifier  *notifier.Notifier
}

func NewApp(engine *threatintel.Engine, sched *scheduler.Scheduler, notif *notifier.Notifier) *App {
	a := app.NewWithID("com.securego.antimalware")
	a.Settings().SetTheme(NewCustomTheme())

	w := a.NewWindow("SecureGo - Monitor em Tempo Real & Analisador de Ameaças")
	w.Resize(fyne.NewSize(1020, 680))
	w.SetMaster()

	dashboardTab := NewDashboardTab(w, engine, sched, notif)
	processTab := NewProcessTab(w, engine, sched)
	diskTab := NewDiskTab(w, engine)
	databaseTab := NewDatabaseTab(w, engine)
	settingsTab := NewSettingsTab(w, engine, sched, notif)

	// Callback do engine para atualizar banco quando um novo hash for avaliado
	engine.SetOnNewVerdictCallback(func(rec *cache.HashRecord) {
		databaseTab.Refresh()
		dashboardTab.updateMetrics()
	})

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Painel Central (Dashboard)", theme.HomeIcon(), dashboardTab.Content()),
		container.NewTabItemWithIcon("Processos Ativos", theme.ListIcon(), processTab.Content()),
		container.NewTabItemWithIcon("Scanner de Disco", theme.StorageIcon(), diskTab.Content()),
		container.NewTabItemWithIcon("Banco de Hashes", theme.FolderIcon(), databaseTab.Content()),
		container.NewTabItemWithIcon("Configurações", theme.SettingsIcon(), settingsTab.Content()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// Barra superior estilizada com branding e indicador de proteção
	brandTitle := widget.NewLabelWithStyle("🛡️ SECURE-GO", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	brandSub := widget.NewLabel("CYBERSECURITY & THREAT MONITOR")
	statusPill := widget.NewLabelWithStyle("● PROTEÇÃO ATIVA (TEMPO REAL)", fyne.TextAlignTrailing, fyne.TextStyle{Bold: true})

	headerBanner := container.NewVBox(
		container.NewBorder(nil, nil,
			container.NewHBox(brandTitle, widget.NewLabel("|"), brandSub),
			statusPill,
		),
		widget.NewSeparator(),
	)

	w.SetContent(container.NewBorder(headerBanner, nil, nil, nil, tabs))

	return &App{
		fyneApp:   a,
		window:    w,
		engine:    engine,
		scheduler: sched,
		notifier:  notif,
	}
}

func (a *App) Run() {
	a.window.ShowAndRun()
}
