package ui

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"secure-go/internal/network"
	"secure-go/internal/threatintel"
)

type NetworkTab struct {
	window          fyne.Window
	engine          *threatintel.Engine
	conns           []network.ConnectionEntry
	filtered        []network.ConnectionEntry
	listWidget      *widget.List
	searchEntry     *widget.Entry
	checkOnlySus    *widget.Check
	lblTotal        *widget.Label
	lblExternal     *widget.Label
	lblSuspicious   *widget.Label
	lblListening    *widget.Label
	btnRefresh      *widget.Button
	mu              sync.RWMutex
}

func NewNetworkTab(win fyne.Window, engine *threatintel.Engine) *NetworkTab {
	nt := &NetworkTab{
		window: win,
		engine: engine,
	}

	nt.initUI()
	nt.Refresh()
	return nt
}

func (nt *NetworkTab) initUI() {
	nt.lblTotal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	nt.lblExternal = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	nt.lblSuspicious = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	nt.lblListening = widget.NewLabelWithStyle("0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	nt.searchEntry = widget.NewEntry()
	nt.searchEntry.SetPlaceHolder("🔍 Filtrar conexões por processo, PID, IP ou porta...")
	nt.searchEntry.OnChanged = func(q string) {
		nt.filterItems(q)
	}

	nt.checkOnlySus = widget.NewCheck("Apenas Alertas & Suspeitas", func(checked bool) {
		nt.filterItems(nt.searchEntry.Text)
	})

	nt.btnRefresh = widget.NewButtonWithIcon("Atualizar Conexões", IconFANetwork, func() {
		nt.Refresh()
	})
	nt.btnRefresh.Importance = widget.HighImportance

	nt.listWidget = widget.NewList(
		func() int {
			nt.mu.RLock()
			defer nt.mu.RUnlock()
			return len(nt.filtered)
		},
		func() fyne.CanvasObject {
			procLabel := widget.NewLabelWithStyle("process.exe [PID: 0000]", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			connLabel := widget.NewLabel("127.0.0.1:0000 -> 0.0.0.0:0000 [ESTABLISHED]")
			riskBadge := widget.NewLabel("[NORMAL]")
			riskBadge.TextStyle = fyne.TextStyle{Bold: true}

			return container.NewBorder(nil, nil, nil, riskBadge,
				container.NewVBox(procLabel, connLabel),
			)
		},
		func(id int, obj fyne.CanvasObject) {
			nt.mu.RLock()
			if id >= len(nt.filtered) {
				nt.mu.RUnlock()
				return
			}
			c := nt.filtered[id]
			nt.mu.RUnlock()

			box := obj.(*fyne.Container)
			badge := box.Objects[1].(*widget.Label)
			vbox := box.Objects[0].(*fyne.Container)
			procLbl := vbox.Objects[0].(*widget.Label)
			connLbl := vbox.Objects[1].(*widget.Label)

			procLbl.SetText(fmt.Sprintf("%s  [PID: %d]", c.ProcessName, c.PID))

			if c.IsSuspicious {
				badge.SetText("🚨 ALERTA C2/RISCO")
				connLbl.SetText(fmt.Sprintf("%s -> %s [%s] - %s", c.LocalAddr, c.RemoteAddr, c.State, c.ThreatIndicator))
			} else {
				if c.State == "LISTEN" {
					badge.SetText("👂 ESCUTANDO")
				} else {
					badge.SetText("✔ NORMAL")
				}
				connLbl.SetText(fmt.Sprintf("%s -> %s [%s]", c.LocalAddr, c.RemoteAddr, c.State))
			}
		},
	)

	nt.listWidget.OnSelected = func(id int) {
		nt.mu.RLock()
		if id >= len(nt.filtered) {
			nt.mu.RUnlock()
			return
		}
		item := nt.filtered[id]
		nt.mu.RUnlock()
		nt.showConnectionDialog(item)
		nt.listWidget.Unselect(id)
	}
}

func (nt *NetworkTab) Refresh() {
	go func() {
		conns, err := network.GetActiveTcpConnections()
		if err != nil {
			return
		}

		total := len(conns)
		extCount := 0
		susCount := 0
		listenCount := 0

		for _, c := range conns {
			if c.IsSuspicious {
				susCount++
			}
			if c.State == "LISTEN" {
				listenCount++
			}
			ip := net.ParseIP(c.RemoteIP)
			if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() {
				extCount++
			}
		}

		nt.mu.Lock()
		nt.conns = conns
		nt.mu.Unlock()

		fyne.Do(func() {
			nt.lblTotal.SetText(fmt.Sprintf("%d", total))
			nt.lblExternal.SetText(fmt.Sprintf("%d", extCount))
			nt.lblSuspicious.SetText(fmt.Sprintf("%d", susCount))
			nt.lblListening.SetText(fmt.Sprintf("%d", listenCount))
			nt.filterItems(nt.searchEntry.Text)
		})
	}()
}

func (nt *NetworkTab) filterItems(query string) {
	nt.mu.Lock()
	q := strings.ToLower(strings.TrimSpace(query))
	onlySus := nt.checkOnlySus.Checked

	var res []network.ConnectionEntry
	for _, c := range nt.conns {
		if onlySus && !c.IsSuspicious {
			continue
		}
		if q != "" {
			match := strings.Contains(strings.ToLower(c.ProcessName), q) ||
				strings.Contains(fmt.Sprintf("%d", c.PID), q) ||
				strings.Contains(c.LocalAddr, q) ||
				strings.Contains(c.RemoteAddr, q) ||
				strings.Contains(strings.ToLower(c.State), q) ||
				strings.Contains(strings.ToLower(c.ThreatIndicator), q)
			if !match {
				continue
			}
		}
		res = append(res, c)
	}
	nt.filtered = res
	nt.mu.Unlock()

	if nt.listWidget != nil {
		nt.listWidget.Refresh()
	}
}

func (nt *NetworkTab) showConnectionDialog(c network.ConnectionEntry) {
	riskTxt := "Tráfego normal do sistema operacional ou aplicativo conhecido."
	if c.IsSuspicious {
		riskTxt = fmt.Sprintf("ALERTA CRÍTICO DE SEGURANÇA: %s", c.ThreatIndicator)
	}

	content := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Processo: %s (PID: %d)", c.ProcessName, c.PID), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("Local:  %s", c.LocalAddr)),
		widget.NewLabel(fmt.Sprintf("Remoto: %s (IP: %s, Porta: %d)", c.RemoteAddr, c.RemoteIP, c.RemotePort)),
		widget.NewLabel(fmt.Sprintf("Estado TCP: %s", c.State)),
		widget.NewLabel(fmt.Sprintf("Avaliação de Risco: %s", c.RiskLevel)),
		widget.NewLabel(riskTxt),
	)

	if c.ExePath != "" {
		content.Add(widget.NewLabel(fmt.Sprintf("Executável: %s", c.ExePath)))
	}

	d := dialog.NewCustom("Detalhes da Conexão TCP", "Fechar", content, nt.window)
	d.Resize(fyne.NewSize(580, 280))
	d.Show()
}

func (nt *NetworkTab) Content() fyne.CanvasObject {
	cardTotal := NewMetricCard("CONEXÕES TOTAIS", "Sockets TCP ativos", nt.lblTotal, "TCP", ColorBluePrimary, ColorBlueAlpha)
	cardExt := NewMetricCard("CONEXÕES EXTERNAS", "Endpoints na Internet", nt.lblExternal, "INTERNET", ColorCyan, ColorCyanAlpha)
	cardSus := NewMetricCard("ALERTAS DE REDE", "Portas suspeitas / C2", nt.lblSuspicious, "AMEAÇAS", ColorDanger, ColorDangerBg)
	cardListen := NewMetricCard("PORTAS ESCUTANDO", "Servidores / Listeners", nt.lblListening, "LISTEN", ColorWarn, ColorWarnBg)

	toolbar := NewPanelCard("MONITORAMENTO ATIVO DE CONEXÕES & THREAT NETWORK MAP",
		container.NewHBox(nt.btnRefresh, nt.checkOnlySus),
		nt.searchEntry,
	)

	header := container.NewVBox(
		container.NewGridWithColumns(4,
			cardTotal,
			cardExt,
			cardSus,
			cardListen,
		),
		toolbar,
	)

	return container.NewBorder(header, nil, nil, nil, nt.listWidget)
}
