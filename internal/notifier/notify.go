package notifier

import (
	"fmt"
	"log"

	"github.com/gen2brain/beeep"
)

// Notifier gerencia notificações visuais no desktop.
type Notifier struct {
	appName string
}

// NewNotifier instancia o disparador de alertas.
func NewNotifier(appName string) *Notifier {
	return &Notifier{
		appName: appName,
	}
}

// Alert envia um alerta crítico na área de trabalho.
func (n *Notifier) Alert(title, message string) error {
	log.Printf("[NOTIFICAÇÃO ALERTA] %s: %s", title, message)
	return beeep.Alert(fmt.Sprintf("[%s] %s", n.appName, title), message, "")
}

// Notify envia uma notificação informativa padrão.
func (n *Notifier) Notify(title, message string) error {
	log.Printf("[NOTIFICAÇÃO INFO] %s: %s", title, message)
	return beeep.Notify(fmt.Sprintf("[%s] %s", n.appName, title), message, "")
}

// SendMalwareAlert envia um alerta sonoro/visual específico de ameaça detectada em execução.
func (n *Notifier) SendMalwareAlert(processName string, pid uint32, threatName, sha256 string) error {
	title := "🚨 PROCESSO MALICIOSO DETECTADO!"
	body := fmt.Sprintf("Processo: %s (PID: %d)\nAmeaça: %s\nHash: %.16s...", processName, pid, threatName, sha256)
	return n.Alert(title, body)
}
