package main

// Alert data types for the agent, adapted from the controller monolith
// (alerts.go): the state-change tracker and config loading are ported;
// delivery (webhook/Telegram) stays controller-side — the agent records
// nothing and sends nothing (alertSend is a no-op seam here).

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type alertConfig struct {
	Enabled      bool   `json:"enabled"`
	WebhookURL   string `json:"webhook_url,omitempty"`
	Telegram     bool   `json:"telegram"`              // reuse bot token/chat from watchdog.json
	NotifyDegrad bool   `json:"notify_degraded"`       // also alert on healthy<->degraded
	MinGapSec    int    `json:"min_gap_sec,omitempty"` // per-link minimum between alerts (default 120)
}

type alertEvent struct {
	Link string `json:"link"`
	From string `json:"from"`
	To   string `json:"to"`
	Why  string `json:"why,omitempty"`
	At   string `json:"at"`
	Host string `json:"host"`
}

func alertConfigPath() string { return filepath.Join(configDir, "alerts.json") }

func loadAlertConfig() alertConfig {
	c := alertConfig{MinGapSec: 120}
	if b, err := os.ReadFile(alertConfigPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.MinGapSec < 10 {
		c.MinGapSec = 120
	}
	return c
}

// alertSend delivers alerts on the controller; on the agent it is a
// deliberate no-op seam (no notifier is configured or executed here).
var alertSend = func(cfg alertConfig, evs []alertEvent) {}
