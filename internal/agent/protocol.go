package agent

import (
	"encoding/json"

	"github.com/green-server/server_app/internal/classify"
	"github.com/green-server/server_app/internal/metrics"
)

// Wire types of the agent WebSocket, see plan/docs/api.md. That document is
// the source of truth.

type helloMsg struct {
	Type         string `json:"type"`
	AgentVersion string `json:"agentVersion"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
}

type metricsMsg struct {
	Type        string            `json:"type"`
	TS          string            `json:"ts"`
	CPUPct      float64           `json:"cpuPct"`
	MemPct      float64           `json:"memPct"`
	Watts       float64           `json:"watts"`
	IsEstimated bool              `json:"isEstimated"`
	Processes   []metrics.Process `json:"processes"`
}

type toolCallMsg struct {
	Type           string        `json:"type"`
	ConsultationID int64         `json:"consultationId"`
	RequestID      string        `json:"requestId"`
	Command        string        `json:"command"`
	Tier           classify.Tier `json:"tier"`
	Decision       string        `json:"decision"`
	UndoCommand    *string       `json:"undoCommand"`
}

type toolResultMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	ExitCode  *int   `json:"exitCode"`
}

type recommendation struct {
	Type         string  `json:"type"`
	Detail       string  `json:"detail"`
	EstSavingKrw float64 `json:"estSavingKrw"`
}

type consultationStatusMsg struct {
	Type            string           `json:"type"`
	ConsultationID  int64            `json:"consultationId"`
	Status          string           `json:"status"`
	Summary         string           `json:"summary,omitempty"`
	Level           string           `json:"level,omitempty"`
	Feedback        []string         `json:"feedback,omitempty"`
	Fixes           []string         `json:"fixes,omitempty"`
	Recommendations []recommendation `json:"recommendations,omitempty"`
}

type undoResultMsg struct {
	Type       string `json:"type"`
	ToolCallID int64  `json:"toolCallId"`
	ExitCode   int    `json:"exitCode"`
}

// incoming is the union of backend-to-agent messages.
type incoming struct {
	Type           string `json:"type"`
	ConsultationID int64  `json:"consultationId"`
	AuthMode       string `json:"authMode"`
	MaxTurns       int    `json:"maxTurns"`
	Model          string `json:"model"`
	ToolCallID     int64  `json:"toolCallId"`
	Command        string `json:"command"`
}

// Local socket protocol: one JSON request line, one JSON response line.

const (
	kindPre     = "pre"
	kindPost    = "post"
	kindApprove = "approve"
)

type ipcRequest struct {
	Kind      string          `json:"kind"`
	Tool      string          `json:"tool"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"toolUseId"`
	ExitCode  *int            `json:"exitCode,omitempty"`
}

type ipcResponse struct {
	Allow   bool   `json:"allow"`
	Message string `json:"message"`
}
