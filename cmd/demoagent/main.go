// Command demoagent plays several servers on one connection each, so the site can
// be shown with a fleet. Every reading is invented and sent as estimated; it runs
// no command on any machine. Values derive from the timestamp, so a restart resends
// the same samples and the backend ignores the duplicates.
package main

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	step     = 10 * time.Second
	backfill = 12 * time.Hour
)

var kst = time.FixedZone("KST", 9*3600)

type process struct {
	Name  string
	PID   int
	Share float64
}

type report struct {
	Level    string
	Summary  string
	Feedback []string
	Fixes    []string
	Rec      map[string]any
}

type scenario struct {
	Name      string
	Mem       float64
	Idle, Max float64
	Load      func(t time.Time) float64 // 0 to 1
	Processes []process
	Session   []string // kind|text
	Report    report
}

func hours(t time.Time) float64 {
	t = t.In(kst)
	return float64(t.Hour()) + float64(t.Minute())/60
}

// bump is 1 at center and fades to 0 over width hours, wrapping past midnight.
func bump(h, center, width float64) float64 {
	d := math.Abs(h - center)
	d = math.Min(d, 24-d)
	return math.Max(0, math.Cos(math.Min(d/width, 1)*math.Pi/2))
}

var scenarios = map[string]scenario{
	"web": {
		Name: "web", Mem: 46, Idle: 58, Max: 128,
		Load:      func(t time.Time) float64 { h := hours(t); return 0.1 + 0.75*bump(h, 14, 7) + 0.3*bump(h, 21, 3) },
		Processes: []process{{"nginx", 812, 0.34}, {"node", 1431, 0.31}, {"postgres", 977, 0.2}, {"redis-server", 903, 0.09}, {"cron", 601, 0.02}},
		Session:   []string{"text|웹서버의 야간 사용량을 확인합니다.", "command|sar -u -s 02:00:00 -e 06:00:00", "output|Average: CPU 4.2%  idle 95.8%", "command|ls /etc/nginx/sites-enabled", "output|shop.example.com\nold-admin.example.com"},
		Report: report{
			Level: "fair", Summary: "[데모] 새벽에 CPU가 5% 아래로 내려가는데 워커 수는 낮과 같습니다.",
			Feedback: []string{"새벽 2시부터 6시까지 평균 CPU가 4%입니다.", "쓰지 않는 관리자 사이트가 켜져 있습니다."},
			Fixes:    []string{"nginx 워커를 8개에서 4개로 줄입니다. 되돌리려면 worker_processes를 8로 바꿉니다.", "old-admin 사이트를 비활성화합니다.", "하루 뒤 전력을 다시 잽니다."},
			Rec:      map[string]any{"type": "oversized", "detail": "[데모] 새벽 사용량에 비해 nginx 워커가 많습니다. 줄이면 유휴 전력이 내려갑니다.", "estSavingKrw": 2400},
		},
	},
	"game": {
		Name: "game", Mem: 72, Idle: 82, Max: 196,
		Load:      func(t time.Time) float64 { h := hours(t); return 0.08 + 0.95*bump(h, 21.5, 5) },
		Processes: []process{{"java", 2210, 0.74}, {"playit", 1190, 0.05}, {"dockerd", 804, 0.03}, {"backup.sh", 3321, 0.02}},
		Session:   []string{"text|접속자가 없는 시간대를 찾습니다.", "command|rcon-cli list", "output|There are 0 of a max of 40 players online", "command|journalctl -u game --since -24h | grep -c joined", "output|37"},
		Report: report{
			Level: "warning", Summary: "[데모] 오전에 접속자가 없는데 게임 서버가 계속 82W 이상을 씁니다.",
			Feedback: []string{"오전 3시부터 11시까지 접속 기록이 없습니다.", "이 시간 평균 전력이 86W입니다."},
			Fixes:    []string{"접속자가 0명이면 서버를 일시정지하도록 켭니다.", "접속이 오면 자동으로 깨어나는지 확인합니다.", "다음 날 오전 전력을 비교합니다."},
			Rec:      map[string]any{"type": "empty_game_server", "detail": "[데모] 오전 내내 접속자가 없습니다. 자동 일시정지를 켜면 이 시간의 전력을 크게 줄일 수 있습니다.", "estSavingKrw": 8700},
		},
	},
	"batch": {
		Name: "batch", Mem: 31, Idle: 44, Max: 236,
		Load: func(t time.Time) float64 {
			l := t.In(kst)
			if m := l.Minute(); l.Hour()%3 == 0 && m < 25 {
				return 0.72 + 0.2*math.Sin(float64(m))
			}
			return 0.03
		},
		Processes: []process{{"python3", 5120, 0.81}, {"airflow", 2204, 0.06}, {"containerd", 744, 0.03}},
		Session:   []string{"text|배치가 없는 시간의 낭비를 봅니다.", "command|crontab -l", "output|0 */3 * * * /opt/etl/run.sh", "command|cpupower frequency-info -p", "output|governor \"performance\""},
		Report: report{
			Level: "fair", Summary: "[데모] 배치 사이 2시간 반 동안에도 CPU가 최고 성능 모드입니다.",
			Feedback: []string{"배치는 3시간마다 25분 돕니다.", "나머지 시간 CPU 사용률은 3% 아래입니다."},
			Fixes:    []string{"CPU 거버너를 schedutil로 바꿉니다. 되돌리려면 performance로 설정합니다.", "배치 소요 시간이 늘지 않았는지 확인합니다."},
			Rec:      map[string]any{"type": "idle", "detail": "[데모] 배치 사이의 유휴 시간이 깁니다. CPU 거버너를 바꾸면 유휴 전력이 줄어듭니다.", "estSavingKrw": 3100},
		},
	},
}

// variant is a scenario running on another schedule and at another size, so a
// fleet does not peak in lockstep.
func variant(base string, name string, shift time.Duration, idle, max float64) scenario {
	s := scenarios[base]
	load := s.Load
	s.Name, s.Idle, s.Max = name, idle, max
	s.Load = func(t time.Time) float64 { return load(t.Add(-shift)) }
	return s
}

func init() {
	scenarios["api"] = variant("web", "api", 3*time.Hour, 34, 88)
	scenarios["game2"] = variant("game", "game2", -4*time.Hour, 64, 142)
	scenarios["encode"] = variant("batch", "encode", 80*time.Minute, 52, 268)
}

func noise(name string, t time.Time) float64 {
	h := fnv.New32a()
	h.Write([]byte(name + t.UTC().Format(time.RFC3339)))
	return float64(h.Sum32()%2000)/1000 - 1
}

// calm (DEMO_CALM=1) keeps every server near idle, so the fleet draws less than its week.
var calm bool

func (s scenario) reading(t time.Time) (cpu, mem, watts float64) {
	load := math.Min(1, math.Max(0, s.Load(t)+0.025*noise(s.Name, t)))
	if calm {
		load *= 0.1
	}
	return math.Round(load*1000) / 10, s.Mem + 6*load, math.Round((s.Idle+(s.Max-s.Idle)*load)*100) / 100
}

func metrics(s scenario, t time.Time, withProcesses bool) map[string]any {
	cpu, mem, watts := s.reading(t)
	procs := []map[string]any{}
	if withProcesses {
		for _, p := range s.Processes {
			procs = append(procs, map[string]any{"pid": p.PID, "name": p.Name, "cpuPct": math.Round(cpu*p.Share*10) / 10, "watts": math.Round(watts*p.Share*10) / 10})
		}
	}
	return map[string]any{"type": "metrics", "ts": t.UTC().Format(time.RFC3339), "cpuPct": cpu, "memPct": mem, "watts": watts, "isEstimated": true, "processes": procs}
}

func consult(ctx context.Context, send func(any) error, s scenario, id int64, readOnly bool, recommendation int64) {
	status := func(fields map[string]any) {
		fields["type"], fields["consultationId"] = "consultation_status", id
		_ = send(fields)
	}
	status(map[string]any{"status": "running"})
	for _, line := range s.Session {
		kind, text, _ := strings.Cut(line, "|")
		select {
		case <-ctx.Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
		_ = send(map[string]any{"type": "consultation_stream", "consultationId": id, "kind": kind, "text": text})
	}
	done := map[string]any{"status": "done", "summary": s.Report.Summary, "level": s.Report.Level, "feedback": s.Report.Feedback, "fixes": s.Report.Fixes}
	switch {
	case readOnly:
		done["summary"] = "계획: " + s.Report.Summary
	case recommendation > 0:
		done["summary"], done["recommendationId"] = "[데모] 데모 서버라 실제로 실행하지 않았습니다.", recommendation
		done["fixes"] = []string{}
	default:
		done["recommendations"] = []map[string]any{s.Report.Rec}
	}
	status(done)
}

func run(ctx context.Context, url, token string, s scenario) error {
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	out := make(chan []byte, 64)
	send := func(v any) error {
		data, err := json.Marshal(v)
		if err == nil {
			select {
			case out <- data:
			case <-ctx.Done():
			}
		}
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { // one writer: the socket allows no concurrent writes
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-out:
				if conn.Write(ctx, websocket.MessageText, data) != nil {
					cancel()
					return
				}
			}
		}
	}()
	_ = send(map[string]string{"type": "hello", "agentVersion": "demo", "hostname": "demo-" + s.Name, "os": "demo"})
	go func() {
		// time.Now each round: the catch-up takes minutes, and those must not leave a gap.
		for t := time.Now().Truncate(step).Add(-backfill); t.Before(time.Now().Truncate(step)) && ctx.Err() == nil; t = t.Add(step) {
			_ = send(metrics(s, t, false))
			time.Sleep(50 * time.Millisecond) // the database also serves real traffic
		}
		ticker := time.NewTicker(step)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				_ = send(metrics(s, t.Truncate(step), true))
			}
		}
	}()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var m struct {
			Type             string `json:"type"`
			ConsultationID   int64  `json:"consultationId"`
			ReadOnly         bool   `json:"readOnly"`
			RecommendationID int64  `json:"recommendationId"`
		}
		if json.Unmarshal(data, &m) == nil && m.Type == "consultation_start" {
			go consult(ctx, send, s, m.ConsultationID, m.ReadOnly, m.RecommendationID)
		}
	}
}

// DEMO_SERVERS is scenario=token pairs separated by commas; DEMO_CALM=1 idles the fleet.
func main() {
	url := os.Getenv("DEMO_URL")
	calm = os.Getenv("DEMO_CALM") == "1"
	pairs := strings.Split(os.Getenv("DEMO_SERVERS"), ",")
	for _, pair := range pairs {
		name, token, _ := strings.Cut(strings.TrimSpace(pair), "=")
		s, ok := scenarios[name]
		if !ok {
			log.Fatalf("unknown scenario %q", name)
		}
		go func() {
			for {
				if err := run(context.Background(), url, token, s); err != nil {
					log.Printf("%s: %v", s.Name, err)
				}
				time.Sleep(5 * time.Second)
			}
		}()
	}
	select {}
}
