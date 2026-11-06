package metrics

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func raplRoot(t *testing.T, energy string) (root, energyFile string) {
	root = t.TempDir()
	zone := filepath.Join(root, "sys/class/powercap/intel-rapl:0")
	write(t, filepath.Join(zone, "name"), "package-0\n")
	write(t, filepath.Join(zone, "max_energy_range_uj"), "1000000000\n")
	energyFile = filepath.Join(zone, "energy_uj")
	write(t, energyFile, energy)
	return root, energyFile
}

func TestRAPLDelta(t *testing.T) {
	root, file := raplRoot(t, "1000000\n")
	s := newSampler(Profile{10, 100}, root)
	start := time.Now()
	if _, ok := s.readRAPL(start); ok {
		t.Fatal("first read has no delta, must not count as measured")
	}
	write(t, file, "51000000\n") // 50 J
	w, ok := s.readRAPL(start.Add(10 * time.Second))
	if !ok || !near(w, 5) {
		t.Fatalf("got %v %v, want 5 W measured", w, ok)
	}
}

func TestRAPLWraparound(t *testing.T) {
	root, file := raplRoot(t, "999000000\n")
	s := newSampler(Profile{10, 100}, root)
	start := time.Now()
	s.readRAPL(start)
	write(t, file, "9000000\n") // 1 J to the top of the range, then 9 J after wrapping
	w, ok := s.readRAPL(start.Add(10 * time.Second))
	if !ok || !near(w, 1) {
		t.Fatalf("got %v %v, want 1 W measured", w, ok)
	}
}

func TestRAPLWrapWithoutRangeIsNotMeasured(t *testing.T) {
	root, file := raplRoot(t, "500\n")
	os.Remove(filepath.Join(root, "sys/class/powercap/intel-rapl:0/max_energy_range_uj"))
	s := newSampler(Profile{10, 100}, root)
	start := time.Now()
	s.readRAPL(start)
	write(t, file, "100\n")
	if _, ok := s.readRAPL(start.Add(time.Second)); ok {
		t.Fatal("a wrap with unknown range cannot produce a measurement")
	}
}

func TestRAPLIgnoresSubzonesAndPsys(t *testing.T) {
	root, file := raplRoot(t, "0\n")
	base := filepath.Join(root, "sys/class/powercap")
	sub := filepath.Join(base, "intel-rapl:0:0")
	write(t, filepath.Join(sub, "energy_uj"), "0\n")
	psys := filepath.Join(base, "intel-rapl:1")
	write(t, filepath.Join(psys, "name"), "psys\n")
	write(t, filepath.Join(psys, "energy_uj"), "0\n")
	s := newSampler(Profile{10, 100}, root)
	start := time.Now()
	s.readRAPL(start)
	write(t, file, "10000000\n")
	write(t, filepath.Join(sub, "energy_uj"), "9000000\n")
	write(t, filepath.Join(psys, "energy_uj"), "99000000\n")
	w, ok := s.readRAPL(start.Add(10 * time.Second))
	if !ok || !near(w, 1) {
		t.Fatalf("got %v %v, want only the package: 1 W", w, ok)
	}
}

func TestRAPLUnreadableFallsBack(t *testing.T) {
	root, file := raplRoot(t, "1000\n")
	s := newSampler(Profile{10, 100}, root)
	start := time.Now()
	s.readRAPL(start)
	os.Remove(file)
	if _, ok := s.readRAPL(start.Add(time.Second)); ok {
		t.Fatal("unreadable counter must not count as measured")
	}
}

func procRoot(t *testing.T, root string, idle int, ticks map[int]int, cpuinfo string) {
	t.Helper()
	write(t, filepath.Join(root, "proc/stat"), fmt.Sprintf("cpu  1000 0 0 %d 0 0 0 0 0 0\ncpu0 1 1 1 1\n", idle))
	write(t, filepath.Join(root, "proc/meminfo"), "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
	write(t, filepath.Join(root, "proc/cpuinfo"), cpuinfo)
	for pid, n := range ticks {
		write(t, filepath.Join(root, "proc", fmt.Sprint(pid), "stat"),
			fmt.Sprintf("%d (we ird) x) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0\n", pid, n))
	}
}

// RAPL present and a real delta: measured, with GPU power added on top.
func TestSampleMeasured(t *testing.T) {
	root, file := raplRoot(t, "0\n")
	procRoot(t, root, 0, map[int]int{7: 0}, "flags : fpu sse\n")
	s := newSampler(Profile{10, 100}, root)
	s.gpuWatts = func() (float64, bool) { return 40, true }
	s.baseline()
	time.Sleep(20 * time.Millisecond)
	write(t, file, "1000000\n")
	procRoot(t, root, 500, map[int]int{7: 100}, "flags : fpu sse\n")
	got, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if got.IsEstimated || got.Watts <= 40 {
		t.Fatalf("%+v", got)
	}
	if !near(got.MemPct, 75) {
		t.Fatalf("mem %v", got.MemPct)
	}
	if len(got.Processes) != 1 || got.Processes[0].Name != "we ird) x" {
		t.Fatalf("%+v", got.Processes)
	}
}

// A VM stays an estimate even if it exposes a RAPL-looking directory.
func TestSampleVMIsEstimated(t *testing.T) {
	root, file := raplRoot(t, "0\n")
	procRoot(t, root, 0, nil, "flags : fpu hypervisor sse\n")
	s := newSampler(Profile{10, 110}, root)
	s.baseline()
	write(t, file, "9000000\n")
	procRoot(t, root, 3000, nil, "flags : fpu hypervisor sse\n") // only idle time passed: 0% CPU
	got, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEstimated || !near(got.Watts, 10) {
		t.Fatalf("%+v", got)
	}
}

func TestEverySamplePathWithoutRAPLIsEstimated(t *testing.T) {
	root := t.TempDir()
	procRoot(t, root, 0, nil, "")
	s := newSampler(Profile{10, 100}, root)
	s.gpuWatts = func() (float64, bool) { return 30, true } // a measured GPU does not make CPU power measured
	s.baseline()
	procRoot(t, root, 1000, nil, "")
	got, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEstimated {
		t.Fatalf("%+v", got)
	}
}

func TestProfile(t *testing.T) {
	p := Profile{20, 120}
	for _, c := range []struct{ cpu, want float64 }{{0, 20}, {50, 70}, {100, 120}, {150, 120}, {-5, 20}} {
		if got := p.Estimate(c.cpu); !near(got, c.want) {
			t.Errorf("Estimate(%v) = %v, want %v", c.cpu, got, c.want)
		}
	}
	for _, bad := range []Profile{{-1, 10}, {10, 5}, {0, 0}} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
	if p.Validate() != nil {
		t.Error("good profile rejected")
	}
}

func TestApportion(t *testing.T) {
	var procs []Process
	for i := 1; i <= 15; i++ {
		procs = append(procs, Process{PID: i, CPUPct: float64(i)})
	}
	got := apportion(procs, 120) // total share is 120
	if len(got) != topProcesses || got[0].PID != 15 || !near(got[0].Watts, 15) {
		t.Fatalf("%+v", got)
	}
	var sum float64
	for _, p := range got {
		sum += p.Watts
	}
	if sum >= 120 {
		t.Fatalf("top processes took %v W, must stay below the 120 W of everything", sum)
	}
	if got := apportion([]Process{{PID: 1}}, 100); got[0].Watts != 0 {
		t.Fatalf("no CPU use: %+v", got)
	}
}

func TestParsers(t *testing.T) {
	if w, ok := parseNvidia("35.20\n[N/A]\n10.5\n"); !ok || !near(w, 45.7) {
		t.Fatalf("%v %v", w, ok)
	}
	if _, ok := parseNvidia("[N/A]\n"); ok {
		t.Fatal("no reading must be reported as absent")
	}
	cpu, mem, procs := parsePS("  12  80.0  1.5 /usr/bin/my app\n  13  0.0  2.5 idle\nnoise\n", 4)
	if !near(cpu, 20) || !near(mem, 4) || len(procs) != 1 || procs[0].Name != "my app" || !near(procs[0].CPUPct, 20) {
		t.Fatalf("%v %v %+v", cpu, mem, procs)
	}
	if _, _, err := parseCPULine("garbage"); err == nil {
		t.Fatal("bad /proc/stat accepted")
	}
	if name, ticks, ok := parseProcStat("1 (a (b)) S 1 1 1 0 -1 0 0 0 0 0 5 6 0 0"); !ok || name != "a (b)" || ticks != 11 {
		t.Fatalf("%q %v %v", name, ticks, ok)
	}
}

// Runs the real sampler on this machine: macOS has no RAPL, Linux CI may.
func TestRealSampler(t *testing.T) {
	s := New(Profile{10, 100})
	got, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if got.Watts <= 0 {
		t.Fatalf("%+v", got)
	}
}
