// Package metrics reads CPU, memory and power, and apportions power to
// processes. Every source reads from an injectable root, so tests use a fake
// sysfs and procfs on any OS and nothing here needs a build tag.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const topProcesses = 10

// Profile maps CPU use to power when it cannot be measured.
type Profile struct {
	IdleWatts float64 // at 0% CPU
	MaxWatts  float64 // at 100% CPU
}

func (p Profile) Validate() error {
	if p.IdleWatts < 0 || p.MaxWatts <= 0 || p.MaxWatts < p.IdleWatts {
		return fmt.Errorf("need 0 <= idle-watts <= max-watts and max-watts > 0, got idle=%v max=%v", p.IdleWatts, p.MaxWatts)
	}
	return nil
}

func (p Profile) Estimate(cpuPct float64) float64 {
	return p.IdleWatts + (p.MaxWatts-p.IdleWatts)*min(max(cpuPct, 0), 100)/100
}

type Process struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	CPUPct float64 `json:"cpuPct"`
	Watts  float64 `json:"watts"`
}

type Sample struct {
	CPUPct      float64
	MemPct      float64
	Watts       float64
	IsEstimated bool
	Processes   []Process
}

// Sampler holds the previous counters that power and CPU deltas need.
type Sampler struct {
	Profile Profile

	root      string // "/" outside tests
	gpuWatts  func() (float64, bool)
	psOutput  func() (string, error)
	virtual   bool
	rapl      map[string]uint64
	raplAt    time.Time
	cpuTotal  uint64
	cpuBusy   uint64
	procTicks map[int]uint64
}

func New(p Profile) *Sampler {
	s := newSampler(p, "/")
	s.gpuWatts = nvidiaWatts
	s.psOutput = psOutput
	s.baseline()
	return s
}

func newSampler(p Profile, root string) *Sampler {
	s := &Sampler{Profile: p, root: root, gpuWatts: func() (float64, bool) { return 0, false }}
	s.virtual = isVirtual(root)
	return s
}

// baseline stores first readings, so the first Sample already has a delta.
func (s *Sampler) baseline() {
	s.readRAPL(time.Now())
	s.readSystem()
}

// Sample reads everything once. Watts are measured only when RAPL produced a
// real delta; any other path is an estimate and is reported as one.
func (s *Sampler) Sample() (Sample, error) {
	cpu, mem, procs, err := s.readSystem()
	if err != nil {
		return Sample{}, err
	}
	gpu, _ := s.gpuWatts()
	watts, measured := s.readRAPL(time.Now())
	if !measured {
		watts = s.Profile.Estimate(cpu)
	}
	out := Sample{CPUPct: cpu, MemPct: mem, Watts: watts + gpu, IsEstimated: !measured}
	out.Processes = apportion(procs, out.Watts)
	return out, nil
}

// apportion splits watts by CPU share over all processes, then keeps the top.
func apportion(procs []Process, watts float64) []Process {
	var total float64
	for _, p := range procs {
		total += p.CPUPct
	}
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].CPUPct > procs[j].CPUPct })
	if len(procs) > topProcesses {
		procs = procs[:topProcesses]
	}
	out := make([]Process, len(procs))
	copy(out, procs)
	for i := range out {
		if total > 0 {
			out[i].Watts = watts * out[i].CPUPct / total
		}
	}
	return out
}

// isVirtual detects a VM. A guest's RAPL view, where it exists at all, does
// not describe what the instance draws, so VMs always estimate.
func isVirtual(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, "proc/cpuinfo"))
	return err == nil && strings.Contains(string(data), " hypervisor")
}

// readRAPL returns average package plus DRAM watts since the previous call.
// core and uncore are already inside their package, and psys overlaps it, but
// the dram subzone is a separate rail the package counter does not include.
//
// The kernel makes energy_uj root-only by default; install.sh grants the
// greenserver group read access. Unreadable falls back to estimation.
func (s *Sampler) readRAPL(now time.Time) (float64, bool) {
	if s.virtual {
		return 0, false
	}
	base := filepath.Join(s.root, "sys/class/powercap")
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, false
	}
	current := map[string]uint64{}
	var joules float64
	complete := true
	for _, e := range entries {
		// intel-rapl:0 is a package, intel-rapl:0:0 its subzone. AMD uses the same names.
		if !strings.HasPrefix(e.Name(), "intel-rapl:") {
			continue
		}
		dir := filepath.Join(base, e.Name())
		data, _ := os.ReadFile(filepath.Join(dir, "name"))
		name := strings.TrimSpace(string(data))
		if top := strings.Count(e.Name(), ":") == 1; top && name == "psys" || !top && name != "dram" {
			continue
		}
		energy, err := readUint(filepath.Join(dir, "energy_uj"))
		if err != nil {
			return 0, s.dropRAPL()
		}
		current[e.Name()] = energy
		prev, seen := s.rapl[e.Name()]
		if !seen {
			complete = false
			continue
		}
		delta := energy - prev
		if energy < prev { // the counter wrapped
			limit, err := readUint(filepath.Join(dir, "max_energy_range_uj"))
			if err != nil || limit < prev {
				return 0, s.dropRAPL()
			}
			delta = limit - prev + energy
		}
		joules += float64(delta) / 1e6
	}
	elapsed := now.Sub(s.raplAt).Seconds()
	s.rapl, s.raplAt = current, now
	if len(current) == 0 || !complete || elapsed <= 0 {
		return 0, false
	}
	return joules / elapsed, true
}

func (s *Sampler) dropRAPL() bool {
	s.rapl = nil
	return false
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func nvidiaWatts() (float64, bool) {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return 0, false
	}
	return parseNvidia(string(out))
}

// parseNvidia sums one watt value per GPU. Lines such as "[N/A]" are skipped.
func parseNvidia(out string) (float64, bool) {
	var total float64
	found := false
	for _, line := range strings.Split(out, "\n") {
		if w, err := strconv.ParseFloat(strings.TrimSpace(line), 64); err == nil {
			total += w
			found = true
		}
	}
	return total, found
}

func (s *Sampler) readSystem() (cpu, mem float64, procs []Process, err error) {
	if stat, statErr := os.ReadFile(filepath.Join(s.root, "proc/stat")); statErr == nil {
		return s.readProcfs(string(stat))
	}
	if s.psOutput == nil {
		return 0, 0, nil, errors.New("no process source")
	}
	out, err := s.psOutput()
	if err != nil {
		return 0, 0, nil, err
	}
	cpu, mem, procs = parsePS(out, runtime.NumCPU())
	return cpu, mem, procs, nil
}

func (s *Sampler) readProcfs(stat string) (float64, float64, []Process, error) {
	total, busy, err := parseCPULine(stat)
	if err != nil {
		return 0, 0, nil, err
	}
	dTotal, dBusy := total-s.cpuTotal, busy-s.cpuBusy
	s.cpuTotal, s.cpuBusy = total, busy
	var cpu float64
	if dTotal > 0 {
		cpu = float64(dBusy) / float64(dTotal) * 100
	}

	meminfo, err := os.ReadFile(filepath.Join(s.root, "proc/meminfo"))
	if err != nil {
		return 0, 0, nil, err
	}

	dirs, err := os.ReadDir(filepath.Join(s.root, "proc"))
	if err != nil {
		return 0, 0, nil, err
	}
	ticks := make(map[int]uint64, len(dirs))
	var procs []Process
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, "proc", d.Name(), "stat"))
		if err != nil {
			continue // it exited between the listing and the read
		}
		name, used, ok := parseProcStat(string(data))
		if !ok {
			continue
		}
		ticks[pid] = used
		// A process first seen now has no delta, and this also covers a reused pid.
		if prev, seen := s.procTicks[pid]; seen && used >= prev && dTotal > 0 {
			if pct := float64(used-prev) / float64(dTotal) * 100; pct > 0 {
				procs = append(procs, Process{PID: pid, Name: name, CPUPct: pct})
			}
		}
	}
	s.procTicks = ticks
	return cpu, parseMeminfo(string(meminfo)), procs, nil
}

// parseCPULine reads the aggregate line of /proc/stat.
func parseCPULine(stat string) (total, busy uint64, err error) {
	line, _, _ := strings.Cut(stat, "\n")
	f := strings.Fields(line)
	if len(f) < 6 || f[0] != "cpu" {
		return 0, 0, errors.New("unexpected /proc/stat format")
	}
	var idle uint64
	for i, v := range f[1:] {
		if i >= 8 { // guest time is already inside user time
			break
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return total, total - idle, nil
}

// parseProcStat reads /proc/<pid>/stat. The name sits in parentheses and may
// itself contain spaces and parentheses, so fields are counted after the last ')'.
func parseProcStat(line string) (name string, ticks uint64, ok bool) {
	open, end := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
	if open < 0 || end < open {
		return "", 0, false
	}
	f := strings.Fields(line[end+1:])
	if len(f) < 13 {
		return "", 0, false
	}
	utime, err1 := strconv.ParseUint(f[11], 10, 64)
	stime, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, false
	}
	return line[open+1 : end], utime + stime, true
}

func parseMeminfo(meminfo string) float64 {
	var total, available float64
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			available = v
		}
	}
	if total == 0 {
		return 0
	}
	return (total - available) / total * 100
}

func psOutput() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=,pcpu=,pmem=,comm=").Output()
	return string(out), err
}

// parsePS is the fallback for hosts without procfs, which in practice means
// macOS development. CPU is normalized so 100 means the whole machine, the
// same scale procfs gives.
//
// ponytail: memory is the sum of resident share, so shared pages count twice;
// use vm_stat if macOS ever becomes a real target.
func parsePS(out string, cpus int) (cpu, mem float64, procs []Process) {
	if cpus < 1 {
		cpus = 1
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		pcpu, err2 := strconv.ParseFloat(f[1], 64)
		pmem, err3 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		share := pcpu / float64(cpus)
		cpu += share
		mem += pmem
		if pcpu > 0 {
			name := filepath.Base(strings.Join(f[3:], " "))
			procs = append(procs, Process{PID: pid, Name: name, CPUPct: share})
		}
	}
	return min(cpu, 100), min(mem, 100), procs
}
