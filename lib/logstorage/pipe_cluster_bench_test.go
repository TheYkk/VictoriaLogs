package logstorage

import (
	"fmt"
	"math/rand"
	"testing"
)

// benchClusterLines pre-renders a pool of synthetic log lines covering a handful of
// templates (mixed fixed-length and variable-length) with random numbers, IPs and ids.
//
// Numbers vary so the collapse_nums masking + clustering has real work to do, while the
// number of distinct templates stays small (as in real logs).
func benchClusterLines(n int) []string {
	rng := rand.New(rand.NewSource(42))
	lines := make([]string, n)
	weekdays := []string{"Sun", "Mon", "Tue", "Wed"}
	for i := 0; i < n; i++ {
		wd := weekdays[rng.Intn(len(weekdays))]
		switch i % 8 {
		case 0:
			lines[i] = fmt.Sprintf("[%s Dec %02d %02d:%02d:%02d 2005] [notice] jk2_init() Found child %d in scoreboard slot %d",
				wd, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(9000), rng.Intn(64))
		case 1:
			lines[i] = fmt.Sprintf("[%s Dec %02d %02d:%02d:%02d 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers%d.properties",
				wd, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(4))
		case 2:
			lines[i] = fmt.Sprintf("[%s Dec %02d %02d:%02d:%02d 2005] [error] mod_jk child workerEnv in error state %d",
				wd, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(10))
		case 3:
			lines[i] = fmt.Sprintf("[%s Dec %02d %02d:%02d:%02d 2005] [error] [client %d.%d.%d.%d] Directory index forbidden by rule: /var/www/html/",
				wd, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
		case 4:
			lines[i] = fmt.Sprintf("Jun %d %02d:%02d:%02d combo sshd(pam_unix)[%d]: authentication failure; logname= uid=%d euid=%d tty=NODEVssh ruser= rhost=%d.%d.%d.%d",
				rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(30000), rng.Intn(1000), rng.Intn(1000), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
		case 5:
			lines[i] = fmt.Sprintf("Jun %d %02d:%02d:%02d combo sshd(pam_unix)[%d]: session opened for user test by (uid=%d)",
				rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(30000), rng.Intn(1000))
		case 6:
			// variable-length template: a trailing list of step counters of random arity.
			s := fmt.Sprintf("%d-%02d:%02d:%02d:%03d|Step_SPUtils|%d| getTodayTotalDetailSteps =",
				20171223, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(1000), rng.Intn(99999))
			for k := 0; k < 3+rng.Intn(4); k++ {
				s += fmt.Sprintf(" %d", rng.Intn(5000))
			}
			lines[i] = s
		default:
			lines[i] = fmt.Sprintf("%d-%02d:%02d:%02d:%03d|Step_StandReportReceiver|%d|onReceive action: android.intent.action.SCREEN_ON",
				20171223, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(1000), rng.Intn(99999))
		}
	}
	return lines
}

func benchmarkPipeCluster(b *testing.B, pipeStr string) {
	pool := benchClusterLines(100_000)

	lex := newLexer(pipeStr, 0)
	p, err := parsePipe(lex)
	if err != nil {
		b.Fatalf("cannot parse %q: %s", pipeStr, err)
	}

	totalBytes := int64(0)
	for _, l := range pool {
		totalBytes += int64(len(l))
	}
	avgLen := float64(totalBytes) / float64(len(pool))

	b.ReportAllocs()
	b.SetBytes(int64(avgLen))
	b.ResetTimer()

	workersCount := 4
	stopCh := make(chan struct{})
	cancel := func() {}
	ppTest := newTestPipeProcessor()
	pp := p.newPipeProcessor(workersCount, stopCh, cancel, ppTest)
	brw := newTestBlockResultWriter(workersCount, pp)

	for i := 0; i < b.N; i++ {
		brw.writeRow([]Field{{Name: "_msg", Value: pool[i%len(pool)]}})
	}
	brw.flush()
	if err := pp.flush(); err != nil {
		b.Fatalf("flush failed: %s", err)
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "logs/s")
}

func BenchmarkPipeCluster(b *testing.B) {
	for _, md := range []string{"0.3", "0.5", "0.7"} {
		b.Run("max_dist="+md, func(b *testing.B) {
			benchmarkPipeCluster(b, "cluster max_dist "+md)
		})
	}
}
