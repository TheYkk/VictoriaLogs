package logstorage

import (
	"testing"
)

func TestParsePipeClusterSuccess(t *testing.T) {
	f := func(pipeStr string) {
		t.Helper()
		expectParsePipeSuccess(t, pipeStr)
	}

	f(`cluster max_dist 0.6`)
	f(`cluster max_dist 0.3`)
	f(`cluster by (foo) max_dist 0.6`)
	f(`cluster max_dist 0.5 min_members 3`)
	f(`cluster max_dist 0.5 pattern as p`)
	f(`cluster max_dist 0.5 hits as cnt`)
	f(`cluster by (foo) max_dist 0.5 min_members 2 pattern as p hits as cnt`)
	f(`cluster max_dist 0.5 variables (a=x, b=y)`)
	f(`cluster max_dist 0.5 variables (ip="[0-9.]+")`)
	f(`cluster by (msg) max_dist 0.3 variables (user="/u/[a-z]+", id="[0-9]+")`)
}

func TestParsePipeClusterFailure(t *testing.T) {
	f := func(pipeStr string) {
		t.Helper()
		expectParsePipeFailure(t, pipeStr)
	}

	f(`cluster max_dist`)
	f(`cluster max_dist abc`)
	f(`cluster max_dist 0`)
	f(`cluster max_dist 2`)
	f(`cluster min_members 0`)
	f(`cluster by ()`)
	f(`cluster by (a, b)`)
	f(`cluster foo`)
	f(`cluster max_dist 0.5 variables`)
	f(`cluster max_dist 0.5 variables (`)
	f(`cluster max_dist 0.5 variables ()`)
	f(`cluster max_dist 0.5 variables (a)`)
	f(`cluster max_dist 0.5 variables (a=)`)
	f(`cluster max_dist 0.5 variables (a="(")`)
}

func TestParsePipeClusterLogmineAlias(t *testing.T) {
	lex := newLexer(`logmine max_dist 0.5`, 0)
	p, err := parsePipe(lex)
	if err != nil {
		t.Fatalf("cannot parse logmine alias: %s", err)
	}
	if got, want := p.String(), `cluster max_dist 0.5`; got != want {
		t.Fatalf("unexpected String() for logmine alias; got %q; want %q", got, want)
	}
}

func TestPipeCluster(t *testing.T) {
	f := func(pipeStr string, rows, rowsExpected [][]Field) {
		t.Helper()
		expectPipeResults(t, pipeStr, rows, rowsExpected)
	}

	// Numbers are masked, so messages differing only by numbers fall into the same cluster.
	f(`cluster max_dist 0.6`, [][]Field{
		{
			{"_msg", `request took 12ms`},
		},
		{
			{"_msg", `request took 345ms`},
		},
		{
			{"_msg", `request took 7ms`},
		},
	}, [][]Field{
		{
			{"pattern", `request took <N>ms`},
			{"hits", `3`},
		},
	})

	// Tokens, which vary across members within max_dist, become wildcards.
	f(`cluster max_dist 0.6`, [][]Field{
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /about 200`},
		},
	}, [][]Field{
		{
			{"pattern", `GET * <N>`},
			{"hits", `3`},
		},
	})

	// A low max_dist keeps distinct paths in separate clusters.
	f(`cluster max_dist 0.1`, [][]Field{
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /about 200`},
		},
	}, [][]Field{
		{
			{"pattern", `GET /home <N>`},
			{"hits", `2`},
		},
		{
			{"pattern", `GET /about <N>`},
			{"hits", `1`},
		},
	})

	// min_members filters out small clusters.
	f(`cluster max_dist 0.1 min_members 2`, [][]Field{
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /home 200`},
		},
		{
			{"_msg", `GET /about 200`},
		},
	}, [][]Field{
		{
			{"pattern", `GET /home <N>`},
			{"hits", `2`},
		},
	})

	// Variable-length clustering: messages with different token counts can share a cluster,
	// and the extra trailing token becomes a wildcard.
	f(`cluster max_dist 0.4`, [][]Field{
		{
			{"_msg", `alpha beta`},
		},
		{
			{"_msg", `alpha beta gamma`},
		},
	}, [][]Field{
		{
			{"pattern", `alpha beta *`},
			{"hits", `2`},
		},
	})

	// A low max_dist keeps different-length messages in separate clusters.
	f(`cluster max_dist 0.2`, [][]Field{
		{
			{"_msg", `alpha beta`},
		},
		{
			{"_msg", `alpha beta gamma`},
		},
	}, [][]Field{
		{
			{"pattern", `alpha beta`},
			{"hits", `1`},
		},
		{
			{"pattern", `alpha beta gamma`},
			{"hits", `1`},
		},
	})

	// Mid-sequence insertion is handled by alignment: the inserted token becomes a single
	// wildcard instead of shifting and wildcarding every following token.
	f(`cluster max_dist 0.6`, [][]Field{
		{
			{"_msg", `conn open port done`},
		},
		{
			{"_msg", `conn open retry port done`},
		},
	}, [][]Field{
		{
			{"pattern", `conn open * port done`},
			{"hits", `2`},
		},
	})

	// Clustering can be performed by a non-default field.
	f(`cluster by (log) max_dist 0.4`, [][]Field{
		{
			{"log", `disk sda full`},
		},
		{
			{"log", `disk sdb full`},
		},
	}, [][]Field{
		{
			{"pattern", `disk * full`},
			{"hits", `2`},
		},
	})
}


func TestPipeClusterVariables(t *testing.T) {
	f := func(pipeStr string, rows, rowsExpected [][]Field) {
		t.Helper()
		expectPipeResults(t, pipeStr, rows, rowsExpected)
	}

	// A user variable masks the user path, so messages that differ only by user collapse
	// into a single cluster instead of producing a wildcard.
	f(`cluster max_dist 0.1 variables (user="/u/[a-z]+")`, [][]Field{
		{
			{"_msg", `GET /u/alice 200`},
		},
		{
			{"_msg", `GET /u/bob 200`},
		},
		{
			{"_msg", `GET /u/carol 200`},
		},
	}, [][]Field{
		{
			{"pattern", `GET <user> <N>`},
			{"hits", `3`},
		},
	})
}

// runClusterPipeCollect runs p over rows using the test harness and returns the produced rows.
func runClusterPipeCollect(t *testing.T, p pipe, rows [][]Field) [][]Field {
	t.Helper()

	workersCount := 5
	stopCh := make(chan struct{})
	cancel := func() {}
	ppTest := newTestPipeProcessor()
	pp := p.newPipeProcessor(workersCount, stopCh, cancel, ppTest)

	brw := newTestBlockResultWriter(workersCount, pp)
	for _, row := range rows {
		brw.writeRow(row)
	}
	brw.flush()
	if err := pp.flush(); err != nil {
		t.Fatalf("unexpected error in flush: %s", err)
	}
	return ppTest.resultRows
}

// TestPipeClusterMapReduce verifies the distributed (cluster mode) split: each "node" runs the
// remote pipe locally, then a single local merge pipe reduces the per-node patterns. The result
// must match the single-node clustering.
func TestPipeClusterMapReduce(t *testing.T) {
	f := func(pipeStr string, nodeRows [][][]Field, rowsExpected [][]Field) {
		t.Helper()

		lex := newLexer(pipeStr, 0)
		p, err := parsePipe(lex)
		if err != nil {
			t.Fatalf("cannot parse %q: %s", pipeStr, err)
		}
		pc, ok := p.(*pipeCluster)
		if !ok {
			t.Fatalf("expected *pipeCluster, got %T", p)
		}

		pRemote, psLocal := pc.splitToRemoteAndLocal(0)
		if pRemote == nil || len(psLocal) != 1 {
			t.Fatalf("unexpected split: remote=%v local=%v", pRemote, psLocal)
		}

		// Each node runs the remote pipe over its own rows.
		var intermediate [][]Field
		for _, rows := range nodeRows {
			intermediate = append(intermediate, runClusterPipeCollect(t, pRemote, rows)...)
		}

		// vlselect runs the local merge pipe over all per-node intermediate rows.
		got := runClusterPipeCollect(t, psLocal[0], intermediate)
		assertRowsEqual(t, got, rowsExpected)
	}

	nodeA := [][]Field{
		{{"_msg", `GET /home 200`}},
		{{"_msg", `GET /home 200`}},
	}
	nodeB := [][]Field{
		{{"_msg", `GET /home 200`}},
		{{"_msg", `GET /about 200`}},
	}

	// Same result as clustering all 4 rows on a single node.
	f(`cluster max_dist 0.6`, [][][]Field{nodeA, nodeB}, [][]Field{
		{
			{"pattern", `GET * <N>`},
			{"hits", `4`},
		},
	})

	// min_members is applied only after the global merge (4 >= 3 -> kept).
	f(`cluster max_dist 0.6 min_members 3`, [][][]Field{nodeA, nodeB}, [][]Field{
		{
			{"pattern", `GET * <N>`},
			{"hits", `4`},
		},
	})

	// min_members applied after the global merge (4 < 5 -> dropped).
	f(`cluster max_dist 0.6 min_members 5`, [][][]Field{nodeA, nodeB}, nil)
}
