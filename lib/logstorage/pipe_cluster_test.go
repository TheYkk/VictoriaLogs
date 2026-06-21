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
