package logstorage

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/atomicutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/memory"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/prefixfilter"
)

// pipeClusterMerge is the local (reduce) stage of the distributed cluster pipe.
//
// In cluster mode the cluster pipe is split into:
//   - a remote pipe (pipeCluster) running on each vlstorage node, which emits per-node
//     clusters as (pattern, hits) rows;
//   - this pipe running on vlselect, which re-clusters the per-node patterns into the final
//     set and applies min_members.
//
// It is never parsed from a query string: it is constructed by pipeCluster.splitToRemoteAndLocal
// and executed in-process, so it does not need to be registered with a parser.
type pipeClusterMerge struct {
	maxDist          float64
	minMembers       uint64
	patternFieldName string
	hitsFieldName    string
}

func (pm *pipeClusterMerge) String() string {
	return fmt.Sprintf("cluster_merge max_dist %s min_members %d pattern %s hits %s",
		strconv.FormatFloat(pm.maxDist, 'g', -1, 64), pm.minMembers,
		quoteTokenIfNeeded(pm.patternFieldName), quoteTokenIfNeeded(pm.hitsFieldName))
}

func (pm *pipeClusterMerge) splitToRemoteAndLocal(_ int64) (pipe, []pipe) {
	return nil, []pipe{pm}
}

func (pm *pipeClusterMerge) canLiveTail() bool {
	return false
}

func (pm *pipeClusterMerge) canReturnLastNResults() bool {
	return false
}

func (pm *pipeClusterMerge) isFixedOutputFieldsOrder() bool {
	return true
}

func (pm *pipeClusterMerge) updateNeededFields(pf *prefixfilter.Filter) {
	pf.Reset()
	pf.AddAllowFilter(pm.patternFieldName)
	pf.AddAllowFilter(pm.hitsFieldName)
}

func (pm *pipeClusterMerge) hasFilterInWithQuery() bool {
	return false
}

func (pm *pipeClusterMerge) initFilterInValues(_ *inValuesCache, _ getFieldValuesFunc) (pipe, error) {
	return pm, nil
}

func (pm *pipeClusterMerge) visitSubqueries(_ func(q *Query)) {
	// nothing to do
}

func (pm *pipeClusterMerge) newPipeProcessor(concurrency int, stopCh <-chan struct{}, cancel func(), ppNext pipeProcessor) pipeProcessor {
	maxStateSize := int64(float64(memory.Allowed()) * 0.4)

	pmp := &pipeClusterMergeProcessor{
		pm:     pm,
		stopCh: stopCh,
		cancel: cancel,
		ppNext: ppNext,

		maxStateSize: maxStateSize,
	}
	pmp.shards.Init = func(shard *pipeClusterMergeProcessorShard) {
		shard.pm = pm
		shard.buckets = make(map[int][]*clusterEntry)
	}
	pmp.stateSizeBudget.Store(maxStateSize)

	return pmp
}

type pipeClusterMergeProcessor struct {
	pm     *pipeClusterMerge
	stopCh <-chan struct{}
	cancel func()
	ppNext pipeProcessor

	shards atomicutil.Slice[pipeClusterMergeProcessorShard]

	maxStateSize    int64
	stateSizeBudget atomic.Int64
}

type pipeClusterMergeProcessorShard struct {
	pm *pipeClusterMerge

	// buckets holds merged clusters keyed by the number of tokens in their pattern.
	buckets map[int][]*clusterEntry

	// maxLen is the largest pattern token count seen by the shard.
	maxLen int

	stateSizeBudget int
}

func (shard *pipeClusterMergeProcessorShard) writeBlock(br *blockResult) {
	cPattern := br.getColumnByName(shard.pm.patternFieldName)
	cHits := br.getColumnByName(shard.pm.hitsFieldName)
	patterns := cPattern.getValues(br)
	hitsValues := cHits.getValues(br)

	for rowIdx := 0; rowIdx < len(patterns); rowIdx++ {
		hits, err := strconv.ParseUint(strings.TrimSpace(hitsValues[rowIdx]), 10, 64)
		if err != nil || hits == 0 {
			continue
		}
		tokens := parsePatternTokens(patterns[rowIdx])
		if len(tokens) == 0 {
			continue
		}
		shard.addEntry(&clusterEntry{pattern: tokens, hits: hits})
	}
}

// addEntry merges the given cluster entry into the shard buckets using pattern-based distance.
func (shard *pipeClusterMergeProcessorShard) addEntry(entry *clusterEntry) {
	n := len(entry.pattern)
	maxDist := shard.pm.maxDist

	lo, hi := lengthBucketRange(n, maxDist, shard.maxLen)
	var best *clusterEntry
	bestDist := maxDist
search:
	for ln := lo; ln <= hi; ln++ {
		for _, dst := range shard.buckets[ln] {
			d := clusterDistancePatterns(dst.pattern, entry.pattern)
			if d <= bestDist {
				bestDist = d
				best = dst
				if d == 0 {
					break search
				}
			}
		}
	}

	if best != nil {
		before := patternSizeBytes(best.pattern)
		best.pattern = mergePatternWithPattern(best.pattern, entry.pattern)
		best.hits += entry.hits
		shard.stateSizeBudget += before - patternSizeBytes(best.pattern)
		return
	}

	shard.buckets[n] = append(shard.buckets[n], entry)
	if n > shard.maxLen {
		shard.maxLen = n
	}
	shard.stateSizeBudget -= patternSizeBytes(entry.pattern) + int(unsafeSizeOfClusterEntry)
}

func (pmp *pipeClusterMergeProcessor) writeBlock(workerID uint, br *blockResult) {
	if br.rowsLen == 0 {
		return
	}

	shard := pmp.shards.Get(workerID)

	for shard.stateSizeBudget < 0 {
		remaining := pmp.stateSizeBudget.Add(-stateSizeBudgetChunk)
		if remaining < 0 {
			if remaining+stateSizeBudgetChunk >= 0 {
				pmp.cancel()
			}
			return
		}
		shard.stateSizeBudget += stateSizeBudgetChunk
	}

	shard.writeBlock(br)
}

func (pmp *pipeClusterMergeProcessor) flush() error {
	if n := pmp.stateSizeBudget.Load(); n <= 0 {
		return fmt.Errorf("cannot calculate [%s], since it requires more than %dMB of memory", pmp.pm.String(), pmp.maxStateSize/(1<<20))
	}

	entries := pmp.mergeShards()
	if needStop(pmp.stopCh) {
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].hits != entries[j].hits {
			return entries[i].hits > entries[j].hits
		}
		return clusterPatternString(entries[i].pattern) < clusterPatternString(entries[j].pattern)
	})

	wctx := &pipeClusterWriteContext{
		ppNext: pmp.ppNext,
	}
	var rowFields []Field
	minMembers := pmp.pm.minMembers
	for _, e := range entries {
		if needStop(pmp.stopCh) {
			return nil
		}
		if e.hits < minMembers {
			continue
		}
		rowFields = append(rowFields[:0],
			Field{
				Name:  pmp.pm.patternFieldName,
				Value: clusterPatternString(e.pattern),
			},
			Field{
				Name:  pmp.pm.hitsFieldName,
				Value: string(marshalUint64String(nil, e.hits)),
			},
		)
		wctx.writeRow(rowFields)
	}
	wctx.flush()

	return nil
}

// mergeShards merges per-worker merge states into a single set of clusters.
func (pmp *pipeClusterMergeProcessor) mergeShards() []*clusterEntry {
	shards := pmp.shards.All()
	if len(shards) == 0 {
		return nil
	}
	if len(shards) == 1 {
		return collectEntries(shards[0].buckets)
	}

	maxDist := pmp.pm.maxDist
	merged := make(map[int][]*clusterEntry)
	mergedMaxLen := 0
	for _, shard := range shards {
		if needStop(pmp.stopCh) {
			return nil
		}
		for _, bucket := range shard.buckets {
			for _, ce := range bucket {
				lo, hi := lengthBucketRange(len(ce.pattern), maxDist, mergedMaxLen)
				var best *clusterEntry
				bestDist := maxDist
			search:
				for ln := lo; ln <= hi; ln++ {
					for _, dst := range merged[ln] {
						d := clusterDistancePatterns(dst.pattern, ce.pattern)
						if d <= bestDist {
							bestDist = d
							best = dst
							if d == 0 {
								break search
							}
						}
					}
				}
				if best != nil {
					best.pattern = mergePatternWithPattern(best.pattern, ce.pattern)
					best.hits += ce.hits
				} else {
					key := len(ce.pattern)
					merged[key] = append(merged[key], ce)
					if key > mergedMaxLen {
						mergedMaxLen = key
					}
				}
			}
		}
	}
	return collectEntries(merged)
}

// clusterDistancePatterns returns the distance between two patterns, where a wildcard token
// matches anything. It is used to re-cluster per-node patterns during the distributed reduce.
func clusterDistancePatterns(a, b []patternToken) float64 {
	la, lb := len(a), len(b)
	maxLen := la
	minLen := lb
	if lb > maxLen {
		maxLen = lb
		minLen = la
	}
	if maxLen == 0 {
		return 0
	}
	matches := 0
	for i := 0; i < minLen; i++ {
		if a[i].isWild || b[i].isWild || a[i].value == b[i].value {
			matches++
		}
	}
	return 1 - float64(matches)/float64(maxLen)
}

// parsePatternTokens parses a pattern string (tokens joined by spaces, wildcards rendered as
// the wildcard placeholder) back into pattern tokens. Token values are copied, since the
// underlying block memory is reused.
func parsePatternTokens(s string) []patternToken {
	fields := appendWhitespaceTokens(nil, s)
	if len(fields) == 0 {
		return nil
	}
	out := make([]patternToken, len(fields))
	for i, f := range fields {
		if f == pipeClusterWildcard {
			out[i] = patternToken{isWild: true}
		} else {
			out[i] = patternToken{value: bytesutil.ToUnsafeString(append([]byte(nil), f...))}
		}
	}
	return out
}
