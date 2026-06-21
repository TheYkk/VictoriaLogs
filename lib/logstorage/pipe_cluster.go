package logstorage

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/atomicutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/memory"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/prefixfilter"
)

// pipeClusterDefaultMaxDist is the default max distance between log messages in a single cluster.
//
// It matches the default value used by the reference LogMine implementation
// (https://github.com/trungdq88/logmine).
const pipeClusterDefaultMaxDist = 0.6

// pipeClusterDefaultMinMembers is the default minimum number of members in a cluster to be returned.
const pipeClusterDefaultMinMembers = 1

// pipeClusterWildcard is the placeholder shown for tokens, which vary across the cluster members.
const pipeClusterWildcard = "*"

// pipeCluster processes '| cluster ...' pipe.
//
// It implements the LogMine log pattern clustering technique on top of VictoriaLogs:
//
//	https://www.cs.unm.edu/~mueen/Papers/LogMine.pdf
//
// Log messages are masked with collapse_nums (numbers, IPv4, UUID, time, datetime)
// before clustering, so that messages, which differ only by such values, fall into
// the same cluster. The remaining tokens are clustered greedily with a max distance
// threshold. Tokens, which vary across cluster members, are replaced with a wildcard.
type pipeCluster struct {
	// field is the log field to cluster by. Default is _msg.
	field string

	// maxDist is the maximum distance between any two log messages in a single cluster.
	// Lower value produces more granular clusters (more clusters). Range (0.0 .. 1.0].
	maxDist float64

	// maxDistStr is the original string representation of maxDist, used for String().
	maxDistStr string

	// minMembers is the minimum number of members in a cluster to be returned.
	minMembers uint64

	// hitsFieldName is the name of the field with the number of members per cluster.
	hitsFieldName string

	// patternFieldName is the name of the field with the generated pattern per cluster.
	patternFieldName string

	// variables are user-defined named regexps. Substrings matching a variable regexp are
	// replaced with the <name> placeholder before clustering, which reduces the number of
	// clusters. This mirrors the -v option of the reference LogMine CLI.
	variables []clusterVariable
}

// clusterVariable is a user-defined named regexp used to mask matching substrings before clustering.
type clusterVariable struct {
	// name is the variable name. Matching substrings are replaced with placeholder.
	name string

	// reStr is the original regexp string, used for String().
	reStr string

	// re is the compiled regexp.
	re *regexp.Regexp

	// placeholder is "<name>", precomputed once.
	placeholder string
}

func (pc *pipeCluster) String() string {
	s := "cluster"
	if pc.field != "_msg" {
		s += " by (" + quoteTokenIfNeeded(pc.field) + ")"
	}
	s += " max_dist " + pc.maxDistStr
	if pc.minMembers != pipeClusterDefaultMinMembers {
		s += " min_members " + strconv.FormatUint(pc.minMembers, 10)
	}
	if pc.patternFieldName != "pattern" {
		s += " pattern as " + quoteTokenIfNeeded(pc.patternFieldName)
	}
	if pc.hitsFieldName != "hits" {
		s += " hits as " + quoteTokenIfNeeded(pc.hitsFieldName)
	}
	if len(pc.variables) > 0 {
		parts := make([]string, len(pc.variables))
		for i, v := range pc.variables {
			parts[i] = quoteTokenIfNeeded(v.name) + "=" + quoteTokenIfNeeded(v.reStr)
		}
		s += " variables (" + strings.Join(parts, ", ") + ")"
	}
	return s
}

func (pc *pipeCluster) splitToRemoteAndLocal(_ int64) (pipe, []pipe) {
	// Distributed (cluster mode) execution is a map-reduce:
	//   - the remote pipe clusters the logs locally on each vlstorage node and emits the
	//     per-node clusters as (pattern, hits) rows. min_members is forced to 1 there, since
	//     the global per-cluster counts are only known after merging all nodes.
	//   - the local pipe (pipeClusterMerge) runs on vlselect, re-clusters the per-node
	//     patterns into the final set, then applies min_members and the configured output.
	// In single-node mode this split is not used and the pipe runs directly.
	pRemote := *pc
	pRemote.minMembers = pipeClusterDefaultMinMembers

	pLocal := &pipeClusterMerge{
		maxDist:          pc.maxDist,
		minMembers:       pc.minMembers,
		patternFieldName: pc.patternFieldName,
		hitsFieldName:    pc.hitsFieldName,
	}
	return &pRemote, []pipe{pLocal}
}

func (pc *pipeCluster) canLiveTail() bool {
	return false
}

func (pc *pipeCluster) canReturnLastNResults() bool {
	return false
}

func (pc *pipeCluster) isFixedOutputFieldsOrder() bool {
	return true
}

func (pc *pipeCluster) updateNeededFields(pf *prefixfilter.Filter) {
	pf.Reset()
	pf.AddAllowFilter(pc.field)
}

func (pc *pipeCluster) hasFilterInWithQuery() bool {
	return false
}

func (pc *pipeCluster) initFilterInValues(_ *inValuesCache, _ getFieldValuesFunc) (pipe, error) {
	return pc, nil
}

func (pc *pipeCluster) visitSubqueries(_ func(q *Query)) {
	// nothing to do
}

func (pc *pipeCluster) newPipeProcessor(concurrency int, stopCh <-chan struct{}, cancel func(), ppNext pipeProcessor) pipeProcessor {
	maxStateSize := int64(float64(memory.Allowed()) * 0.4)

	pcp := &pipeClusterProcessor{
		pc:     pc,
		stopCh: stopCh,
		cancel: cancel,
		ppNext: ppNext,

		maxStateSize: maxStateSize,
	}
	pcp.shards.Init = func(shard *pipeClusterProcessorShard) {
		shard.pc = pc
		shard.buckets = make(map[int][]*clusterEntry)
	}
	pcp.stateSizeBudget.Store(maxStateSize)

	return pcp
}

// clusterEntry represents a single log pattern cluster.
type clusterEntry struct {
	// repr is the representative (the first member's masked tokens) of the cluster.
	//
	// It is fixed for the lifetime of the cluster and used for distance calculations,
	// matching the LogMine reference implementation. Keeping it fixed avoids the cluster
	// "center" drifting as members are added.
	repr []string

	// pattern is the generalized pattern of the cluster, used for output.
	//
	// Tokens, which vary across cluster members, are wildcards. The pattern may have a
	// different length than repr, since it is built via sequence alignment.
	pattern []patternToken

	// hits is the number of log messages, which belong to this cluster.
	hits uint64
}

// patternToken is a single token of a cluster pattern.
type patternToken struct {
	// value is the token value. It is meaningful only when isWild is false.
	value string

	// isWild is set to true if the token varies across the cluster members.
	isWild bool
}

// sizeBytes returns the approximate size of the cluster entry state in bytes.
func (ce *clusterEntry) sizeBytes() int {
	n := int(unsafeSizeOfClusterEntry)
	for _, s := range ce.repr {
		n += len(s) + int(unsafeSizeOfStringHeader)
	}
	n += patternSizeBytes(ce.pattern)
	return n
}

func patternSizeBytes(pattern []patternToken) int {
	n := 0
	for _, t := range pattern {
		n += len(t.value) + int(unsafeSizeOfPatternToken)
	}
	return n
}

const (
	unsafeSizeOfClusterEntry = 64
	unsafeSizeOfPatternToken = 24
	unsafeSizeOfStringHeader = 16
)

// clusterDistanceRepr returns the LogMine distance between a cluster representative and the
// masked tokens of an incoming log message.
//
// The distance is in range [0.0 .. 1.0], where 0.0 means identical and 1.0 means completely
// different. It is computed positionally over the common prefix, normalized by the longer
// length, which is exactly the LogMine scorer. Differing token counts are allowed and are
// penalized via the longer-length denominator.
func clusterDistanceRepr(repr, tokens []string) float64 {
	la, lb := len(repr), len(tokens)
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
		if repr[i] == tokens[i] {
			matches++
		}
	}
	return 1 - float64(matches)/float64(maxLen)
}

// lengthBucketRange returns the inclusive range of representative token counts, which can
// possibly be within maxDist of a message with tokensLen tokens.
//
// A pair of sequences with lengths a <= b has distance at least 1 - a/b even when every
// common position matches, so only length buckets satisfying min/max >= 1-maxDist need to
// be inspected. This keeps the nearest-cluster search cheap while supporting variable length.
func lengthBucketRange(tokensLen int, maxDist float64, maxLen int) (int, int) {
	oneMinus := 1 - maxDist
	if oneMinus <= 0 {
		return 1, maxLen
	}
	lo := int(math.Ceil(float64(tokensLen) * oneMinus))
	if lo < 1 {
		lo = 1
	}
	hi := int(math.Floor(float64(tokensLen) / oneMinus))
	if hi > maxLen {
		hi = maxLen
	}
	return lo, hi
}

// alignPair is a single column of a sequence alignment. A field set to -1 means a gap.
type alignPair struct {
	i int
	j int
}

const (
	alignMatchScore    = 2
	alignMismatchScore = -1
	alignGapScore      = -1
)

// alignSequences computes a global (Needleman-Wunsch) alignment of two sequences of lengths
// la and lb, where match(i, j) reports whether element i of the first sequence matches
// element j of the second. It returns the aligned columns in order.
func alignSequences(la, lb int, match func(i, j int) bool) []alignPair {
	w := lb + 1
	dp := make([]int, (la+1)*w)
	for j := 1; j <= lb; j++ {
		dp[j] = j * alignGapScore
	}
	for i := 1; i <= la; i++ {
		dp[i*w] = i * alignGapScore
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			diagAdd := alignMismatchScore
			if match(i-1, j-1) {
				diagAdd = alignMatchScore
			}
			best := dp[(i-1)*w+(j-1)] + diagAdd
			if up := dp[(i-1)*w+j] + alignGapScore; up > best {
				best = up
			}
			if left := dp[i*w+(j-1)] + alignGapScore; left > best {
				best = left
			}
			dp[i*w+j] = best
		}
	}

	pairs := make([]alignPair, 0, la+lb)
	i, j := la, lb
	for i > 0 || j > 0 {
		if i > 0 && j > 0 {
			diagAdd := alignMismatchScore
			if match(i-1, j-1) {
				diagAdd = alignMatchScore
			}
			if dp[i*w+j] == dp[(i-1)*w+(j-1)]+diagAdd {
				pairs = append(pairs, alignPair{i - 1, j - 1})
				i--
				j--
				continue
			}
		}
		if i > 0 && dp[i*w+j] == dp[(i-1)*w+j]+alignGapScore {
			pairs = append(pairs, alignPair{i - 1, -1})
			i--
			continue
		}
		pairs = append(pairs, alignPair{-1, j - 1})
		j--
	}
	// reverse pairs into ascending order
	for l, r := 0, len(pairs)-1; l < r; l, r = l+1, r-1 {
		pairs[l], pairs[r] = pairs[r], pairs[l]
	}
	return pairs
}

// mergePatternWithTokens generalizes the cluster pattern with the incoming masked tokens.
//
// When lengths match it is a cheap positional merge. Otherwise the sequences are aligned, so
// inserted/deleted tokens become wildcards instead of shifting every following token.
func mergePatternWithTokens(pattern []patternToken, tokens []string) []patternToken {
	if len(pattern) == len(tokens) {
		for i := range pattern {
			if pattern[i].isWild {
				continue
			}
			if pattern[i].value != tokens[i] {
				pattern[i] = patternToken{isWild: true}
			}
		}
		return pattern
	}

	pairs := alignSequences(len(pattern), len(tokens), func(i, j int) bool {
		return pattern[i].isWild || pattern[i].value == tokens[j]
	})
	out := make([]patternToken, 0, len(pairs))
	for _, p := range pairs {
		switch {
		case p.i < 0 || p.j < 0:
			out = append(out, patternToken{isWild: true})
		case pattern[p.i].isWild || pattern[p.i].value != tokens[p.j]:
			out = append(out, patternToken{isWild: true})
		default:
			out = append(out, pattern[p.i])
		}
	}
	return out
}

// mergePatternWithPattern generalizes pattern a with pattern b (used when merging shards).
func mergePatternWithPattern(a, b []patternToken) []patternToken {
	if len(a) == len(b) {
		for i := range a {
			if a[i].isWild {
				continue
			}
			if b[i].isWild || a[i].value != b[i].value {
				a[i] = patternToken{isWild: true}
			}
		}
		return a
	}

	pairs := alignSequences(len(a), len(b), func(i, j int) bool {
		return a[i].isWild || b[j].isWild || a[i].value == b[j].value
	})
	out := make([]patternToken, 0, len(pairs))
	for _, p := range pairs {
		switch {
		case p.i < 0 || p.j < 0:
			out = append(out, patternToken{isWild: true})
		case a[p.i].isWild || b[p.j].isWild || a[p.i].value != b[p.j].value:
			out = append(out, patternToken{isWild: true})
		default:
			out = append(out, a[p.i])
		}
	}
	return out
}

type pipeClusterProcessor struct {
	pc     *pipeCluster
	stopCh <-chan struct{}
	cancel func()
	ppNext pipeProcessor

	shards atomicutil.Slice[pipeClusterProcessorShard]

	maxStateSize    int64
	stateSizeBudget atomic.Int64
}

type pipeClusterProcessorShard struct {
	// pc points to the parent pipeCluster.
	pc *pipeCluster

	// buckets holds clusters keyed by the number of tokens in their representative.
	//
	// Clusters with similar token counts are inspected together; the length-tolerant
	// search in addTokens allows messages with differing token counts to join the same
	// cluster (variable-length clustering).
	buckets map[int][]*clusterEntry

	// maxLen is the largest representative token count seen by the shard.
	maxLen int

	// tokens is a temporary buffer for the tokens of the currently processed log message.
	tokens []string

	// maskBuf is a temporary buffer for masking log messages via collapse_nums.
	maskBuf []byte

	// stateSizeBudget is the remaining budget for the whole state size for the shard.
	// The per-shard budget is provided in chunks from the parent pipeClusterProcessor.
	stateSizeBudget int
}

// writeBlock clusters the values of the configured field in br into the shard state.
func (shard *pipeClusterProcessorShard) writeBlock(br *blockResult) {
	c := br.getColumnByName(shard.pc.field)
	values := c.getValues(br)

	prevValue := ""
	prevTokens := false
	for rowIdx := 0; rowIdx < len(values); rowIdx++ {
		v := values[rowIdx]
		if prevTokens && v == prevValue {
			// Fast path: identical consecutive value reuses the previously computed tokens.
			shard.addTokens(shard.tokens)
			continue
		}
		shard.tokens = shard.tokenizeMasked(v, shard.tokens[:0])
		shard.addTokens(shard.tokens)
		prevValue = v
		prevTokens = true
	}
}

// tokenizeMasked applies user variables and collapse_nums prettify to v, then splits it into
// tokens by whitespace.
func (shard *pipeClusterProcessorShard) tokenizeMasked(v string, dst []string) []string {
	src := v
	if vars := shard.pc.variables; len(vars) > 0 {
		for _, vr := range vars {
			src = vr.re.ReplaceAllString(src, vr.placeholder)
		}
	}
	shard.maskBuf = appendCollapseNums(shard.maskBuf[:0], src)
	bLen := 0
	shard.maskBuf = appendPrettifyCollapsedNums(shard.maskBuf[:bLen:cap(shard.maskBuf)], shard.maskBuf[bLen:])
	masked := bytesutil.ToUnsafeString(shard.maskBuf)
	return appendWhitespaceTokens(dst, masked)
}

// appendWhitespaceTokens splits s by whitespace and appends the resulting tokens to dst.
func appendWhitespaceTokens(dst []string, s string) []string {
	for {
		// skip leading whitespace
		start := 0
		for start < len(s) && isSpaceByte(s[start]) {
			start++
		}
		if start >= len(s) {
			return dst
		}
		end := start
		for end < len(s) && !isSpaceByte(s[end]) {
			end++
		}
		dst = append(dst, s[start:end])
		s = s[end:]
	}
}

func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// addTokens assigns the given masked tokens to the nearest cluster or creates a new one.
func (shard *pipeClusterProcessorShard) addTokens(tokens []string) {
	n := len(tokens)
	if n == 0 {
		return
	}
	maxDist := shard.pc.maxDist

	// Search clusters in length buckets, which could be within maxDist of tokens.
	lo, hi := lengthBucketRange(n, maxDist, shard.maxLen)
	var best *clusterEntry
	bestDist := maxDist
search:
	for ln := lo; ln <= hi; ln++ {
		for _, ce := range shard.buckets[ln] {
			d := clusterDistanceRepr(ce.repr, tokens)
			if d <= bestDist {
				bestDist = d
				best = ce
				if d == 0 {
					break search
				}
			}
		}
	}

	if best != nil {
		before := patternSizeBytes(best.pattern)
		best.pattern = mergePatternWithTokens(best.pattern, tokens)
		best.hits++
		shard.stateSizeBudget += before - patternSizeBytes(best.pattern)
		return
	}

	// Create a new cluster. Token values must be copied, since the block memory is reused.
	repr := make([]string, n)
	pt := make([]patternToken, n)
	for i, t := range tokens {
		c := strings.Clone(t)
		repr[i] = c
		pt[i] = patternToken{value: c}
	}
	ce := &clusterEntry{
		repr:    repr,
		pattern: pt,
		hits:    1,
	}
	shard.buckets[n] = append(shard.buckets[n], ce)
	if n > shard.maxLen {
		shard.maxLen = n
	}
	shard.stateSizeBudget -= ce.sizeBytes()
}

func (pcp *pipeClusterProcessor) writeBlock(workerID uint, br *blockResult) {
	if br.rowsLen == 0 {
		return
	}

	shard := pcp.shards.Get(workerID)

	for shard.stateSizeBudget < 0 {
		// steal some budget for the state size from the global budget.
		remaining := pcp.stateSizeBudget.Add(-stateSizeBudgetChunk)
		if remaining < 0 {
			// The state size is too big. Stop processing data in order to avoid OOM crash.
			if remaining+stateSizeBudgetChunk >= 0 {
				// Notify worker goroutines to stop calling writeBlock() in order to save CPU time.
				pcp.cancel()
			}
			return
		}
		shard.stateSizeBudget += stateSizeBudgetChunk
	}

	shard.writeBlock(br)
}

func (pcp *pipeClusterProcessor) flush() error {
	if n := pcp.stateSizeBudget.Load(); n <= 0 {
		return fmt.Errorf("cannot calculate [%s], since it requires more than %dMB of memory", pcp.pc.String(), pcp.maxStateSize/(1<<20))
	}

	entries := pcp.mergeShards()
	if needStop(pcp.stopCh) {
		return nil
	}

	// Sort clusters by hits in descending order, with the pattern as a tie-breaker for determinism.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].hits != entries[j].hits {
			return entries[i].hits > entries[j].hits
		}
		return clusterPatternString(entries[i].pattern) < clusterPatternString(entries[j].pattern)
	})

	wctx := &pipeClusterWriteContext{
		ppNext: pcp.ppNext,
	}
	var rowFields []Field
	minMembers := pcp.pc.minMembers
	for _, e := range entries {
		if needStop(pcp.stopCh) {
			return nil
		}
		if e.hits < minMembers {
			continue
		}
		rowFields = append(rowFields[:0],
			Field{
				Name:  pcp.pc.patternFieldName,
				Value: clusterPatternString(e.pattern),
			},
			Field{
				Name:  pcp.pc.hitsFieldName,
				Value: string(marshalUint64String(nil, e.hits)),
			},
		)
		wctx.writeRow(rowFields)
	}
	wctx.flush()

	return nil
}

// mergeShards merges per-worker cluster states into a single set of clusters.
//
// It re-clusters the representative patterns of all shards, which is the hierarchical
// merge step described in the LogMine paper.
func (pcp *pipeClusterProcessor) mergeShards() []*clusterEntry {
	shards := pcp.shards.All()
	if len(shards) == 0 {
		return nil
	}
	if len(shards) == 1 {
		return collectEntries(shards[0].buckets)
	}

	maxDist := pcp.pc.maxDist
	merged := make(map[int][]*clusterEntry)
	mergedMaxLen := 0
	for _, shard := range shards {
		if needStop(pcp.stopCh) {
			return nil
		}
		for _, bucket := range shard.buckets {
			for _, ce := range bucket {
				lo, hi := lengthBucketRange(len(ce.repr), maxDist, mergedMaxLen)
				var best *clusterEntry
				bestDist := maxDist
			search:
				for ln := lo; ln <= hi; ln++ {
					for _, dst := range merged[ln] {
						d := clusterDistanceRepr(dst.repr, ce.repr)
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
					key := len(ce.repr)
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

func collectEntries(buckets map[int][]*clusterEntry) []*clusterEntry {
	var entries []*clusterEntry
	for _, bucket := range buckets {
		entries = append(entries, bucket...)
	}
	return entries
}

// clusterPatternString renders the cluster pattern tokens into a single string.
func clusterPatternString(tokens []patternToken) string {
	var sb strings.Builder
	for i, t := range tokens {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if t.isWild {
			sb.WriteString(pipeClusterWildcard)
		} else {
			sb.WriteString(t.value)
		}
	}
	return sb.String()
}

type pipeClusterWriteContext struct {
	ppNext pipeProcessor
	rcs    []resultColumn
	br     blockResult

	rowsCount int
	valuesLen int
}

func (wctx *pipeClusterWriteContext) writeRow(rowFields []Field) {
	rcs := wctx.rcs

	areEqualColumns := len(rcs) == len(rowFields)
	if areEqualColumns {
		for i, f := range rowFields {
			if rcs[i].name != f.Name {
				areEqualColumns = false
				break
			}
		}
	}
	if !areEqualColumns {
		wctx.flush()

		rcs = wctx.rcs[:0]
		for _, f := range rowFields {
			rcs = appendResultColumnWithName(rcs, f.Name)
		}
		wctx.rcs = rcs
	}

	for i, f := range rowFields {
		v := f.Value
		rcs[i].addValue(v)
		wctx.valuesLen += len(v)
	}

	wctx.rowsCount++
	if wctx.valuesLen >= 64_000 {
		wctx.flush()
	}
}

func (wctx *pipeClusterWriteContext) flush() {
	rcs := wctx.rcs
	br := &wctx.br

	wctx.valuesLen = 0

	br.setResultColumns(rcs, wctx.rowsCount)
	wctx.rowsCount = 0
	wctx.ppNext.writeBlock(0, br)
	br.reset()
	for i := range rcs {
		rcs[i].resetValues()
	}
}

func parsePipeCluster(lex *lexer) (pipe, error) {
	if !lex.isKeyword("cluster", "logmine") {
		return nil, fmt.Errorf("expecting 'cluster'; got %q", lex.token)
	}
	lex.nextToken()

	pc := &pipeCluster{
		field:            "_msg",
		maxDist:          pipeClusterDefaultMaxDist,
		maxDistStr:       strconv.FormatFloat(pipeClusterDefaultMaxDist, 'g', -1, 64),
		minMembers:       pipeClusterDefaultMinMembers,
		hitsFieldName:    "hits",
		patternFieldName: "pattern",
	}

	if lex.isKeyword("by") {
		lex.nextToken()
		if !lex.isKeyword("(") {
			return nil, fmt.Errorf("missing '(' after 'by'")
		}
		fields, err := parseFieldNamesInParens(lex)
		if err != nil {
			return nil, fmt.Errorf("cannot parse 'by(...)': %w", err)
		}
		if len(fields) != 1 {
			return nil, fmt.Errorf("'cluster' supports clustering by a single field; got %d fields", len(fields))
		}
		pc.field = fields[0]
	}

	for {
		switch {
		case lex.isKeyword("max_dist"):
			lex.nextToken()
			f, s, err := parseNumber(lex)
			if err != nil {
				return nil, fmt.Errorf("cannot parse 'max_dist' value: %w", err)
			}
			if f <= 0 || f > 1 {
				return nil, fmt.Errorf("'max_dist' must be in the range (0.0 .. 1.0]; got %s", s)
			}
			pc.maxDist = f
			pc.maxDistStr = s
		case lex.isKeyword("min_members"):
			lex.nextToken()
			f, s, err := parseNumber(lex)
			if err != nil {
				return nil, fmt.Errorf("cannot parse 'min_members' value: %w", err)
			}
			if f < 1 {
				return nil, fmt.Errorf("'min_members' must be an integer bigger than 0; got %s", s)
			}
			pc.minMembers = uint64(f)
		case lex.isKeyword("pattern"):
			lex.nextToken()
			if lex.isKeyword("as") {
				lex.nextToken()
			}
			s, err := lex.nextCompoundToken()
			if err != nil {
				return nil, fmt.Errorf("cannot parse 'pattern' name: %w", err)
			}
			pc.patternFieldName = s
		case lex.isKeyword("hits"):
			lex.nextToken()
			if lex.isKeyword("as") {
				lex.nextToken()
			}
			s, err := lex.nextCompoundToken()
			if err != nil {
				return nil, fmt.Errorf("cannot parse 'hits' name: %w", err)
			}
			pc.hitsFieldName = s
		case lex.isKeyword("variables"):
			vars, err := parseClusterVariables(lex)
			if err != nil {
				return nil, fmt.Errorf("cannot parse 'variables': %w", err)
			}
			pc.variables = vars
		default:
			return pc, nil
		}
	}
}

// parseClusterVariables parses 'variables (name1=regexp1, name2=regexp2, ...)'.
func parseClusterVariables(lex *lexer) ([]clusterVariable, error) {
	if !lex.isKeyword("variables") {
		return nil, fmt.Errorf("expecting 'variables'; got %q", lex.token)
	}
	lex.nextToken()
	if !lex.isKeyword("(") {
		return nil, fmt.Errorf("missing '(' after 'variables'")
	}
	lex.nextToken()

	var vars []clusterVariable
	for {
		if lex.isKeyword(")") {
			return nil, fmt.Errorf("missing variable definition")
		}
		name, err := lex.nextCompoundToken()
		if err != nil {
			return nil, fmt.Errorf("cannot parse variable name: %w", err)
		}
		if !lex.isKeyword("=") {
			return nil, fmt.Errorf("missing '=' after variable name %q", name)
		}
		lex.nextToken()
		reStr, err := lex.nextCompoundToken()
		if err != nil {
			return nil, fmt.Errorf("cannot parse regexp for variable %q: %w", name, err)
		}
		re, err := regexpCompile(reStr)
		if err != nil {
			return nil, fmt.Errorf("cannot compile regexp %q for variable %q: %w", reStr, name, err)
		}
		vars = append(vars, clusterVariable{
			name:        name,
			reStr:       reStr,
			re:          re,
			placeholder: "<" + name + ">",
		})
		switch {
		case lex.isKeyword(","):
			lex.nextToken()
		case lex.isKeyword(")"):
			lex.nextToken()
			return vars, nil
		default:
			return nil, fmt.Errorf("unexpected token %q after variable %q; want ',' or ')'", lex.token, name)
		}
	}
}
