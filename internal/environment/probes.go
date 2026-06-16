// Package environment defines the server-side environment probe validation logic.
//
// Environment probes test whether the client is a real browser by measuring
// platform-specific timing characteristics. They fingerprint the PLATFORM,
// not the USER — values vary per software type (browser vs. headless vs. Node),
// not per individual.
package environment

import (
	"strconv"
)

// ProbePool is the ordered list of available probe names.
// The Collatz parameter mapper selects indices into this list.
var ProbePool = []string{
	"webcrypto_timing",
	"dom_computation",
	"memory_allocation",
}

// ProbeSpec defines expected timing ranges for a probe.
type ProbeSpec struct {
	// MinMS is the minimum plausible timing in milliseconds.
	MinMS float64
	// MaxMS is the maximum plausible timing.
	MaxMS float64
	// SuspiciousBelow is the threshold below which the result is highly suspicious.
	SuspiciousBelow float64
}

var probeSpecs = map[string]ProbeSpec{
	// ECDSA key generation: real browsers 5–15ms, headless/server ~0.1ms
	"webcrypto_timing": {MinMS: 0.5, MaxMS: 500, SuspiciousBelow: 1.0},
	// CSS transform + computed layout: requires real layout engine
	"dom_computation": {MinMS: 0.1, MaxMS: 500, SuspiciousBelow: 0.3},
	// ArrayBuffer allocation timing: browser V8 vs Node V8 differ
	"memory_allocation": {MinMS: 0.5, MaxMS: 2000, SuspiciousBelow: 0.2},
}

// Validate checks a probe result and returns an anomaly score [0, 1].
// 0 = looks like a real browser, 1 = certain bot/headless indicator.
// Returns (false, 1.0) for unknown probe names.
func Validate(probeName, value string) (pass bool, anomalyScore float64) {
	spec, ok := probeSpecs[probeName]
	if !ok {
		// Unknown probe — treat as suspicious but not definitive
		return false, 0.5
	}

	ms, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, 1.0
	}

	// Out of plausible range
	if ms < spec.MinMS || ms > spec.MaxMS {
		return false, 0.8
	}

	// Below suspicious threshold — likely headless
	if ms < spec.SuspiciousBelow {
		return false, 0.9
	}

	return true, 0.0
}

// ValidateAll validates all probe results and returns the mean anomaly score.
func ValidateAll(results map[string]string) float64 {
	if len(results) == 0 {
		return 0
	}
	total := 0.0
	for name, val := range results {
		_, score := Validate(name, val)
		total += score
	}
	return total / float64(len(results))
}
