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
// The parameter mapper selects indices into this list.
var ProbePool = []string{
	"webcrypto_timing",
	"dom_computation",
	"memory_allocation",
	"canvas_timing",
	"audio_latency",
	"font_measurement",
	"animation_frame",
	"intersection_observer",
	"webgl_query",
	"performance_heap",
}

// ProbeSpec defines expected timing ranges for a probe.
type ProbeSpec struct {
	MinMS           float64
	MaxMS           float64
	SuspiciousBelow float64
}

var probeSpecs = map[string]ProbeSpec{
	// ECDSA key generation: real browsers 5–15ms, headless/server ~0.1ms
	"webcrypto_timing": {MinMS: 0.5, MaxMS: 500, SuspiciousBelow: 1.0},
	// CSS transform + computed layout: requires real layout engine
	"dom_computation": {MinMS: 0.1, MaxMS: 500, SuspiciousBelow: 0.3},
	// ArrayBuffer allocation timing: browser V8 vs Node V8 differ
	"memory_allocation": {MinMS: 0.5, MaxMS: 2000, SuspiciousBelow: 0.2},
	// OffscreenCanvas draw + readback: requires GPU pipeline
	"canvas_timing": {MinMS: 0.2, MaxMS: 1000, SuspiciousBelow: 0.1},
	// AudioContext baseLatency: absent or zero in headless
	"audio_latency": {MinMS: 0.0, MaxMS: 500, SuspiciousBelow: -1.0},
	// Measure rendered text width: requires text shaper
	"font_measurement": {MinMS: 0.05, MaxMS: 500, SuspiciousBelow: 0.02},
	// requestAnimationFrame callback jitter: synthetic vsync has zero jitter
	"animation_frame": {MinMS: 1.0, MaxMS: 200, SuspiciousBelow: 0.5},
	// IntersectionObserver callback delay: synchronous in headless
	"intersection_observer": {MinMS: 0.1, MaxMS: 500, SuspiciousBelow: 0.05},
	// WEBGL_debug_renderer_info query timing: stubbed driver is instant
	"webgl_query": {MinMS: 0.05, MaxMS: 500, SuspiciousBelow: 0.02},
	// performance.memory.usedJSHeapSize: absent or 0 in non-Chrome headless
	"performance_heap": {MinMS: 0.0, MaxMS: 1e9, SuspiciousBelow: -1.0},
}

// Validate checks a probe result and returns an anomaly score [0, 1].
// 0 = looks like a real browser, 1 = certain bot/headless indicator.
func Validate(probeName, value string) (pass bool, anomalyScore float64) {
	spec, ok := probeSpecs[probeName]
	if !ok {
		return false, 0.5
	}

	ms, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, 1.0
	}

	// For probes that report a value (not timing), SuspiciousBelow < 0
	// means "absence is suspicious" — check differently
	if spec.SuspiciousBelow < 0 {
		if ms < 0 {
			return false, 0.9
		}
		return true, 0.0
	}

	if ms < spec.MinMS || ms > spec.MaxMS {
		return false, 0.8
	}

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
