package environment

import "testing"

func TestProbePoolSize(t *testing.T) {
	if len(ProbePool) < 8 {
		t.Errorf("ProbePool has %d probes, want at least 8 for meaningful rotation", len(ProbePool))
	}
	if len(ProbePool) != len(probeSpecs) {
		t.Errorf("ProbePool has %d entries but probeSpecs has %d — every probe needs a spec", len(ProbePool), len(probeSpecs))
	}
	for _, name := range ProbePool {
		if _, ok := probeSpecs[name]; !ok {
			t.Errorf("probe %q in ProbePool has no entry in probeSpecs", name)
		}
	}
}

func TestValidate_PlausibleValues(t *testing.T) {
	tests := []struct {
		probe string
		value string
		want  bool
	}{
		{"webcrypto_timing", "8.5", true},
		{"webcrypto_timing", "0.01", false},
		{"dom_computation", "3.2", true},
		{"dom_computation", "0.01", false},
		{"memory_allocation", "1.5", true},
		{"canvas_timing", "5.0", true},
		{"canvas_timing", "0.01", false},
		{"audio_latency", "5.3", true},
		{"audio_latency", "-1", false},
		{"font_measurement", "2.1", true},
		{"font_measurement", "0.001", false},
		{"animation_frame", "16.7", true},
		{"animation_frame", "0.1", false},
		{"intersection_observer", "1.5", true},
		{"intersection_observer", "0.01", false},
		{"webgl_query", "0.5", true},
		{"webgl_query", "0.001", false},
		{"performance_heap", "15000000", true},
		{"performance_heap", "-1", false},
	}

	for _, tt := range tests {
		pass, score := Validate(tt.probe, tt.value)
		if pass != tt.want {
			t.Errorf("Validate(%q, %q) pass=%v score=%.1f, want pass=%v", tt.probe, tt.value, pass, score, tt.want)
		}
	}
}

func TestValidate_UnknownProbe(t *testing.T) {
	pass, score := Validate("nonexistent_probe", "5.0")
	if pass {
		t.Error("unknown probe should not pass")
	}
	if score != 0.5 {
		t.Errorf("unknown probe score = %.1f, want 0.5", score)
	}
}

func TestValidate_InvalidValue(t *testing.T) {
	pass, score := Validate("webcrypto_timing", "not_a_number")
	if pass {
		t.Error("invalid value should not pass")
	}
	if score != 1.0 {
		t.Errorf("invalid value score = %.1f, want 1.0", score)
	}
}

func TestValidateAll(t *testing.T) {
	results := map[string]string{
		"webcrypto_timing": "8.5",
		"dom_computation":  "3.2",
		"canvas_timing":    "5.0",
	}
	score := ValidateAll(results)
	if score != 0.0 {
		t.Errorf("all-plausible results: score = %.2f, want 0.0", score)
	}

	mixed := map[string]string{
		"webcrypto_timing": "8.5",
		"dom_computation":  "0.01",
	}
	score = ValidateAll(mixed)
	if score < 0.3 || score > 0.6 {
		t.Errorf("mixed results: score = %.2f, want ~0.45", score)
	}
}
