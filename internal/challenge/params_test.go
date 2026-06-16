package challenge

import (
	"fmt"
	"testing"
)

func TestDeriveParams_WithinRanges(t *testing.T) {
	ranges := ParameterRanges{
		HashCashBitsMin:     16,
		HashCashBitsMax:     22,
		Argon2MemoryMinKiB:  65536,
		Argon2MemoryMaxKiB:  131072,
		Argon2IterationsMin: 2,
		Argon2IterationsMax: 5,
		ProbePoolSize:       10,
		ProbeCount:          3,
	}

	for i := 0; i < 1000; i++ {
		seed := GenerateSeed(
			[]byte("secret"),
			[]byte(fmt.Sprintf("nonce-%d", i)),
			[]byte("timestamp"),
			[]byte("iphash"),
		)
		params := DeriveParams(seed, ranges)

		if params.HashCashBits < ranges.HashCashBitsMin || params.HashCashBits > ranges.HashCashBitsMax {
			t.Errorf("HashCashBits %d outside [%d, %d]", params.HashCashBits, ranges.HashCashBitsMin, ranges.HashCashBitsMax)
		}
		if params.Argon2Memory < ranges.Argon2MemoryMinKiB || params.Argon2Memory > ranges.Argon2MemoryMaxKiB {
			t.Errorf("Argon2Memory %d outside [%d, %d]", params.Argon2Memory, ranges.Argon2MemoryMinKiB, ranges.Argon2MemoryMaxKiB)
		}
		if params.Argon2Iterations < ranges.Argon2IterationsMin || params.Argon2Iterations > ranges.Argon2IterationsMax {
			t.Errorf("Argon2Iterations %d outside [%d, %d]", params.Argon2Iterations, ranges.Argon2IterationsMin, ranges.Argon2IterationsMax)
		}
		if len(params.ProbeIndices) != ranges.ProbeCount {
			t.Errorf("ProbeIndices length %d, want %d", len(params.ProbeIndices), ranges.ProbeCount)
		}
		for _, idx := range params.ProbeIndices {
			if idx < 0 || idx >= ranges.ProbePoolSize {
				t.Errorf("probe index %d outside [0, %d)", idx, ranges.ProbePoolSize)
			}
		}
	}
}

func TestDeriveParams_Deterministic(t *testing.T) {
	ranges := ParameterRanges{
		HashCashBitsMin:     16,
		HashCashBitsMax:     22,
		Argon2MemoryMinKiB:  65536,
		Argon2MemoryMaxKiB:  131072,
		Argon2IterationsMin: 2,
		Argon2IterationsMax: 5,
		ProbePoolSize:       10,
		ProbeCount:          3,
	}

	seed := GenerateSeed([]byte("secret"), []byte("nonce"), []byte("ts"), []byte("ip"))
	a := DeriveParams(seed, ranges)
	b := DeriveParams(seed, ranges)

	if a.HashCashBits != b.HashCashBits || a.Argon2Memory != b.Argon2Memory || a.Argon2Iterations != b.Argon2Iterations {
		t.Error("same seed produced different parameters")
	}
}

func TestDeriveParams_Variation(t *testing.T) {
	ranges := ParameterRanges{
		HashCashBitsMin:     16,
		HashCashBitsMax:     22,
		Argon2MemoryMinKiB:  65536,
		Argon2MemoryMaxKiB:  131072,
		Argon2IterationsMin: 2,
		Argon2IterationsMax: 5,
		ProbePoolSize:       10,
		ProbeCount:          3,
	}

	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		seed := GenerateSeed([]byte("secret"), []byte(fmt.Sprintf("nonce-%d", i)), []byte("ts"), []byte("ip"))
		p := DeriveParams(seed, ranges)
		key := fmt.Sprintf("%d-%d-%d", p.HashCashBits, p.Argon2Memory, p.Argon2Iterations)
		seen[key]++
	}

	if len(seen) < 5 {
		t.Errorf("only %d distinct parameter combos from 100 seeds", len(seen))
	}
	t.Logf("%d distinct parameter combinations from 100 seeds", len(seen))
}

func TestDeriveParams_ShortSeed(t *testing.T) {
	ranges := ParameterRanges{
		HashCashBitsMin:     16,
		HashCashBitsMax:     22,
		Argon2MemoryMinKiB:  65536,
		Argon2MemoryMaxKiB:  131072,
		Argon2IterationsMin: 2,
		Argon2IterationsMax: 5,
	}

	p := DeriveParams([]byte{0x01}, ranges)
	if p.HashCashBits != ranges.HashCashBitsMin {
		t.Errorf("short seed: HashCashBits = %d, want min %d", p.HashCashBits, ranges.HashCashBitsMin)
	}
}

func TestGenerateSeed_Length(t *testing.T) {
	seed := GenerateSeed([]byte("secret"), []byte("nonce"), []byte("ts"), []byte("ip"))
	if len(seed) != 32 {
		t.Errorf("seed length = %d, want 32", len(seed))
	}
}
