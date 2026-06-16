package temperature

import "github.com/sovereign-trust/sdk/internal/challenge"

// BucketRanges maps a temperature bucket (0–3) to challenge parameter ranges.
func BucketRanges(bucket uint8) challenge.ParameterRanges {
	switch bucket {
	case 0: // clean: light challenges
		return challenge.ParameterRanges{
			HashCashBitsMin:     16,
			HashCashBitsMax:     18,
			Argon2MemoryMinKiB:  65536,  // 64 MB
			Argon2MemoryMaxKiB:  98304,  // 96 MB
			Argon2IterationsMin: 2,
			Argon2IterationsMax: 3,
			ProbePoolSize:       10,
			ProbeCount:          3,
		}
	case 1: // warm: moderate challenges
		return challenge.ParameterRanges{
			HashCashBitsMin:     18,
			HashCashBitsMax:     20,
			Argon2MemoryMinKiB:  98304,  // 96 MB
			Argon2MemoryMaxKiB:  131072, // 128 MB
			Argon2IterationsMin: 2,
			Argon2IterationsMax: 4,
			ProbePoolSize:       10,
			ProbeCount:          4,
		}
	case 2: // hot: hard challenges
		return challenge.ParameterRanges{
			HashCashBitsMin:     20,
			HashCashBitsMax:     22,
			Argon2MemoryMinKiB:  131072, // 128 MB
			Argon2MemoryMaxKiB:  196608, // 192 MB
			Argon2IterationsMin: 3,
			Argon2IterationsMax: 5,
			ProbePoolSize:       10,
			ProbeCount:          5,
		}
	default: // critical: maximum challenges
		return challenge.ParameterRanges{
			HashCashBitsMin:     22,
			HashCashBitsMax:     22,
			Argon2MemoryMinKiB:  196608, // 192 MB
			Argon2MemoryMaxKiB:  262144, // 256 MB
			Argon2IterationsMin: 4,
			Argon2IterationsMax: 5,
			ProbePoolSize:       10,
			ProbeCount:          5,
		}
	}
}
