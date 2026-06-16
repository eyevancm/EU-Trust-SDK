package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// ChallengeParams holds the randomized parameters for a composite challenge.
type ChallengeParams struct {
	HashCashBits     uint8
	Argon2Memory     uint32
	Argon2Iterations uint32
	ProbeIndices     []int
}

// ParameterRanges defines the allowed ranges for challenge parameters
// at a given temperature.
type ParameterRanges struct {
	HashCashBitsMin uint8
	HashCashBitsMax uint8

	Argon2MemoryMinKiB uint32
	Argon2MemoryMaxKiB uint32

	Argon2IterationsMin uint32
	Argon2IterationsMax uint32

	ProbePoolSize int
	ProbeCount    int
}

// GenerateSeed creates an HMAC-SHA256 seed from a server secret and
// per-request inputs (nonce, timestamp, IP hash).
func GenerateSeed(serverSecret, nonce, timestampBytes, ipHash []byte) []byte {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write(nonce)
	mac.Write(timestampBytes)
	mac.Write(ipHash)
	return mac.Sum(nil)
}

// DeriveParams maps a cryptographic seed to challenge parameters using
// direct byte extraction. The seed must be an HMAC-SHA256 output (32 bytes)
// which is already uniformly random — no additional mixing is needed.
func DeriveParams(seed []byte, ranges ParameterRanges) ChallengeParams {
	if len(seed) < 9 {
		return ChallengeParams{
			HashCashBits:     ranges.HashCashBitsMin,
			Argon2Memory:     ranges.Argon2MemoryMinKiB,
			Argon2Iterations: ranges.Argon2IterationsMin,
		}
	}

	hashRange := ranges.HashCashBitsMax - ranges.HashCashBitsMin + 1
	hashBits := ranges.HashCashBitsMin + seed[0]%hashRange

	memRange := ranges.Argon2MemoryMaxKiB - ranges.Argon2MemoryMinKiB + 1
	argon2Mem := ranges.Argon2MemoryMinKiB + binary.BigEndian.Uint32(seed[1:5])%memRange

	iterRange := ranges.Argon2IterationsMax - ranges.Argon2IterationsMin + 1
	argon2Iter := ranges.Argon2IterationsMin + binary.BigEndian.Uint32(seed[5:9])%iterRange

	probeIndices := selectProbes(seed[9:], ranges.ProbePoolSize, ranges.ProbeCount)

	return ChallengeParams{
		HashCashBits:     hashBits,
		Argon2Memory:     argon2Mem,
		Argon2Iterations: argon2Iter,
		ProbeIndices:     probeIndices,
	}
}

func selectProbes(seed []byte, poolSize, count int) []int {
	if poolSize <= 0 || count <= 0 {
		return nil
	}
	if count > poolSize {
		count = poolSize
	}

	selected := make(map[int]bool)
	indices := make([]int, 0, count)

	for i := 0; i < len(seed) && len(indices) < count; i++ {
		idx := int(seed[i]) % poolSize
		if !selected[idx] {
			selected[idx] = true
			indices = append(indices, idx)
		}
	}

	for idx := 0; len(indices) < count && idx < poolSize; idx++ {
		if !selected[idx] {
			indices = append(indices, idx)
		}
	}

	return indices
}
