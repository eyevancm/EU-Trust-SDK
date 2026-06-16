package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sovereign-trust/sdk/pkg/api"
)

var ErrHashCashFailed = errors.New("challenge: hashcash solution invalid")

// NewHashCashChallenge generates a fresh HashCash challenge with a random nonce.
func NewHashCashChallenge(difficultyBits uint8) (*api.HashCashChallenge, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &api.HashCashChallenge{
		Nonce:          hex.EncodeToString(nonce),
		DifficultyBits: difficultyBits,
	}, nil
}

// VerifyHashCash checks that SHA-256(nonceBytes || solutionBytes) has the
// required number of leading zero bits. solution is a hex-encoded uint64.
func VerifyHashCash(ch *api.HashCashChallenge, solution string) error {
	nonceBytes, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("challenge: invalid nonce: %w", err)
	}

	solBytes, err := hex.DecodeString(solution)
	if err != nil || len(solBytes) != 8 {
		return ErrHashCashFailed
	}
	counter := binary.BigEndian.Uint64(solBytes)

	if !checkHashCash(nonceBytes, counter, ch.DifficultyBits) {
		return ErrHashCashFailed
	}
	return nil
}

func checkHashCash(nonce []byte, counter uint64, diffBits uint8) bool {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	h := sha256.New()
	h.Write(nonce)
	h.Write(counterBytes[:])
	digest := h.Sum(nil)

	return countLeadingZeroBits(digest) >= int(diffBits)
}

func countLeadingZeroBits(b []byte) int {
	count := 0
	for _, byte_ := range b {
		if byte_ == 0 {
			count += 8
		} else {
			for mask := byte(0x80); mask != 0; mask >>= 1 {
				if byte_&mask != 0 {
					return count
				}
				count++
			}
			return count
		}
	}
	return count
}
