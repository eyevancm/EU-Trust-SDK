package challenge

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sovereign-trust/sdk/pkg/api"
	"golang.org/x/crypto/argon2"
)

var ErrArgon2Failed = errors.New("challenge: argon2 result invalid")

// NewArgon2Challenge generates a fresh Argon2 challenge with a random nonce.
func NewArgon2Challenge(memoryKiB, iterations uint32) (*api.Argon2Challenge, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &api.Argon2Challenge{
		Nonce:       hex.EncodeToString(nonce),
		Memory:      memoryKiB,
		Iterations:  iterations,
		Parallelism: 1,
		KeyLength:   32,
	}, nil
}

// VerifyArgon2 recomputes Argon2id and checks it against the client's result.
func VerifyArgon2(ch *api.Argon2Challenge, result string) error {
	nonceBytes, err := hex.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("challenge: invalid nonce: %w", err)
	}

	expected := argon2.IDKey(
		[]byte("sovereign-trust-challenge"),
		nonceBytes,
		ch.Iterations,
		ch.Memory,
		ch.Parallelism,
		ch.KeyLength,
	)

	got, err := hex.DecodeString(result)
	if err != nil {
		return ErrArgon2Failed
	}

	if len(got) != int(ch.KeyLength) {
		return ErrArgon2Failed
	}

	diff := byte(0)
	for i := range expected {
		diff |= expected[i] ^ got[i]
	}
	if diff != 0 {
		return ErrArgon2Failed
	}
	return nil
}
