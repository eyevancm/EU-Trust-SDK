package challenge

import (
	"errors"
	"time"

	"github.com/sovereign-trust/sdk/internal/environment"
	"github.com/sovereign-trust/sdk/pkg/api"
)

// ProbeValidator validates a single probe result and returns an anomaly score [0,1].
type ProbeValidator func(probeName, probeValue string) (anomalyScore float64)

// New assembles a ChallengePayload from derived parameters.
func New(params ChallengeParams, temperatureBucket uint8, challengeID string) (api.ChallengePayload, error) {
	hc, err := NewHashCashChallenge(params.HashCashBits)
	if err != nil {
		return api.ChallengePayload{}, err
	}

	a2, err := NewArgon2Challenge(params.Argon2Memory, params.Argon2Iterations)
	if err != nil {
		return api.ChallengePayload{}, err
	}

	probeNames := make([]string, 0, len(params.ProbeIndices))
	for _, idx := range params.ProbeIndices {
		if idx < len(environment.ProbePool) {
			probeNames = append(probeNames, environment.ProbePool[idx])
		}
	}

	return api.ChallengePayload{
		ChallengeID: challengeID,
		HashCash:    hc,
		Argon2:      a2,
		Probes:      probeNames,
		ExpiresAt:   time.Now().Add(120 * time.Second),
	}, nil
}

// Verify checks all solutions in a ChallengeResponse and returns the achieved
// ChallengeClass and an aggregate probe anomaly score [0,1].
func Verify(
	payload api.ChallengePayload,
	resp api.ChallengeResponse,
	validateProbe ProbeValidator,
) (challengeClass uint8, probeAnomalyScore float64, err error) {
	if time.Now().After(payload.ExpiresAt) {
		return 0, 0, errors.New("challenge: expired")
	}
	if resp.ChallengeID != payload.ChallengeID {
		return 0, 0, errors.New("challenge: ID mismatch")
	}

	if payload.HashCash != nil {
		if resp.HashCashSolution == "" {
			return 0, 0, errors.New("challenge: missing hashcash solution")
		}
		if err := VerifyHashCash(payload.HashCash, resp.HashCashSolution); err != nil {
			return 0, 0, err
		}
		challengeClass = 1
	}

	if payload.Argon2 != nil && resp.Argon2Result != "" {
		if err := VerifyArgon2(payload.Argon2, resp.Argon2Result); err != nil {
			return 0, 0, err
		}
		challengeClass = 2
	}

	if len(payload.Probes) > 0 && len(resp.ProbeResults) > 0 {
		totalScore := 0.0
		evaluated := 0
		for _, probeName := range payload.Probes {
			val, ok := resp.ProbeResults[probeName]
			if !ok {
				continue
			}
			if validateProbe != nil {
				totalScore += validateProbe(probeName, val)
				evaluated++
			}
		}
		if evaluated > 0 {
			probeAnomalyScore = totalScore / float64(evaluated)
		}
	}

	return challengeClass, probeAnomalyScore, nil
}
