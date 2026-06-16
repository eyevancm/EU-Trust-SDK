// Package api defines the public data types for the Sovereign Trust SDK.
//
// These types define the contract between client widget, SDK backend,
// and relying party. All other packages communicate through these structures.
package api

import "time"

// --- Metadata for RSAPBSSA tokens ---

// TrustMetadata is the public metadata bound to a Privacy Pass token
// via RSAPBSSA (partially blind RSA signatures). It encodes what the
// client proved during token issuance.
//
// Fields are coarse buckets, not precise values — unlinkability requires
// that many tokens share the same metadata value within a time window.
type TrustMetadata struct {
	// ChallengeClass indicates what the client completed.
	//   0 = minimal (PoW only)
	//   1 = standard (PoW + Argon2)
	//   2 = full (PoW + Argon2 + environment probes)
	//   3 = escalated (full + visible interaction challenge)
	ChallengeClass uint8 `json:"challenge_class"`

	// TemperatureBucket is the abuse score at issuance time.
	//   0 = clean (temperature 0-20)
	//   1 = warm (temperature 21-50)
	//   2 = hot (temperature 51-80)
	//   3 = critical (temperature 81-100)
	TemperatureBucket uint8 `json:"temperature_bucket"`

	// DeviceClass identifies the platform category.
	//   0 = unknown
	//   1 = desktop browser
	//   2 = mobile browser
	DeviceClass uint8 `json:"device_class"`

	// TimeBucket is a coarse time window (hourly bucket).
	// Encoded as hours since Unix epoch, not a precise timestamp.
	TimeBucket uint32 `json:"time_bucket"`
}

// Encode serializes metadata to a deterministic byte slice suitable
// for use as the `info` parameter in RSAPBSSA.
func (m TrustMetadata) Encode() []byte {
	// 7 bytes: 1 + 1 + 1 + 4
	buf := make([]byte, 7)
	buf[0] = m.ChallengeClass
	buf[1] = m.TemperatureBucket
	buf[2] = m.DeviceClass
	buf[3] = byte(m.TimeBucket >> 24)
	buf[4] = byte(m.TimeBucket >> 16)
	buf[5] = byte(m.TimeBucket >> 8)
	buf[6] = byte(m.TimeBucket)
	return buf
}

// DecodeMetadata deserializes metadata from bytes.
func DecodeMetadata(b []byte) (TrustMetadata, error) {
	if len(b) != 7 {
		return TrustMetadata{}, ErrInvalidMetadata
	}
	return TrustMetadata{
		ChallengeClass:    b[0],
		TemperatureBucket: b[1],
		DeviceClass:       b[2],
		TimeBucket: uint32(b[3])<<24 |
			uint32(b[4])<<16 |
			uint32(b[5])<<8 |
			uint32(b[6]),
	}, nil
}

// TimeBucketFromTime returns the hourly bucket for a given time.
func TimeBucketFromTime(t time.Time) uint32 {
	return uint32(t.Unix() / 3600)
}

// --- Challenge payloads (server → client) ---

// ChallengePayload is sent by the server to the client widget.
// It specifies what the client must solve to obtain a token.
type ChallengePayload struct {
	// ChallengeID is a unique identifier for this challenge instance.
	ChallengeID string `json:"challenge_id"`

	// HashCash parameters
	HashCash *HashCashChallenge `json:"hashcash,omitempty"`

	// Argon2 parameters
	Argon2 *Argon2Challenge `json:"argon2,omitempty"`

	// EnvironmentProbes to execute
	Probes []string `json:"probes,omitempty"`

	// ExpiresAt is when this challenge becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`
}

// HashCashChallenge defines a SHA-256 partial preimage puzzle.
type HashCashChallenge struct {
	// Nonce is the server-provided random value the client hashes against.
	Nonce string `json:"nonce"`

	// DifficultyBits is the number of leading zero bits required.
	DifficultyBits uint8 `json:"difficulty_bits"`
}

// Argon2Challenge defines a memory-hard challenge.
type Argon2Challenge struct {
	// Nonce is the server-provided random value.
	Nonce string `json:"nonce"`

	// Memory in KiB (e.g. 65536 = 64 MB).
	Memory uint32 `json:"memory"`

	// Iterations (time cost).
	Iterations uint32 `json:"iterations"`

	// Parallelism (threads).
	Parallelism uint8 `json:"parallelism"`

	// KeyLength is the output hash length in bytes.
	KeyLength uint32 `json:"key_length"`
}

// --- Challenge response (client → server) ---

// ChallengeResponse is sent by the client after solving the challenge.
type ChallengeResponse struct {
	// ChallengeID matches the ChallengePayload.ChallengeID.
	ChallengeID string `json:"challenge_id"`

	// HashCashSolution is the nonce suffix that produces the required hash.
	HashCashSolution string `json:"hashcash_solution,omitempty"`

	// Argon2Result is the Argon2 output hash (hex-encoded).
	Argon2Result string `json:"argon2_result,omitempty"`

	// ProbeResults maps probe name → result value.
	ProbeResults map[string]string `json:"probe_results,omitempty"`
}

// --- Token verification (relying party → server) ---

// SiteVerifyRequest is sent by the relying party to verify a token.
type SiteVerifyRequest struct {
	// Token is the base64-encoded RSAPBSSA token from the client.
	Token string `json:"token"`

	// Secret is the relying party's secret key (site secret).
	Secret string `json:"secret"`
}

// SiteVerifyResponse is the server's response to a verification request.
type SiteVerifyResponse struct {
	// Success indicates whether the token is valid.
	Success bool `json:"success"`

	// Timestamp is when the token was issued (coarse, hourly bucket).
	Timestamp string `json:"timestamp,omitempty"`

	// Hostname is the site the token was issued for.
	Hostname string `json:"hostname,omitempty"`

	// ChallengeClass indicates what the client proved (0-3).
	ChallengeClass uint8 `json:"challenge_class,omitempty"`

	// TemperatureBucket indicates abuse context at issuance (0-3).
	TemperatureBucket uint8 `json:"temperature_bucket,omitempty"`

	// ErrorCodes lists any issues encountered.
	ErrorCodes []string `json:"error_codes,omitempty"`
}

// --- Errors ---

var (
	ErrInvalidMetadata = apiError("invalid metadata encoding")
)

type apiError string

func (e apiError) Error() string { return string(e) }
