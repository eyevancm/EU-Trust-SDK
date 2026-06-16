package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sovereign-trust/sdk/internal/rsapbssa"
	"github.com/sovereign-trust/sdk/pkg/api"
	"golang.org/x/crypto/argon2"
)

func testServer(t *testing.T) (*server, *http.ServeMux) {
	t.Helper()
	kp := loadDevKey()
	srv := newServer(kp)
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", srv.handleChallenge)
	mux.HandleFunc("/verify", srv.handleVerify)
	mux.HandleFunc("/siteverify", srv.handleSiteverify)
	return srv, mux
}

// TestFullRoundTrip exercises the complete protocol:
//
//	GET /challenge → solve HashCash + Argon2 → blind nonce →
//	POST /verify → unblind → assemble token →
//	POST /siteverify → success with metadata
func TestFullRoundTrip(t *testing.T) {
	_, mux := testServer(t)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// --- Step 1: GET /challenge ---
	challengeResp, err := http.Get(ts.URL + "/challenge?sitekey=sk_test_sovereign")
	if err != nil {
		t.Fatalf("GET /challenge: %v", err)
	}
	defer challengeResp.Body.Close()
	if challengeResp.StatusCode != 200 {
		t.Fatalf("GET /challenge: status %d", challengeResp.StatusCode)
	}

	// Verify Cache-Control header
	if cc := challengeResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}

	var challenge struct {
		api.ChallengePayload
		ServerPublicKey struct {
			N string `json:"n"`
			E int    `json:"e"`
		} `json:"server_public_key"`
		PredictedMetadata string `json:"predicted_metadata"`
	}
	if err := json.NewDecoder(challengeResp.Body).Decode(&challenge); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	t.Logf("challenge_id=%s hashcash_bits=%d argon2_mem=%d probes=%v",
		challenge.ChallengeID,
		challenge.HashCash.DifficultyBits,
		challenge.Argon2.Memory,
		challenge.Probes)

	// --- Step 2: Solve challenges ---

	nonceBytes, _ := hex.DecodeString(challenge.HashCash.Nonce)
	hashcashSolution := solveHashCashGo(nonceBytes, challenge.HashCash.DifficultyBits)
	t.Logf("hashcash solved: counter=%s", hashcashSolution)

	argon2Nonce, _ := hex.DecodeString(challenge.Argon2.Nonce)
	argon2Result := hex.EncodeToString(argon2.IDKey(
		[]byte("sovereign-trust-challenge"),
		argon2Nonce,
		challenge.Argon2.Iterations,
		challenge.Argon2.Memory,
		challenge.Argon2.Parallelism,
		challenge.Argon2.KeyLength,
	))
	t.Logf("argon2 solved: %s...%s", argon2Result[:8], argon2Result[len(argon2Result)-8:])

	probeResults := map[string]string{}
	for _, name := range challenge.Probes {
		probeResults[name] = "8.5"
	}

	// --- Step 3: Blind a nonce with predicted metadata ---
	nonce := make([]byte, 8)
	rand.Read(nonce)

	predictedMetaBytes, err := base64.StdEncoding.DecodeString(challenge.PredictedMetadata)
	if err != nil {
		t.Fatalf("decode predicted metadata: %v", err)
	}

	nBytes, _ := base64.StdEncoding.DecodeString(challenge.ServerPublicKey.N)
	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: challenge.ServerPublicKey.E,
	}

	blindedMsg, inv, err := rsapbssa.Blind(nil, pk, nonce, predictedMetaBytes, nil)
	if err != nil {
		t.Fatalf("Blind: %v", err)
	}

	// --- Step 4: POST /verify ---
	verifyBody := map[string]any{
		"challenge_id":      challenge.ChallengeID,
		"hashcash_solution": hashcashSolution,
		"argon2_result":     argon2Result,
		"probe_results":     probeResults,
		"blinded_message":   base64.StdEncoding.EncodeToString(blindedMsg.BlindedMsg),
		"device_class":      1,
	}
	bodyJSON, _ := json.Marshal(verifyBody)

	verifyResp, err := http.Post(ts.URL+"/verify?sitekey=sk_test_sovereign", "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		t.Fatalf("POST /verify: %v", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != 200 {
		var errBody bytes.Buffer
		errBody.ReadFrom(verifyResp.Body)
		t.Fatalf("POST /verify: status %d: %s", verifyResp.StatusCode, errBody.String())
	}

	var vr verifyResponse
	if err := json.NewDecoder(verifyResp.Body).Decode(&vr); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}

	blindSigBytes, _ := base64.StdEncoding.DecodeString(vr.BlindSignature)
	metaBytes, _ := base64.StdEncoding.DecodeString(vr.Metadata)
	t.Logf("blind signature received (%d bytes), metadata=%x", len(blindSigBytes), metaBytes)

	// --- Step 5: Unblind → final signature ---
	sig, err := rsapbssa.Finalize(pk, nonce, metaBytes, rsapbssa.BlindSignature{BlindSig: blindSigBytes}, inv)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	t.Logf("unblinded signature: %x...%x", sig[:4], sig[len(sig)-4:])

	// --- Step 6: Assemble token and POST /siteverify ---
	tokenBytes := make([]byte, 0, len(sig)+len(metaBytes)+len(nonce))
	tokenBytes = append(tokenBytes, sig...)
	tokenBytes = append(tokenBytes, metaBytes...)
	tokenBytes = append(tokenBytes, nonce...)
	token := base64.StdEncoding.EncodeToString(tokenBytes)

	svBody, _ := json.Marshal(api.SiteVerifyRequest{
		Token:  token,
		Secret: "sk_test_sovereign",
	})
	svResp, err := http.Post(ts.URL+"/siteverify", "application/json", bytes.NewReader(svBody))
	if err != nil {
		t.Fatalf("POST /siteverify: %v", err)
	}
	defer svResp.Body.Close()

	var sv api.SiteVerifyResponse
	if err := json.NewDecoder(svResp.Body).Decode(&sv); err != nil {
		t.Fatalf("decode siteverify response: %v", err)
	}

	if !sv.Success {
		t.Fatalf("siteverify failed: %v", sv.ErrorCodes)
	}

	t.Logf("siteverify success: challenge_class=%d temperature_bucket=%d",
		sv.ChallengeClass, sv.TemperatureBucket)

	if sv.ChallengeClass < 1 {
		t.Errorf("expected challenge_class >= 1, got %d", sv.ChallengeClass)
	}

	// --- Step 7: Replay protection — same token must fail ---
	svResp2, _ := http.Post(ts.URL+"/siteverify", "application/json",
		bytes.NewReader(svBody))
	defer svResp2.Body.Close()

	var sv2 api.SiteVerifyResponse
	json.NewDecoder(svResp2.Body).Decode(&sv2)
	if sv2.Success {
		t.Error("replay: expected failure on second verification of same token")
	}
	if len(sv2.ErrorCodes) == 0 || sv2.ErrorCodes[0] != "timeout-or-duplicate" {
		t.Errorf("replay: expected timeout-or-duplicate error, got %v", sv2.ErrorCodes)
	}
	t.Log("replay protection confirmed")
}

// TestSiteverify_WrongSecret verifies that an invalid secret is rejected.
func TestSiteverify_WrongSecret(t *testing.T) {
	_, mux := testServer(t)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body, _ := json.Marshal(api.SiteVerifyRequest{Token: "anything", Secret: "wrong"})
	resp, _ := http.Post(ts.URL+"/siteverify", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()

	var sv api.SiteVerifyResponse
	json.NewDecoder(resp.Body).Decode(&sv)
	if sv.Success {
		t.Error("expected failure with wrong secret")
	}
}

// TestSiteverify_InvalidToken verifies that a garbage token is rejected.
func TestSiteverify_InvalidToken(t *testing.T) {
	_, mux := testServer(t)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body, _ := json.Marshal(api.SiteVerifyRequest{Token: "aGVsbG8=", Secret: "sk_test_sovereign"})
	resp, _ := http.Post(ts.URL+"/siteverify", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()

	var sv api.SiteVerifyResponse
	json.NewDecoder(resp.Body).Decode(&sv)
	if sv.Success {
		t.Error("expected failure with invalid token")
	}
}

// --- HashCash solver (Go implementation matching the server's verification) ---

func solveHashCashGo(nonce []byte, bits uint8) string {
	var counter uint64
	for {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], counter)
		h := sha256.New()
		h.Write(nonce)
		h.Write(buf[:])
		digest := h.Sum(nil)
		if countLeadingZeros(digest) >= int(bits) {
			return hex.EncodeToString(buf[:])
		}
		counter++
	}
}

func countLeadingZeros(b []byte) int {
	count := 0
	for _, v := range b {
		if v == 0 {
			count += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if v&mask != 0 {
				return count
			}
			count++
		}
		return count
	}
	return count
}
