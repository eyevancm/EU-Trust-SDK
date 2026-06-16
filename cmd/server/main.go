// Package main implements the Sovereign Trust SDK PoC server.
//
// Endpoints:
//   GET  /challenge?sitekey=<key>&ua=<user-agent>  → ChallengePayload
//   POST /verify                                    → {blind_signature}
//   POST /siteverify                                → SiteVerifyResponse
//
// For PoC use only: key management is simplified, stores are in-memory.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/sovereign-trust/sdk/internal/challenge"
	"github.com/sovereign-trust/sdk/internal/environment"
	"github.com/sovereign-trust/sdk/internal/rsapbssa"
	"github.com/sovereign-trust/sdk/internal/temperature"
	"github.com/sovereign-trust/sdk/pkg/api"
)

// --- In-memory stores ---

type challengeEntry struct {
	payload       api.ChallengePayload
	predictedMeta []byte // 7-byte metadata the client blinded with
	expiry        time.Time
}

type tokenEntry struct {
	expiry time.Time
}

type verifyRequest struct {
	ChallengeID  string            `json:"challenge_id"`
	HashCash     string            `json:"hashcash_solution"`
	Argon2Result string            `json:"argon2_result"`
	ProbeResults map[string]string `json:"probe_results"`
	BlindedMsg   string            `json:"blinded_message"`
	DeviceClass  uint8             `json:"device_class"`
}

type verifyResponse struct {
	BlindSignature string `json:"blind_signature"`
	Metadata       string `json:"metadata"`
}

const (
	sigLen       = 256
	metaLen      = 7
	nonceLen     = 8
	tokenLen     = sigLen + metaLen + nonceLen
	tokenTTL     = 300 * time.Second
	challengeTTL = 120 * time.Second
)

type server struct {
	keyPair     *rsapbssa.KeyPair
	challenges  sync.Map
	tokens      sync.Map
	tempStore   *temperature.Store
	testSiteKey string
}

func newServer(kp *rsapbssa.KeyPair) *server {
	s := &server{
		keyPair:     kp,
		tempStore:   temperature.NewStore(),
		testSiteKey: "sk_test_sovereign",
	}
	go s.cleanupLoop()
	return s
}

func (s *server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.challenges.Range(func(k, v any) bool {
			if v.(challengeEntry).expiry.Before(now) {
				s.challenges.Delete(k)
			}
			return true
		})
		s.tokens.Range(func(k, v any) bool {
			if v.(tokenEntry).expiry.Before(now) {
				s.tokens.Delete(k)
			}
			return true
		})
	}
}

// --- Handlers ---

func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	siteKey := r.URL.Query().Get("sitekey")
	if siteKey == "" {
		http.Error(w, "missing sitekey", http.StatusBadRequest)
		return
	}

	ip := extractIP(r)
	s.tempStore.Record(ip, siteKey, nil)
	_, bucket := s.tempStore.Score(ip, siteKey)

	ranges := temperature.BucketRanges(bucket)

	nonce := make([]byte, 16)
	rand.Read(nonce)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	seed := challenge.GenerateSeed([]byte("poc-server-secret"), nonce, ts, []byte(ip))
	params := challenge.DeriveParams(seed, ranges)

	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	challengeID := base64.URLEncoding.EncodeToString(idBytes)

	payload, err := challenge.New(params, bucket, challengeID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	predictedMeta := api.TrustMetadata{
		ChallengeClass:    2,
		TemperatureBucket: bucket,
		DeviceClass:       1,
		TimeBucket:        api.TimeBucketFromTime(time.Now()),
	}
	predictedMetaBytes := predictedMeta.Encode()

	s.challenges.Store(challengeID, challengeEntry{
		payload:       payload,
		predictedMeta: predictedMetaBytes,
		expiry:        time.Now().Add(challengeTTL),
	})

	pk := s.keyPair.PublicKey()
	type challengeResponse struct {
		api.ChallengePayload
		ServerPublicKey struct {
			N string `json:"n"`
			E int    `json:"e"`
		} `json:"server_public_key"`
		PredictedMetadata string `json:"predicted_metadata"`
	}

	resp := challengeResponse{ChallengePayload: payload}
	resp.ServerPublicKey.N = base64.StdEncoding.EncodeToString(pk.N.Bytes())
	resp.ServerPublicKey.E = pk.E
	resp.PredictedMetadata = base64.StdEncoding.EncodeToString(predictedMetaBytes)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	entry, ok := s.challenges.Load(req.ChallengeID)
	if !ok {
		http.Error(w, "challenge not found or expired", http.StatusBadRequest)
		return
	}
	ce := entry.(challengeEntry)
	s.challenges.Delete(req.ChallengeID)

	apiResp := api.ChallengeResponse{
		ChallengeID:      req.ChallengeID,
		HashCashSolution: req.HashCash,
		Argon2Result:     req.Argon2Result,
		ProbeResults:     req.ProbeResults,
	}

	validator := func(name, val string) float64 {
		_, score := environment.Validate(name, val)
		return score
	}

	_, probeAnomaly, err := challenge.Verify(ce.payload, apiResp, validator)
	if err != nil {
		http.Error(w, fmt.Sprintf("challenge verification failed: %v", err), http.StatusBadRequest)
		return
	}

	ip := extractIP(r)
	siteKey := r.URL.Query().Get("sitekey")
	if siteKey == "" {
		siteKey = s.testSiteKey
	}
	probePass := probeAnomaly < 0.5
	s.tempStore.Record(ip, siteKey, &probePass)

	blindedMsgBytes, err := base64.StdEncoding.DecodeString(req.BlindedMsg)
	if err != nil {
		http.Error(w, "invalid blinded_message encoding", http.StatusBadRequest)
		return
	}

	// Use the predicted metadata stored at challenge time — never recompute.
	// This ensures the server signs with the same info the client blinded with.
	blindSig, err := rsapbssa.BlindSign(s.keyPair, blindedMsgBytes, ce.predictedMeta)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	s.tempStore.RecordTokenBurn(siteKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verifyResponse{
		BlindSignature: base64.StdEncoding.EncodeToString(blindSig.BlindSig),
		Metadata:       base64.StdEncoding.EncodeToString(ce.predictedMeta),
	})
}

func (s *server) handleSiteverify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.SiteVerifyRequest
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		r.ParseForm()
		req.Token = r.FormValue("token")
		req.Secret = r.FormValue("secret")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
	}

	if req.Secret != s.testSiteKey {
		writeVerifyError(w, []string{"invalid-input-secret"})
		return
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil || len(tokenBytes) != tokenLen {
		writeVerifyError(w, []string{"invalid-input-response"})
		return
	}

	sig := tokenBytes[:sigLen]
	metaBytes := tokenBytes[sigLen : sigLen+metaLen]
	nonce := tokenBytes[sigLen+metaLen:]

	nonceKey := base64.StdEncoding.EncodeToString(nonce)
	if _, exists := s.tokens.Load(nonceKey); exists {
		writeVerifyError(w, []string{"timeout-or-duplicate"})
		return
	}

	meta, err := api.DecodeMetadata(metaBytes)
	if err != nil {
		writeVerifyError(w, []string{"invalid-input-response"})
		return
	}

	pk := s.keyPair.PublicKey()
	if err := rsapbssa.Verify(pk, nonce, metaBytes, sig); err != nil {
		writeVerifyError(w, []string{"invalid-input-response"})
		return
	}

	s.tokens.Store(nonceKey, tokenEntry{expiry: time.Now().Add(tokenTTL)})

	resp := api.SiteVerifyResponse{
		Success:           true,
		Timestamp:         fmt.Sprintf("%d", meta.TimeBucket*3600),
		ChallengeClass:    meta.ChallengeClass,
		TemperatureBucket: meta.TemperatureBucket,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeVerifyError(w http.ResponseWriter, codes []string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.SiteVerifyResponse{
		Success:    false,
		ErrorCodes: codes,
	})
}

func extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// --- Dev key loading ---

func loadDevKey() *rsapbssa.KeyPair {
	log.Println("[DEV] Using RFC test vector key pair. NOT for production use.")

	devN, _ := hexToInt("d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9")
	devE, _ := hexToInt("010001")
	devD, _ := hexToInt("4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d")
	devP, _ := hexToInt("dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3")
	devQ, _ := hexToInt("f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3")

	return rsapbssa.KeyPairFromComponents(devN, devE, devD, devP, devQ)
}

func hexToInt(s string) (*big.Int, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func main() {
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()

	kp := loadDevKey()
	srv := newServer(kp)

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", srv.handleChallenge)
	mux.HandleFunc("/verify", srv.handleVerify)
	mux.HandleFunc("/siteverify", srv.handleSiteverify)

	mux.Handle("/widget/", http.StripPrefix("/widget/", http.FileServer(http.Dir("widget"))))

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}

	log.Println("Sovereign Trust SDK PoC server listening on :8080")
	log.Println("  GET  /challenge?sitekey=sk_test_sovereign")
	log.Println("  POST /verify")
	log.Println("  POST /siteverify")
	log.Printf("  %s://localhost:8080/widget/widget.html (test page)", scheme)

	if *tlsCert != "" {
		log.Fatal(http.ListenAndServeTLS(":8080", *tlsCert, *tlsKey, corsMiddleware(mux)))
	} else {
		log.Fatal(http.ListenAndServe(":8080", corsMiddleware(mux)))
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
