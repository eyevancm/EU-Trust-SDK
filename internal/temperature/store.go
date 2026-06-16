// Package temperature implements a simplified in-memory abuse scoring system.
//
// Five signals are weighted into a 0–100 score:
//   - IP request rate (30%)
//   - /24 subnet rate (20%)
//   - Token burn rate per site key (20%)
//   - Probe consistency (10%)
//   - IP reputation — cloud/Tor origin detection (20%)
//
// The score maps to a temperature bucket (0–3) which drives challenge difficulty.
package temperature

import (
	"net"
	"sync"
	"time"
)

const windowDuration = 60 * time.Second

// Store holds per-IP and per-site-key signal data.
type Store struct {
	mu           sync.Mutex
	ipRequests   map[string][]time.Time
	subnetReqs   map[string][]time.Time
	tokenBurns   map[string]int
	probeHistory map[string][]bool // IP → [pass, pass, fail, ...]
	reputation   *Reputation
	stopCleanup  chan struct{}
}

// NewStore creates a Store and starts its cleanup goroutine.
func NewStore() *Store {
	s := &Store{
		ipRequests:   make(map[string][]time.Time),
		subnetReqs:   make(map[string][]time.Time),
		tokenBurns:   make(map[string]int),
		probeHistory: make(map[string][]bool),
		reputation:   NewReputation(),
		stopCleanup:  make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the cleanup goroutine.
func (s *Store) Close() {
	close(s.stopCleanup)
}

// Record ingests a single request event.
func (s *Store) Record(ip, siteKey string, probePass *bool) {
	now := time.Now()
	subnet := subnetKey(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ipRequests[ip] = append(s.ipRequests[ip], now)
	s.subnetReqs[subnet] = append(s.subnetReqs[subnet], now)

	if probePass != nil {
		s.probeHistory[ip] = append(s.probeHistory[ip], *probePass)
		// Keep only the last 20 probe results per IP
		if len(s.probeHistory[ip]) > 20 {
			s.probeHistory[ip] = s.probeHistory[ip][len(s.probeHistory[ip])-20:]
		}
	}
}

// RecordTokenBurn increments the token burn count for a site key.
func (s *Store) RecordTokenBurn(siteKey string) {
	s.mu.Lock()
	s.tokenBurns[siteKey]++
	s.mu.Unlock()
}

// Score computes the abuse score (0–100) and bucket (0–3) for the given IP and site key.
func (s *Store) Score(ip, siteKey string) (score int, bucket uint8) {
	now := time.Now()
	subnet := subnetKey(ip)
	cutoff := now.Add(-windowDuration)

	s.mu.Lock()
	defer s.mu.Unlock()

	// IP request rate: count requests in last 60s
	ipReqs := countAfter(s.ipRequests[ip], cutoff)
	// Subnet request rate
	subnetReqs := countAfter(s.subnetReqs[subnet], cutoff)
	// Token burn rate (total for this site key, decays slowly)
	burns := s.tokenBurns[siteKey]
	// Probe consistency: fraction of failed probes
	probeScore := probeFailRate(s.probeHistory[ip])

	// IP reputation: 0 = residential, 80 = cloud, 100 = Tor
	repScore := s.reputation.Score(ip)

	// Convert each signal to 0–100 (capped)
	ipScore := min100(ipReqs * 5)           // 20 req/min → score 100
	subnetScore := min100(subnetReqs * 2)   // 50 req/min from subnet → score 100
	burnScore := min100(burns / 10)         // 1000 tokens burned → score 100
	probeSignal := int(probeScore * 100)

	// Weighted sum: IP rate 30%, subnet 20%, burns 20%, probes 10%, reputation 20%
	weighted := (ipScore*30 + subnetScore*20 + burnScore*20 + probeSignal*10 + repScore*20) / 100
	score = min100(weighted)
	bucket = scoreToBucket(score)
	return score, bucket
}

// scoreToBucket maps 0–100 → 0–3.
func scoreToBucket(score int) uint8 {
	switch {
	case score <= 20:
		return 0
	case score <= 50:
		return 1
	case score <= 80:
		return 2
	default:
		return 3
	}
}

func countAfter(times []time.Time, cutoff time.Time) int {
	count := 0
	for _, t := range times {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

func probeFailRate(history []bool) float64 {
	if len(history) == 0 {
		return 0
	}
	fails := 0
	for _, passed := range history {
		if !passed {
			fails++
		}
	}
	return float64(fails) / float64(len(history))
}

func min100(v int) int {
	if v > 100 {
		return 100
	}
	return v
}

func subnetKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4[:3].String() + ".0/24"
	}
	return ip
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

func (s *Store) cleanup() {
	cutoff := time.Now().Add(-windowDuration)
	s.mu.Lock()
	defer s.mu.Unlock()

	for ip, times := range s.ipRequests {
		filtered := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(s.ipRequests, ip)
		} else {
			s.ipRequests[ip] = filtered
		}
	}
	for subnet, times := range s.subnetReqs {
		filtered := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(s.subnetReqs, subnet)
		} else {
			s.subnetReqs[subnet] = filtered
		}
	}
}
