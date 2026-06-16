package temperature

import "testing"

func TestReputationResidential(t *testing.T) {
	r := NewReputation()
	if score := r.Score("192.168.1.1"); score != 0 {
		t.Errorf("private IP got score %d, want 0", score)
	}
	if score := r.Score("85.1.2.3"); score != 0 {
		t.Errorf("residential IP got score %d, want 0", score)
	}
}

func TestReputationCloud(t *testing.T) {
	r := NewReputation()
	cases := []struct {
		ip       string
		provider string
	}{
		{"3.5.1.1", "AWS"},
		{"52.10.0.1", "AWS"},
		{"54.200.1.1", "AWS"},
		{"35.192.0.1", "GCP"},
		{"34.100.0.1", "GCP"},
		{"104.196.1.1", "GCP"},
		{"20.50.0.1", "Azure"},
		{"52.160.0.1", "Azure"},
		{"104.40.0.1", "Azure"},
		{"159.65.10.1", "DigitalOcean"},
		{"167.71.10.1", "DigitalOcean"},
		{"206.189.10.1", "DigitalOcean"},
	}
	for _, tc := range cases {
		if score := r.Score(tc.ip); score != 80 {
			t.Errorf("%s (%s) got score %d, want 80", tc.ip, tc.provider, score)
		}
	}
}

func TestReputationTor(t *testing.T) {
	r := NewReputation()
	if score := r.Score("185.220.101.5"); score != 100 {
		t.Errorf("Tor exit IP got score %d, want 100", score)
	}
}

func TestReputationInvalidIP(t *testing.T) {
	r := NewReputation()
	if score := r.Score("not-an-ip"); score != 0 {
		t.Errorf("invalid IP got score %d, want 0", score)
	}
}

func TestReputationCIDRParsing(t *testing.T) {
	r := NewReputation()
	if len(r.cloud) == 0 {
		t.Fatal("no cloud CIDRs parsed")
	}
	if len(r.torNets) == 0 {
		t.Fatal("no Tor CIDRs parsed")
	}
}
