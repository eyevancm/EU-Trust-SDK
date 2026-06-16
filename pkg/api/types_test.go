package api

import (
	"testing"
	"time"
)

func TestMetadataRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		meta TrustMetadata
	}{
		{
			name: "zero values",
			meta: TrustMetadata{},
		},
		{
			name: "clean desktop standard challenge",
			meta: TrustMetadata{
				ChallengeClass:    1,
				TemperatureBucket: 0,
				DeviceClass:       1,
				TimeBucket:        489720, // some hour
			},
		},
		{
			name: "critical mobile escalated",
			meta: TrustMetadata{
				ChallengeClass:    3,
				TemperatureBucket: 3,
				DeviceClass:       2,
				TimeBucket:        489721,
			},
		},
		{
			name: "max time bucket",
			meta: TrustMetadata{
				ChallengeClass:    2,
				TemperatureBucket: 1,
				DeviceClass:       0,
				TimeBucket:        0xFFFFFFFF,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.meta.Encode()
			if len(encoded) != 7 {
				t.Fatalf("encoded length = %d, want 7", len(encoded))
			}

			decoded, err := DecodeMetadata(encoded)
			if err != nil {
				t.Fatalf("DecodeMetadata error: %v", err)
			}

			if decoded != tt.meta {
				t.Errorf("roundtrip mismatch:\n  got  %+v\n  want %+v", decoded, tt.meta)
			}
		})
	}
}

func TestDecodeMetadataInvalidLength(t *testing.T) {
	badInputs := [][]byte{
		nil,
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		make([]byte, 8),
	}

	for _, b := range badInputs {
		_, err := DecodeMetadata(b)
		if err != ErrInvalidMetadata {
			t.Errorf("DecodeMetadata(%v) = %v, want ErrInvalidMetadata", b, err)
		}
	}
}

func TestMetadataEncodeDeterministic(t *testing.T) {
	meta := TrustMetadata{
		ChallengeClass:    2,
		TemperatureBucket: 1,
		DeviceClass:       1,
		TimeBucket:        500000,
	}

	a := meta.Encode()
	b := meta.Encode()

	if len(a) != len(b) {
		t.Fatal("non-deterministic encoding length")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic encoding at byte %d: %x vs %x", i, a[i], b[i])
		}
	}
}

func TestTimeBucketFromTime(t *testing.T) {
	// Two times in the same hour should produce the same bucket
	t1 := time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 15, 14, 59, 59, 0, time.UTC)

	if TimeBucketFromTime(t1) != TimeBucketFromTime(t2) {
		t.Error("times in same hour produced different buckets")
	}

	// Times in different hours should produce different buckets
	t3 := time.Date(2026, 6, 15, 15, 0, 0, 0, time.UTC)
	if TimeBucketFromTime(t1) == TimeBucketFromTime(t3) {
		t.Error("times in different hours produced same bucket")
	}
}
