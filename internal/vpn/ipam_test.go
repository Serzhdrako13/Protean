package vpn

import (
	"fmt"
	"testing"
)

func TestNextFreeIP(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		used map[string]bool
		want string
	}{
		{
			name: "first host free",
			cidr: "10.10.0.0/24",
			used: map[string]bool{"10.10.0.0": true},
			want: "10.10.0.1/32",
		},
		{
			name: "skips used addresses",
			cidr: "10.10.0.0/30",
			used: map[string]bool{"10.10.0.0": true, "10.10.0.1": true},
			want: "10.10.0.2/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NextFreeIP(tt.cidr, tt.used)
			if err != nil {
				t.Fatalf("NextFreeIP: %v", err)
			}
			if got != tt.want {
				t.Errorf("NextFreeIP(%s) = %q, want %q", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestNextFreeIPExhausted(t *testing.T) {
	used := map[string]bool{"10.10.0.1": true, "10.10.0.2": true, "10.10.0.3": true}
	if _, err := NextFreeIP("10.10.0.0/30", used); err == nil {
		t.Error("expected error when subnet is exhausted")
	}
}

func TestNextFreeIPInvalidCIDR(t *testing.T) {
	if _, err := NextFreeIP("not-a-cidr", nil); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNextFreeIPInRangeMatchesUnboundedBehavior(t *testing.T) {
	// Empty start/end must be byte-for-byte the same scan as NextFreeIP.
	used := map[string]bool{"10.10.0.0": true, "10.10.0.1": true}
	got, err := NextFreeIPInRange("10.10.0.0/24", "", "", used)
	if err != nil {
		t.Fatalf("NextFreeIPInRange: %v", err)
	}
	want, err := NextFreeIP("10.10.0.0/24", used)
	if err != nil {
		t.Fatalf("NextFreeIP: %v", err)
	}
	if got != want {
		t.Errorf("NextFreeIPInRange (unbounded) = %q, want %q (same as NextFreeIP)", got, want)
	}
}

func TestNextFreeIPInRangeBounded(t *testing.T) {
	// Pool restricted to .10-.20 -- .1 is free but outside the range, so it
	// must never be picked.
	used := map[string]bool{}
	got, err := NextFreeIPInRange("10.10.0.0/24", "10.10.0.10", "10.10.0.20", used)
	if err != nil {
		t.Fatalf("NextFreeIPInRange: %v", err)
	}
	if got != "10.10.0.10/32" {
		t.Errorf("NextFreeIPInRange = %q, want 10.10.0.10/32", got)
	}

	// Fill the range; must report exhausted rather than spilling outside it.
	full := map[string]bool{}
	for i := 10; i <= 20; i++ {
		full[fmt.Sprintf("10.10.0.%d", i)] = true
	}
	if _, err := NextFreeIPInRange("10.10.0.0/24", "10.10.0.10", "10.10.0.20", full); err == nil {
		t.Error("expected error when the restricted range is exhausted, even though the wider subnet has free addresses")
	}
}

func TestNextFreeIPInRangeInvalidBounds(t *testing.T) {
	if _, err := NextFreeIPInRange("10.10.0.0/24", "not-an-ip", "", nil); err == nil {
		t.Error("expected error for invalid range start")
	}
	if _, err := NextFreeIPInRange("10.10.0.0/24", "", "not-an-ip", nil); err == nil {
		t.Error("expected error for invalid range end")
	}
	if _, err := NextFreeIPInRange("10.10.0.0/24", "10.20.0.5", "", nil); err == nil {
		t.Error("expected error when range start is outside the CIDR")
	}
	if _, err := NextFreeIPInRange("10.10.0.0/24", "", "10.20.0.5", nil); err == nil {
		t.Error("expected error when range end is outside the CIDR")
	}
}
