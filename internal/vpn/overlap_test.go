package vpn

import "testing"

func TestCheckNoOverlap(t *testing.T) {
	existing := []string{"10.10.0.0/24", "192.168.1.0/24"}

	tests := []struct {
		name      string
		candidate string
		wantErr   bool
	}{
		{"disjoint", "10.20.0.0/24", false},
		{"exact duplicate", "10.10.0.0/24", true},
		{"subset", "10.10.0.128/25", true},
		{"superset", "10.10.0.0/16", true},
		{"adjacent non-overlapping", "10.11.0.0/24", false},
		{"overlaps second", "192.168.1.64/26", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckNoOverlap(tt.candidate, existing)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckNoOverlap(%q) err=%v, wantErr=%v", tt.candidate, err, tt.wantErr)
			}
		})
	}
}

func TestCheckNoOverlapInvalidCandidate(t *testing.T) {
	if err := CheckNoOverlap("not-a-cidr", nil); err == nil {
		t.Error("expected error for invalid candidate CIDR")
	}
}
