package audit

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"low", SeverityLow, false},
		{"medium", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"", 0, true},
		{"HIGH", 0, true},
		{"critical", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseSeverity(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	f := Finding{Rule: "latest-image", Severity: SeverityMedium}
	if !f.AtOrAbove(SeverityLow) || !f.AtOrAbove(SeverityMedium) {
		t.Error("medium finding should meet low and medium thresholds")
	}
	if f.AtOrAbove(SeverityHigh) {
		t.Error("medium finding should not meet high threshold")
	}
	if SeverityLow.String() != "low" || SeverityHigh.String() != "high" {
		t.Errorf("String() round-trip broken: %v %v", SeverityLow, SeverityHigh)
	}
}
