package httptime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatRFC3339_zeroValueUsesUTC(t *testing.T) {
	got := FormatRFC3339(time.Time{})
	if !strings.HasSuffix(got, "Z") {
		t.Fatalf("expected zero time to format in UTC (suffix Z), got %q", got)
	}
}

func TestFormatRFC3339_nonZeroUsesBogota(t *testing.T) {
	// 2026-04-28T12:00:00Z is 07:00 in Bogota (-05:00, no DST).
	in := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	got := FormatRFC3339(in)
	if !strings.HasSuffix(got, "-05:00") {
		t.Fatalf("expected -05:00 offset, got %q", got)
	}
	if !strings.HasPrefix(got, "2026-04-28T07:00:00") {
		t.Fatalf("expected wall time 07:00:00 in Bogota, got %q", got)
	}
}

func TestJSONTime_marshalsAsBogotaString(t *testing.T) {
	in := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	b, err := json.Marshal(JSONTime(in))
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(b), "-05:00") {
		t.Fatalf("expected Bogota offset in JSON, got %s", b)
	}
}

func TestJSONPtr_marshalsNilAsNull(t *testing.T) {
	b, err := json.Marshal(JSONPtr{nil})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if string(b) != "null" {
		t.Fatalf("expected null, got %s", b)
	}
}
