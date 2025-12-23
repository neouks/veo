package fingerprint

import (
	"testing"
)

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator()

	// Test case 1: First time URL
	url1 := "http://example.com"
	fps1 := []string{"CMS"}
	if !d.ShouldOutput(url1, fps1) {
		t.Error("Expected true for first time output")
	}

	// Test case 2: Duplicate URL
	if d.ShouldOutput(url1, fps1) {
		t.Error("Expected false for second time output")
	}

	// Test case 3: Different Fingerprints (should be treated as new if logic includes fingerprint)
	// Current logic uses URL|Path|Fingerprints as key
	fps2 := []string{"CMS", "Framework"}
	if !d.ShouldOutput(url1, fps2) {
		t.Error("Expected true for new fingerprints on same URL")
	}

	// Test case 4: Fingerprint list duplicates should not create a new key
	d.Clear()
	if !d.ShouldOutput(url1, []string{"CMS"}) {
		t.Error("Expected true for first time output")
	}
	if d.ShouldOutput(url1, []string{"CMS", "CMS"}) {
		t.Error("Expected false for duplicated fingerprint names (same logical key)")
	}

	// Test case 5: Clear
	d.Clear()
	if d.Count() != 0 {
		t.Errorf("Expected count 0, got %d", d.Count())
	}
	if !d.ShouldOutput(url1, fps1) {
		t.Error("Expected true after clear")
	}
}
