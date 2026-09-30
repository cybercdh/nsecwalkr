package main

import "testing"

func TestGenerateProbeLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"foo", "foo--"},
		{"", "--"},
		{"AbC", "abc--"}, // lower-cased
	}
	for _, c := range cases {
		if got := generateProbeLabel(c.in); got != c.want {
			t.Errorf("generateProbeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// Over 63 chars: the 63rd byte (index 62) is bumped, others truncated.
	long := ""
	for i := 0; i < 62; i++ {
		long += "a"
	}
	// long is 62 'a's; +"--" => 64 chars, index 62 == '-', bumped to '0'
	got := generateProbeLabel(long)
	if len(got) != 63 {
		t.Fatalf("expected length 63, got %d (%q)", len(got), got)
	}
	if got[62] != '0' {
		t.Errorf("expected trailing '0' when bumped byte was '-', got %q", got[62])
	}

	// A label whose bumped byte is '9' should roll to 'a'.
	nine := ""
	for i := 0; i < 62; i++ {
		nine += "a"
	}
	nine += "9" // 63 chars; +"--" => 65, truncated to 63, index 62 == '9'
	got = generateProbeLabel(nine)
	if got[62] != 'a' {
		t.Errorf("expected '9' to roll to 'a', got %q", got[62])
	}
}
