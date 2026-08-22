package discover

import "testing"

func TestApexFor(t *testing.T) {
	apex, ok := ApexFor("WWW.Example.COM.", []string{"example.com"})
	if !ok {
		t.Fatal("ApexFor() ok = false, want true")
	}
	if apex != "example.com" {
		t.Fatalf("ApexFor() apex = %q, want example.com", apex)
	}
}

func TestMergeDeduplicatesHostPort(t *testing.T) {
	hosts := Merge(
		[]Host{{Hostname: "www.example.com", Port: 443, Source: SourceCrtName}},
		[]Host{{Hostname: "WWW.EXAMPLE.COM.", Port: 443, Source: SourceManual}},
		[]Host{{Hostname: "www.example.com", Port: 8443, Source: SourceManual}},
	)

	if len(hosts) != 2 {
		t.Fatalf("len(Merge()) = %d, want 2", len(hosts))
	}
}
