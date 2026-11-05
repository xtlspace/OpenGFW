package geo

import (
	"testing"

	"github.com/apernet/OpenGFW/ruleset/builtins/geo/v2geo"
)

func testGeoSite() *v2geo.GeoSite {
	return &v2geo.GeoSite{
		Domain: []*v2geo.Domain{
			{Type: v2geo.Domain_Full, Value: "example.com"},
			{Type: v2geo.Domain_RootDomain, Value: "example.org"},
			{Type: v2geo.Domain_Plain, Value: "plain-sub"},
			{Type: v2geo.Domain_Regex, Value: `^re[0-9]+\.test$`},
			{
				Type:      v2geo.Domain_Full,
				Value:     "attributed.com",
				Attribute: []*v2geo.Domain_Attribute{{Key: "cn"}},
			},
		},
	}
}

func TestGeositeMatcher(t *testing.T) {
	m, err := newGeositeMatcher(testGeoSite(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", false},
		{"example.org", true},
		{"a.example.org", true},
		{"badexample.org", false},
		{"xplain-subx", true},
		{"re12.test", true},
		{"re.test", false},
		{"attributed.com", true},
		{"nomatch.net", false},
	}
	for _, tt := range tests {
		if got := m.Match(HostInfo{Name: tt.host}); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestGeositeMatcherAttrs(t *testing.T) {
	m, err := newGeositeMatcher(testGeoSite(), []string{"cn"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(HostInfo{Name: "attributed.com"}) {
		t.Error("expected attributed.com to match the cn attribute filter")
	}
	if m.Match(HostInfo{Name: "example.com"}) {
		t.Error("expected example.com to be filtered out by the cn attribute filter")
	}
}
