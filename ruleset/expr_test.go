package ruleset

import (
	"net"
	"sync"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
)

func testStreamInfo() StreamInfo {
	info := StreamInfo{
		ID:       12345,
		Protocol: ProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.1").To4(),
		DstIP:    net.ParseIP("93.184.216.34").To4(),
		SrcPort:  54321,
		DstPort:  443,
		Props: analyzer.CombinedPropMap{
			"tls": analyzer.PropMap{"sni": "example.com"},
		},
	}
	info.CacheStrings()
	return info
}

func TestExprRulesetBuiltins(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		match bool
	}{
		{"id", `id == 12345`, true},
		{"proto", `proto == "tcp"`, true},
		{"ip", `cidr(string(ip.dst), "93.184.216.0/24")`, true},
		{"port", `port.dst == 443 && port.src == 54321`, true},
		{"string", `string(tls.sni) endsWith "example.com"`, true},
		{"string_fallback", `string(port.dst) == "443"`, true},
		{"no_match", `id == 1`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs, err := CompileExprRules([]ExprRule{
				{Name: tt.name, Action: "block", Expr: tt.expr},
			}, nil, nil, &BuiltinConfig{Logger: noopRulesetLogger{}})
			if err != nil {
				t.Fatal(err)
			}
			res := rs.Match(testStreamInfo())
			if tt.match {
				if res.Action != ActionBlock || res.RuleName != tt.name {
					t.Errorf("expected %q to match, got action %v rule %q", tt.expr, res.Action, res.RuleName)
				}
			} else if res.Action != ActionMaybe {
				t.Errorf("expected no match, got action %v rule %q", res.Action, res.RuleName)
			}
		})
	}
}

func TestExprRulesetConcurrentMatch(t *testing.T) {
	rs, err := CompileExprRules([]ExprRule{
		{Name: "block_tls", Action: "block", Expr: `tls != nil && string(tls.sni) endsWith "example.com"`},
		{Name: "block_cidr", Action: "block", Expr: `cidr(string(ip.dst), "10.0.0.0/8")`},
	}, nil, nil, &BuiltinConfig{Logger: noopRulesetLogger{}})
	if err != nil {
		t.Fatal(err)
	}
	info := testStreamInfo()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if res := rs.Match(info); res.RuleName != "block_tls" {
					t.Errorf("unexpected match result: %+v", res)
					return
				}
			}
		}()
	}
	wg.Wait()
}
