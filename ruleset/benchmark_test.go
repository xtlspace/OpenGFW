package ruleset

import (
	"net"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
)

type noopRulesetLogger struct{}

func (noopRulesetLogger) Log(StreamInfo, string)               {}
func (noopRulesetLogger) MatchError(StreamInfo, string, error) {}

func BenchmarkMatch(b *testing.B) {
	rs, err := CompileExprRules(
		[]ExprRule{
			{Name: "block_tls", Action: "block", Expr: `tls != nil && string(tls.sni) endsWith "example.com"`},
			{Name: "allow_http", Action: "allow", Expr: `http != nil && string(http.host) endsWith "example.com"`},
			{Name: "block_cidr", Action: "block", Expr: `cidr(string(ip.dst), "10.0.0.0/8")`},
			{Name: "block_socks", Action: "block", Expr: `socks != nil && socks.version == 5 && port.dst > 10000`},
		},
		nil,
		nil,
		&BuiltinConfig{Logger: noopRulesetLogger{}},
	)
	if err != nil {
		b.Fatal(err)
	}
	info := StreamInfo{
		ID:       12345,
		Protocol: ProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.1").To4(),
		DstIP:    net.ParseIP("93.184.216.34").To4(),
		SrcPort:  54321,
		DstPort:  443,
		Props: analyzer.CombinedPropMap{
			"tls":   analyzer.PropMap{"sni": "example.com", "version": uint16(771)},
			"http":  analyzer.PropMap{"host": "example.com", "path": "/", "method": "GET"},
			"socks": analyzer.PropMap{"version": 5, "addr": "example.com", "port": 443},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.Match(info)
	}
}
