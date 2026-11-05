package ruleset

import (
	"context"
	"net"
	"strconv"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/modifier"
)

type Action int

const (
	// ActionMaybe indicates that the ruleset hasn't seen anything worth blocking based on
	// current information, but that may change if volatile fields change in the future.
	ActionMaybe Action = iota
	// ActionAllow indicates that the stream should be allowed regardless of future changes.
	ActionAllow
	// ActionBlock indicates that the stream should be blocked.
	ActionBlock
	// ActionDrop indicates that the current packet should be dropped,
	// but the stream should be allowed to continue.
	// Only valid for UDP streams. Equivalent to ActionBlock for TCP streams.
	ActionDrop
	// ActionModify indicates that the current packet should be modified,
	// and the stream should be allowed to continue.
	// Only valid for UDP streams. Equivalent to ActionMaybe for TCP streams.
	ActionModify
)

func (a Action) String() string {
	switch a {
	case ActionMaybe:
		return "maybe"
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionDrop:
		return "drop"
	case ActionModify:
		return "modify"
	default:
		return "unknown"
	}
}

type Protocol int

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

const (
	ProtocolTCP Protocol = iota
	ProtocolUDP
)

type streamStringCache struct {
	srcIP, dstIP string
	src, dst     string
}

type StreamInfo struct {
	ID               int64
	Protocol         Protocol
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Props            analyzer.CombinedPropMap

	// cache holds the precomputed textual forms of the endpoints.
	// It is optional and only set by CacheStrings.
	cache *streamStringCache
}

// CacheStrings precomputes the textual representations of the stream
// endpoints. StreamInfo is frequently logged and matched against rules,
// and net.IP.String plus net.JoinHostPort allocate on every call, so
// caching them once per stream avoids repeated allocations in hot paths.
func (i *StreamInfo) CacheStrings() {
	if i.cache == nil {
		i.cache = &streamStringCache{}
	}
	c := i.cache
	c.srcIP = i.SrcIP.String()
	c.dstIP = i.DstIP.String()
	c.src = net.JoinHostPort(c.srcIP, strconv.Itoa(int(i.SrcPort)))
	c.dst = net.JoinHostPort(c.dstIP, strconv.Itoa(int(i.DstPort)))
}

func (i StreamInfo) srcIPString() string {
	if i.cache != nil {
		return i.cache.srcIP
	}
	return i.SrcIP.String()
}

func (i StreamInfo) dstIPString() string {
	if i.cache != nil {
		return i.cache.dstIP
	}
	return i.DstIP.String()
}

func (i StreamInfo) SrcString() string {
	if i.cache != nil {
		return i.cache.src
	}
	return net.JoinHostPort(i.SrcIP.String(), strconv.Itoa(int(i.SrcPort)))
}

func (i StreamInfo) DstString() string {
	if i.cache != nil {
		return i.cache.dst
	}
	return net.JoinHostPort(i.DstIP.String(), strconv.Itoa(int(i.DstPort)))
}

type MatchResult struct {
	Action      Action
	ModInstance modifier.Instance
	RuleName    string
}

type Ruleset interface {
	// Analyzers returns the list of analyzers to use for a stream.
	// It must be safe for concurrent use by multiple workers.
	Analyzers(StreamInfo) []analyzer.Analyzer
	// Match matches a stream against the ruleset and returns the result.
	// It must be safe for concurrent use by multiple workers.
	Match(StreamInfo) MatchResult
}

// Logger is the logging interface for the ruleset.
type Logger interface {
	Log(info StreamInfo, name string)
	MatchError(info StreamInfo, name string, err error)
}

type BuiltinConfig struct {
	Logger               Logger
	GeoSiteFilename      string
	GeoIpFilename        string
	ProtectedDialContext func(ctx context.Context, network, address string) (net.Conn, error)
}
