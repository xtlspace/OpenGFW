package io

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nfqueueNum              = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 128

	nfqueueConnMarkAccept = 1001
	nfqueueConnMarkDrop   = 1002

	nftFamily = "inet"
	nftTable  = "opengfw"
)

type offloadKey struct {
	ip   [4]byte
	port uint16
}

type offloadCounterEntry struct {
	count    int
	allow    bool
	lastSeen time.Time
}

type offloadCounter struct {
	mu     sync.Mutex
	counts map[offloadKey]*offloadCounterEntry
}

func newOffloadCounter() *offloadCounter {
	return &offloadCounter{
		counts: make(map[offloadKey]*offloadCounterEntry),
	}
}

func (c *offloadCounter) increment(key offloadKey, allow bool, threshold int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, exists := c.counts[key]
	if !exists {
		c.counts[key] = &offloadCounterEntry{
			count:    1,
			allow:    allow,
			lastSeen: time.Now(),
		}
		return false
	}
	entry.count++
	entry.allow = allow
	entry.lastSeen = time.Now()
	if entry.count >= threshold {
		delete(c.counts, key)
		return true
	}
	return false
}

func (c *offloadCounter) cleanup(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, entry := range c.counts {
		if now.Sub(entry.lastSeen) > maxAge {
			delete(c.counts, key)
		}
	}
}

type offloadEntry struct {
	ip       net.IP
	port     uint16
	allow    bool
	ruleName string
}

func generateNftRules(local, rst bool, protos nfProtocolConfig, offloadEnabled bool, offloadTTL time.Duration) (*nftTableSpec, error) {
	if local && rst {
		return nil, errors.New("tcp rst is not supported in local mode")
	}
	table := &nftTableSpec{
		Family: nftFamily,
		Table:  nftTable,
	}
	table.Defines = append(table.Defines, fmt.Sprintf("define ACCEPT_CTMARK=%d", nfqueueConnMarkAccept))
	table.Defines = append(table.Defines, fmt.Sprintf("define DROP_CTMARK=%d", nfqueueConnMarkDrop))
	table.Defines = append(table.Defines, fmt.Sprintf("define QUEUE_NUM=%d", nfqueueNum))
	if offloadEnabled {
		ttl := fmt.Sprintf("%ds", int(offloadTTL.Seconds()))
		table.Sets = append(table.Sets, nftSetSpec{
			Name:    "offload_allow",
			Type:    "ipv4_addr . inet_service",
			Timeout: ttl,
		})
		table.Sets = append(table.Sets, nftSetSpec{
			Name:    "offload_drop",
			Type:    "ipv4_addr . inet_service",
			Timeout: ttl,
		})
	}
	if local {
		table.Chains = []nftChainSpec{
			{Chain: "INPUT", Header: "type filter hook input priority filter; policy accept;"},
			{Chain: "OUTPUT", Header: "type filter hook output priority filter; policy accept;"},
		}
	} else {
		table.Chains = []nftChainSpec{
			{Chain: "FORWARD", Header: "type filter hook forward priority filter; policy accept;"},
		}
	}
	for i := range table.Chains {
		c := &table.Chains[i]
		c.Rules = append(c.Rules, "meta mark $ACCEPT_CTMARK ct mark set $ACCEPT_CTMARK")
		c.Rules = append(c.Rules, "ct mark $ACCEPT_CTMARK counter accept")
		if offloadEnabled {
			c.Rules = append(c.Rules, offloadLookupRules(protos, rst)...)
		}
		if rst {
			c.Rules = append(c.Rules, "ip protocol tcp ct mark $DROP_CTMARK counter reject with tcp reset")
		}
		c.Rules = append(c.Rules, "ct mark $DROP_CTMARK counter drop")
		c.Rules = append(c.Rules, protos.queueRules()...)
	}
	return table, nil
}

func offloadLookupRules(protos nfProtocolConfig, rst bool) []string {
	var rules []string
	if protos.TCP {
		rules = append(rules, "ip daddr . tcp dport @offload_allow accept")
		rules = append(rules, "ip saddr . tcp sport @offload_allow accept")
		if rst {
			rules = append(rules, "ip daddr . tcp dport @offload_drop counter reject with tcp reset")
			rules = append(rules, "ip saddr . tcp sport @offload_drop counter reject with tcp reset")
		} else {
			rules = append(rules, "ip daddr . tcp dport @offload_drop counter drop")
			rules = append(rules, "ip saddr . tcp sport @offload_drop counter drop")
		}
	}
	if protos.UDP {
		rules = append(rules, "ip daddr . udp dport @offload_allow accept")
		rules = append(rules, "ip saddr . udp sport @offload_allow accept")
		rules = append(rules, "ip daddr . udp dport @offload_drop counter drop")
		rules = append(rules, "ip saddr . udp sport @offload_drop counter drop")
	}
	return rules
}

// nfProtocolConfig controls which packets are queued for inspection.
type nfProtocolConfig struct {
	TCP  bool
	UDP  bool
	IPv4 bool
	IPv6 bool
}

// queueRules returns the nftables queue rules to capture the configured
// protocols. Traffic that does not match is left untouched by the kernel.
func (c nfProtocolConfig) queueRules() []string {
	all := c.TCP && c.UDP && c.IPv4 && c.IPv6
	if all {
		return []string{"counter queue num $QUEUE_NUM bypass"}
	}
	var rules []string
	if c.IPv4 && c.TCP {
		rules = append(rules, "meta nfproto ipv4 meta l4proto tcp counter queue num $QUEUE_NUM bypass")
	}
	if c.IPv4 && c.UDP {
		rules = append(rules, "meta nfproto ipv4 meta l4proto udp counter queue num $QUEUE_NUM bypass")
	}
	if c.IPv6 && c.TCP {
		rules = append(rules, "meta nfproto ipv6 meta l4proto tcp counter queue num $QUEUE_NUM bypass")
	}
	if c.IPv6 && c.UDP {
		rules = append(rules, "meta nfproto ipv6 meta l4proto udp counter queue num $QUEUE_NUM bypass")
	}
	return rules
}

var _ PacketIO = (*nfqueuePacketIO)(nil)

var errNotNFQueuePacket = errors.New("not an NFQueue packet")

type nfqueuePacketIO struct {
	n *nfqueue.Nfqueue

	local bool
	rst   bool
	rSet  bool

	protos nfProtocolConfig

	protectedDialer *net.Dialer

	offloadEnabled   bool
	offloadTTL       time.Duration
	offloadThreshold int
	offloadCIDR      *net.IPNet
	offloadCounter   *offloadCounter
	offloadCh        chan offloadEntry
	offloadCtx       context.Context
	offloadCancel    context.CancelFunc

	startPostCommand string
}

type NFQueuePacketIOConfig struct {
	QueueSize        uint32
	ReadBuffer       int
	WriteBuffer      int
	Local            bool
	RST              bool
	TCP              bool
	UDP              bool
	IPv4             bool
	IPv6             bool
	Offload          bool
	OffloadTTL       time.Duration
	OffloadThreshold int
	OffloadCIDR      string
	StartPostCommand string
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	if config.QueueSize == 0 {
		config.QueueSize = nfqueueDefaultQueueSize
	}
	// Protocol filter defaults: capture all if none of the options are set.
	if !config.TCP && !config.UDP && !config.IPv4 && !config.IPv6 {
		config.TCP, config.UDP, config.IPv4, config.IPv6 = true, true, true, true
	}
	if !config.TCP && !config.UDP {
		return nil, errors.New("tcp and udp cannot both be disabled")
	}
	if !config.IPv4 && !config.IPv6 {
		return nil, errors.New("ipv4 and ipv6 cannot both be disabled")
	}
	n, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      nfqueueNum,
		MaxPacketLen: nfqueueMaxPacketLen,
		MaxQueueLen:  config.QueueSize,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	})
	if err != nil {
		return nil, err
	}
	if config.ReadBuffer > 0 {
		err = n.Con.SetReadBuffer(config.ReadBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	if config.WriteBuffer > 0 {
		err = n.Con.SetWriteBuffer(config.WriteBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	var offloadCIDR *net.IPNet
	if config.Offload {
		if config.OffloadCIDR == "" {
			return nil, errors.New("offloadCidr is required when offload is enabled")
		}
		_, cidr, err := net.ParseCIDR(config.OffloadCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid offloadCidr: %w", err)
		}
		offloadCIDR = cidr
		if config.OffloadTTL == 0 {
			config.OffloadTTL = 60 * time.Second
		}
		if config.OffloadThreshold <= 0 {
			config.OffloadThreshold = 3
		}
	}
	io := &nfqueuePacketIO{
		n:     n,
		local: config.Local,
		rst:   config.RST,
		protos: nfProtocolConfig{
			TCP:  config.TCP,
			UDP:  config.UDP,
			IPv4: config.IPv4,
			IPv6: config.IPv6,
		},
		protectedDialer: &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var err error
				cErr := c.Control(func(fd uintptr) {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, nfqueueConnMarkAccept)
				})
				if cErr != nil {
					return cErr
				}
				return err
			},
		},
	}
	if config.Offload {
		io.offloadEnabled = true
		io.offloadTTL = config.OffloadTTL
		io.offloadThreshold = config.OffloadThreshold
		io.offloadCIDR = offloadCIDR
		io.offloadCounter = newOffloadCounter()
		io.offloadCtx, io.offloadCancel = context.WithCancel(context.Background())
		io.offloadCh = make(chan offloadEntry, 1024)
		go io.offloadWorker()
		go io.offloadCleanup()
	}
	io.startPostCommand = config.StartPostCommand
	return io, nil
}

func (n *nfqueuePacketIO) Register(ctx context.Context, cb PacketCallback) error {
	err := n.n.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			if ok, verdict := n.packetAttributeSanityCheck(a); !ok {
				if a.PacketID != nil {
					_ = n.n.SetVerdict(*a.PacketID, verdict)
				}
				return 0
			}
			p := &nfqueuePacket{
				id:       *a.PacketID,
				streamID: ctIDFromCtBytes(*a.Ct),
				data:     *a.Payload,
			}
			return okBoolToInt(cb(p, nil))
		},
		func(e error) int {
			if opErr := (*netlink.OpError)(nil); errors.As(e, &opErr) {
				if errors.Is(opErr.Err, unix.ENOBUFS) {
					// Kernel buffer temporarily full, ignore
					return 0
				}
			}
			return okBoolToInt(cb(nil, e))
		})
	if err != nil {
		return err
	}
	if !n.rSet {
		err = n.setupNft(n.local, n.rst, false, n.protos)
		if err != nil {
			return err
		}
		n.rSet = true
	}
	if n.startPostCommand != "" {
		cmd := exec.Command("sh", "-c", n.startPostCommand)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
	return nil
}

func (n *nfqueuePacketIO) packetAttributeSanityCheck(a nfqueue.Attribute) (ok bool, verdict int) {
	if a.PacketID == nil {
		// Re-inject to NFQUEUE is actually not possible in this condition
		return false, -1
	}
	if a.Payload == nil || len(*a.Payload) < 20 {
		// 20 is the minimum possible size of an IP packet
		return false, nfqueue.NfDrop
	}
	if a.Ct == nil {
		// Multicast packets may not have a conntrack, but only appear in local mode
		if n.local {
			return false, nfqueue.NfAccept
		}
		return false, nfqueue.NfDrop
	}
	return true, -1
}

func (n *nfqueuePacketIO) SetVerdict(p Packet, v Verdict, newPacket []byte, ruleName string) error {
	nP, ok := p.(*nfqueuePacket)
	if !ok {
		return &ErrInvalidPacket{Err: errNotNFQueuePacket}
	}
	switch v {
	case VerdictAccept:
		return n.n.SetVerdict(nP.id, nfqueue.NfAccept)
	case VerdictAcceptModify:
		return n.n.SetVerdictModPacket(nP.id, nfqueue.NfAccept, newPacket)
	case VerdictAcceptStream:
		if n.offloadEnabled {
			n.checkOffload(nP.data, true, ruleName)
		}
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfAccept, nfqueueConnMarkAccept)
	case VerdictDrop:
		return n.n.SetVerdict(nP.id, nfqueue.NfDrop)
	case VerdictDropStream:
		if n.offloadEnabled {
			n.checkOffload(nP.data, false, ruleName)
		}
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfDrop, nfqueueConnMarkDrop)
	default:
		// Invalid verdict, ignore for now
		return nil
	}
}

func (n *nfqueuePacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.protectedDialer.DialContext(ctx, network, address)
}

func (n *nfqueuePacketIO) Close() error {
	if n.offloadEnabled {
		n.offloadCancel()
	}
	if n.rSet {
		_ = n.setupNft(n.local, n.rst, true, n.protos)
		n.rSet = false
	}
	return n.n.Close()
}

func (n *nfqueuePacketIO) setupNft(local, rst, remove bool, protos nfProtocolConfig) error {
	rules, err := generateNftRules(local, rst, protos, n.offloadEnabled, n.offloadTTL)
	if err != nil {
		return err
	}
	rulesText := rules.String()
	if remove {
		err = nftDelete(nftFamily, nftTable)
	} else {
		// Delete first to make sure no leftover rules
		_ = nftDelete(nftFamily, nftTable)
		err = nftAdd(rulesText)
	}
	if err != nil {
		return err
	}
	return nil
}

var _ Packet = (*nfqueuePacket)(nil)

type nfqueuePacket struct {
	id       uint32
	streamID uint32
	data     []byte
}

func (p *nfqueuePacket) StreamID() uint32 {
	return p.streamID
}

func (p *nfqueuePacket) Data() []byte {
	return p.data
}

func okBoolToInt(ok bool) int {
	if ok {
		return 0
	} else {
		return 1
	}
}

func nftAdd(input string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	return cmd.Run()
}

func nftDelete(family, table string) error {
	cmd := exec.Command("nft", "delete", "table", family, table)
	return cmd.Run()
}

type nftSetSpec struct {
	Name    string
	Type    string
	Timeout string
}

func (s nftSetSpec) String() string {
	return fmt.Sprintf(`  set %s {
    type %s
    flags timeout
    timeout %s
  }`, s.Name, s.Type, s.Timeout)
}

type nftTableSpec struct {
	Defines       []string
	Family, Table string
	Sets          []nftSetSpec
	Chains        []nftChainSpec
}

func (t *nftTableSpec) String() string {
	chains := make([]string, 0, len(t.Chains))
	for _, c := range t.Chains {
		chains = append(chains, c.String())
	}
	sets := make([]string, 0, len(t.Sets))
	for _, s := range t.Sets {
		sets = append(sets, s.String())
	}

	return fmt.Sprintf(`
%s

table %s %s {
%s
%s
}`, strings.Join(t.Defines, "\n"), t.Family, t.Table, strings.Join(sets, "\n"), strings.Join(chains, ""))
}

type nftChainSpec struct {
	Chain  string
	Header string
	Rules  []string
}

func (c *nftChainSpec) String() string {
	return fmt.Sprintf(`
  chain %s {
    %s
    %s
  }
`, c.Chain, c.Header, strings.Join(c.Rules, "\n\x20\x20\x20\x20"))
}

func ctIDFromCtBytes(ct []byte) uint32 {
	ctAttrs, err := netlink.UnmarshalAttributes(ct)
	if err != nil {
		return 0
	}
	for _, attr := range ctAttrs {
		if attr.Type == 12 { // CTA_ID
			return binary.BigEndian.Uint32(attr.Data)
		}
	}
	return 0
}

func (n *nfqueuePacketIO) checkOffload(data []byte, allow bool, ruleName string) {
	if len(data) < 20 {
		return
	}
	version := data[0] >> 4
	if version != 4 {
		return
	}
	ipHdrLen := int(data[0]&0xF) * 4
	if len(data) < ipHdrLen+4 {
		return
	}
	proto := data[9]
	if proto != 6 && proto != 17 {
		return
	}
	var srcIP, dstIP [4]byte
	copy(srcIP[:], data[12:16])
	copy(dstIP[:], data[16:20])
	srcPort := binary.BigEndian.Uint16(data[ipHdrLen : ipHdrLen+2])
	dstPort := binary.BigEndian.Uint16(data[ipHdrLen+2 : ipHdrLen+4])

	var key offloadKey
	if n.offloadCIDR.Contains(net.IP(dstIP[:])) {
		// dst ∈ CIDR (inbound) → record src+sport
		key = offloadKey{ip: srcIP, port: srcPort}
	} else if n.offloadCIDR.Contains(net.IP(srcIP[:])) {
		// src ∈ CIDR (outbound) → record dst+dport
		key = offloadKey{ip: dstIP, port: dstPort}
	} else {
		return
	}

	if n.offloadCounter.increment(key, allow, n.offloadThreshold) {
		select {
		case n.offloadCh <- offloadEntry{ip: net.IP(key.ip[:]), port: key.port, allow: allow, ruleName: ruleName}:
		default:
		}
	}
}

func (n *nfqueuePacketIO) offloadWorker() {
	var batch []offloadEntry
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		var sb strings.Builder
		ttl := fmt.Sprintf("%ds", int(n.offloadTTL.Seconds()))
		for _, e := range batch {
			set := "offload_allow"
			if !e.allow {
				set = "offload_drop"
			}
			if e.ruleName != "" {
				fmt.Fprintf(&sb, "add element inet opengfw %s { %s . %d comment %q timeout %s }\n",
					set, e.ip.String(), e.port, e.ruleName, ttl)
			} else {
				fmt.Fprintf(&sb, "add element inet opengfw %s { %s . %d timeout %s }\n",
					set, e.ip.String(), e.port, ttl)
			}
		}
		_ = nftAdd(sb.String())
		batch = batch[:0]
	}

	for {
		select {
		case entry := <-n.offloadCh:
			batch = append(batch, entry)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-n.offloadCtx.Done():
			flush()
			return
		}
	}
}

func (n *nfqueuePacketIO) offloadCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.offloadCounter.cleanup(10 * time.Minute)
		case <-n.offloadCtx.Done():
			return
		}
	}
}
