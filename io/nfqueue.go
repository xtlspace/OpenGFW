package io

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nfqueueNum              = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 1024
	nfqueueMaxQueues        = 64
	nfqueueDefaultQueues    = 8

	nfqueueConnMarkAccept = 1001
	nfqueueConnMarkDrop   = 1002

	nftFamily = "inet"
	nftTable  = "opengfw"
)

// Netfilter queue netlink constants used for batch verdict writeback.
// They mirror the values used by go-nfqueue.
const (
	nfqnlSubsysQueue     = 3
	nfqnlMsgVerdict      = 1
	nfqnlVerAttrHdr      = 2
	nfqnlAttrMark        = 8 // CTA_MARK inside the nested conntrack attribute
	nfqnlAttrPayload     = 10
	nfqnlAttrCt          = 11
	nfnetlinkVersion     = 0 // NFNETLINK_V0
	nfqueueAfFamily      = 0 // AF_UNSPEC, matches the nfqueue.Open config below
	maxVerdictBatch      = 64
	maxVerdictBatchBytes = 32 * 1024
	verdictChanBuffer    = 1024

	// ipCtIsReply is set in NFQA_CT_INFO for packets in the reply direction
	// of their conntrack entry.
	ipCtIsReply = 0x80
)

type offloadKey struct {
	ip      [4]byte // peer IP: client for inbound, remote for outbound
	dstIP   [4]byte // container IP for inbound; zero for outbound
	port    uint16  // service port for inbound, remote port for outbound
	inbound bool
}

type offloadCounterEntry struct {
	count    int
	allow    bool
	lastSeen time.Time
}

const offloadCounterShardCount = 16

type offloadCounterShard struct {
	mu     sync.Mutex
	counts map[offloadKey]*offloadCounterEntry
}

type offloadCounter struct {
	shards [offloadCounterShardCount]offloadCounterShard
}

func newOffloadCounter() *offloadCounter {
	c := &offloadCounter{}
	for i := range c.shards {
		c.shards[i].counts = make(map[offloadKey]*offloadCounterEntry)
	}
	return c
}

func (k offloadKey) shard() uint32 {
	// FNV-1a over the key, masking to the shard count.
	h := uint32(2166136261)
	for _, b := range k.ip {
		h ^= uint32(b)
		h *= 16777619
	}
	for _, b := range k.dstIP {
		h ^= uint32(b)
		h *= 16777619
	}
	h ^= uint32(k.port)
	h *= 16777619
	if k.inbound {
		h ^= 1
		h *= 16777619
	}
	return h % offloadCounterShardCount
}

func (c *offloadCounter) increment(key offloadKey, allow bool, threshold int) bool {
	shard := &c.shards[key.shard()]
	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, exists := shard.counts[key]
	if !exists {
		entry = &offloadCounterEntry{allow: allow}
		shard.counts[key] = entry
	} else if entry.allow != allow {
		// Verdict changed: require a fresh set of consistent verdicts.
		entry.count = 0
		entry.allow = allow
	}
	entry.count++
	entry.lastSeen = now
	if threshold > 0 && entry.count >= threshold {
		delete(shard.counts, key)
		return true
	}
	return false
}

func (c *offloadCounter) cleanup(maxAge time.Duration) {
	now := time.Now()
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		for key, entry := range shard.counts {
			if now.Sub(entry.lastSeen) > maxAge {
				delete(shard.counts, key)
			}
		}
		shard.mu.Unlock()
	}
}

type offloadEntry struct {
	ip       net.IP // client for inbound, remote for outbound
	dstIP    net.IP // container for inbound, nil for outbound
	port     uint16
	allow    bool
	inbound  bool
	ruleName string
}

// nftCtx holds the google/nftables connection and set references
// for runtime element operations (offload hot path).
// Uses transient mode (no AsLasting) to avoid stale netlink messages.
type nftCtx struct {
	conn            *nftables.Conn
	table           *nftables.Table
	offloadInAllow  *nftables.Set
	offloadInDrop   *nftables.Set
	offloadOutAllow *nftables.Set
	offloadOutDrop  *nftables.Set
	convergenceDrop *nftables.Set // nil if convergence disabled
}

// makeConcatKey builds a concatenated key for ipv4_addr . inet_service sets.
// Layout: [IPv4 4 bytes][port 2 bytes][padding 2 bytes] = 8 bytes.
func makeConcatKey(ip net.IP, port uint16) []byte {
	key := make([]byte, 8)
	copy(key[:4], ip.To4())
	binary.BigEndian.PutUint16(key[4:6], port)
	return key
}

// makeInboundConcatKey builds a key for inbound
// ipv4_addr . ipv4_addr . inet_service sets.
// Layout: [client IPv4 4B][container IPv4 4B][port 2B][padding 2B] = 12 bytes.
func makeInboundConcatKey(clientIP, containerIP net.IP, port uint16) []byte {
	key := make([]byte, 12)
	copy(key[:4], clientIP.To4())
	copy(key[4:8], containerIP.To4())
	binary.BigEndian.PutUint16(key[8:10], port)
	return key
}

// makeIPElemList builds a list of set elements for an ipv4_addr set.
func makeIPElemList(ips []net.IP, timeout time.Duration) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(ips))
	for _, ip := range ips {
		elems = append(elems, nftables.SetElement{
			Key:     ip.To4(),
			Timeout: timeout,
		})
	}
	return elems
}

type convergenceEntry struct {
	ports     map[uint16]struct{}
	firstSeen time.Time
}

type convergenceMap struct {
	mu sync.Mutex
	// Only drop verdicts are promoted. Promoting allow verdicts to a
	// whole-IP allow set would bypass all inspection for that IP and is too
	// easy to trigger with ordinary traffic.
	drop map[[4]byte]*convergenceEntry
}

func newConvergenceMap() *convergenceMap {
	return &convergenceMap{
		drop: make(map[[4]byte]*convergenceEntry),
	}
}

func (m *convergenceMap) add(ip [4]byte, port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.drop[ip]
	if !exists {
		entry = &convergenceEntry{
			ports:     make(map[uint16]struct{}),
			firstSeen: time.Now(),
		}
		m.drop[ip] = entry
	}
	entry.ports[port] = struct{}{}
}

// promoteEntries promotes IPs whose distinct port count reaches threshold and
// removes expired entries.
func promoteEntries(entries map[[4]byte]*convergenceEntry, threshold int, maxAge time.Duration) []net.IP {
	now := time.Now()
	var result []net.IP
	for ip, entry := range entries {
		if now.Sub(entry.firstSeen) > maxAge {
			delete(entries, ip)
			continue
		}
		if len(entry.ports) >= threshold {
			ipCopy := make(net.IP, 4)
			copy(ipCopy, ip[:])
			result = append(result, ipCopy)
			delete(entries, ip)
		}
	}
	return result
}

func (m *convergenceMap) checkAndPromote(threshold int, maxAge time.Duration) []net.IP {
	m.mu.Lock()
	defer m.mu.Unlock()
	return promoteEntries(m.drop, threshold, maxAge)
}

func generateNftRules(local, rst bool, protos nfProtocolConfig, queueCount int, offloadEnabled bool, offloadTTL time.Duration, convergenceEnabled bool, convergenceTTL time.Duration) (*nftTableSpec, error) {
	if local && rst {
		return nil, errors.New("tcp rst is not supported in local mode")
	}
	table := &nftTableSpec{
		Family: nftFamily,
		Table:  nftTable,
	}
	table.Defines = append(table.Defines, fmt.Sprintf("define ACCEPT_CTMARK=%d", nfqueueConnMarkAccept))
	table.Defines = append(table.Defines, fmt.Sprintf("define DROP_CTMARK=%d", nfqueueConnMarkDrop))
	if offloadEnabled {
		ttl := fmt.Sprintf("%ds", int(offloadTTL.Seconds()))
		for _, name := range []string{"offload_in_allow", "offload_in_drop"} {
			table.Sets = append(table.Sets, nftSetSpec{
				Name:    name,
				Type:    "ipv4_addr . ipv4_addr . inet_service",
				Timeout: ttl,
			})
		}
		for _, name := range []string{"offload_out_allow", "offload_out_drop"} {
			table.Sets = append(table.Sets, nftSetSpec{
				Name:    name,
				Type:    "ipv4_addr . inet_service",
				Timeout: ttl,
			})
		}
	}
	if convergenceEnabled {
		ttl := fmt.Sprintf("%ds", int(convergenceTTL.Seconds()))
		table.Sets = append(table.Sets, nftSetSpec{
			Name:    "convergence_drop",
			Type:    "ipv4_addr",
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
		// Let traffic from OpenGFW's own protected sockets bypass even the
		// convergence drop set.
		c.Rules = append(c.Rules, "meta mark $ACCEPT_CTMARK counter accept")
		if convergenceEnabled {
			// Drop rules are placed before both the connmark accept and the
			// allow sets so that an IP promoted to convergence_drop always
			// wins over a previously accepted connection or an allow entry.
			c.Rules = append(c.Rules, convergenceDropRules(protos, rst)...)
		}
		c.Rules = append(c.Rules, "ct mark $ACCEPT_CTMARK counter accept")
		if offloadEnabled {
			c.Rules = append(c.Rules, offloadLookupRules(protos, rst)...)
		}
		if rst {
			c.Rules = append(c.Rules, "ip protocol tcp ct mark $DROP_CTMARK counter reject with tcp reset")
		}
		c.Rules = append(c.Rules, "ct mark $DROP_CTMARK counter drop")
		c.Rules = append(c.Rules, protos.queueRules(queueCount)...)
	}
	return table, nil
}

func offloadLookupRules(protos nfProtocolConfig, rst bool) []string {
	var rules []string
	if protos.TCP {
		// Drop rules first: a key present in both sets must fail closed.
		if rst {
			rules = append(rules,
				"ip saddr . ip daddr . tcp dport @offload_in_drop counter reject with tcp reset",
				"ip daddr . ip saddr . tcp sport @offload_in_drop counter reject with tcp reset",
			)
		} else {
			rules = append(rules,
				"ip saddr . ip daddr . tcp dport @offload_in_drop counter drop",
				"ip daddr . ip saddr . tcp sport @offload_in_drop counter drop",
			)
		}
		rules = append(rules,
			"ip saddr . ip daddr . tcp dport @offload_in_allow accept",
			"ip daddr . ip saddr . tcp sport @offload_in_allow accept",
		)
		if rst {
			rules = append(rules,
				"ip daddr . tcp dport @offload_out_drop counter reject with tcp reset",
				"ip saddr . tcp sport @offload_out_drop counter reject with tcp reset",
			)
		} else {
			rules = append(rules,
				"ip daddr . tcp dport @offload_out_drop counter drop",
				"ip saddr . tcp sport @offload_out_drop counter drop",
			)
		}
		rules = append(rules,
			"ip daddr . tcp dport @offload_out_allow accept",
			"ip saddr . tcp sport @offload_out_allow accept",
		)
	}
	if protos.UDP {
		rules = append(rules,
			"ip saddr . ip daddr . udp dport @offload_in_drop counter drop",
			"ip daddr . ip saddr . udp sport @offload_in_drop counter drop",
			"ip saddr . ip daddr . udp dport @offload_in_allow accept",
			"ip daddr . ip saddr . udp sport @offload_in_allow accept",
			"ip daddr . udp dport @offload_out_drop counter drop",
			"ip saddr . udp sport @offload_out_drop counter drop",
			"ip daddr . udp dport @offload_out_allow accept",
			"ip saddr . udp sport @offload_out_allow accept",
		)
	}
	return rules
}

// convergenceDropRules drops (or resets, for TCP) all traffic from/to an IP
// that has been promoted to the convergence drop set. TCP RST rules come
// first so they take precedence over the catch-all drop rules.
func convergenceDropRules(protos nfProtocolConfig, rst bool) []string {
	var rules []string
	if rst && protos.TCP {
		rules = append(rules,
			"ip protocol tcp ip saddr @convergence_drop counter reject with tcp reset",
			"ip protocol tcp ip daddr @convergence_drop counter reject with tcp reset",
		)
	}
	rules = append(rules,
		"ip saddr @convergence_drop counter drop",
		"ip daddr @convergence_drop counter drop",
	)
	return rules
}

// nfProtocolConfig controls which packets are queued for inspection.
type nfProtocolConfig struct {
	TCP  bool
	UDP  bool
	IPv4 bool
	IPv6 bool
}

// queueSpec returns the nftables queue statement for the configured number
// of queues. With more than one queue, the kernel distributes packets by
// flow hash so that all packets of a stream land on the same queue.
func queueSpec(queueCount int) string {
	if queueCount <= 1 {
		return fmt.Sprintf("queue num %d", nfqueueNum)
	}
	return fmt.Sprintf("queue num %d-%d", nfqueueNum, nfqueueNum+queueCount-1)
}

// queueRules returns the nftables queue rules to capture the configured
// protocols. Traffic that does not match is left untouched by the kernel.
func (c nfProtocolConfig) queueRules(queueCount int) []string {
	spec := queueSpec(queueCount) + " bypass"
	all := c.TCP && c.UDP && c.IPv4 && c.IPv6
	if all {
		return []string{"counter " + spec}
	}
	var rules []string
	if c.IPv4 && c.TCP {
		rules = append(rules, "meta nfproto ipv4 meta l4proto tcp counter "+spec)
	}
	if c.IPv4 && c.UDP {
		rules = append(rules, "meta nfproto ipv4 meta l4proto udp counter "+spec)
	}
	if c.IPv6 && c.TCP {
		rules = append(rules, "meta nfproto ipv6 meta l4proto tcp counter "+spec)
	}
	if c.IPv6 && c.UDP {
		rules = append(rules, "meta nfproto ipv6 meta l4proto udp counter "+spec)
	}
	return rules
}

var _ PacketIO = (*nfqueuePacketIO)(nil)

var errNotNFQueuePacket = errors.New("not an NFQueue packet")

// nfqueueQueue represents one NFQUEUE and its dedicated verdict sender.
type nfqueueQueue struct {
	num    uint16
	family uint8
	n      *nfqueue.Nfqueue

	verdictCh chan verdictRequest
	done      chan struct{}
	wg        sync.WaitGroup
}

// verdictRequest is a pending verdict queued by a worker. Converting it to a
// netlink message happens in the queue's sender goroutine, so workers do not
// pay for message marshaling or the netlink syscall.
type verdictRequest struct {
	id      uint32
	verdict int
	mark    uint32
	hasMark bool
	payload []byte
}

type nfqueuePacketIO struct {
	queues     []*nfqueueQueue
	queueCount int

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

	offloadConvergence    int
	offloadConvergenceTTL time.Duration
	convergenceMap        *convergenceMap
	offloadWg             sync.WaitGroup

	nftCtx *nftCtx // google/nftables runtime context (nil if offload disabled)

	startPostCommand string
}

type NFQueuePacketIOConfig struct {
	QueueSize uint32
	// Queues is the number of NFQUEUE instances to use. Packets are
	// distributed across them by flow hash. Zero uses a default of
	// min(NumCPU, 8); set 1 to disable fanout.
	Queues                int
	ReadBuffer            int
	WriteBuffer           int
	Local                 bool
	RST                   bool
	TCP                   bool
	UDP                   bool
	IPv4                  bool
	IPv6                  bool
	Offload               bool
	OffloadTTL            time.Duration
	OffloadThreshold      int
	OffloadCIDR           string
	OffloadConvergence    int
	OffloadConvergenceTTL time.Duration
	StartPostCommand      string
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
	queueCount := config.Queues
	if queueCount <= 0 {
		queueCount = runtime.NumCPU()
		if queueCount > nfqueueDefaultQueues {
			queueCount = nfqueueDefaultQueues
		}
	}
	if queueCount > nfqueueMaxQueues {
		queueCount = nfqueueMaxQueues
	}
	queues := make([]*nfqueueQueue, 0, queueCount)
	stopQueues := func(list []*nfqueueQueue) {
		for _, q := range list {
			select {
			case <-q.done:
			default:
				close(q.done)
			}
			q.wg.Wait()
			_ = q.n.Close()
		}
	}
	for i := 0; i < queueCount; i++ {
		num := uint16(nfqueueNum + i)
		nq, err := nfqueue.Open(&nfqueue.Config{
			NfQueue:      num,
			AfFamily:     nfqueueAfFamily,
			MaxPacketLen: nfqueueMaxPacketLen,
			MaxQueueLen:  config.QueueSize,
			Copymode:     nfqueue.NfQnlCopyPacket,
			Flags:        nfqueue.NfQaCfgFlagConntrack,
		})
		if err != nil {
			stopQueues(queues)
			return nil, err
		}
		if config.ReadBuffer > 0 {
			err = nq.Con.SetReadBuffer(config.ReadBuffer)
			if err != nil {
				_ = nq.Close()
				stopQueues(queues)
				return nil, err
			}
		}
		if config.WriteBuffer > 0 {
			err = nq.Con.SetWriteBuffer(config.WriteBuffer)
			if err != nil {
				_ = nq.Close()
				stopQueues(queues)
				return nil, err
			}
		}
		q := &nfqueueQueue{
			num:       num,
			family:    nfqueueAfFamily,
			n:         nq,
			verdictCh: make(chan verdictRequest, verdictChanBuffer),
			done:      make(chan struct{}),
		}
		q.wg.Add(1)
		go func(q *nfqueueQueue) {
			defer q.wg.Done()
			q.verdictWorker()
		}(q)
		queues = append(queues, q)
	}
	var offloadCIDR *net.IPNet
	if config.Offload {
		if config.OffloadCIDR == "" {
			stopQueues(queues)
			return nil, errors.New("offloadCidr is required when offload is enabled")
		}
		_, cidr, err := net.ParseCIDR(config.OffloadCIDR)
		if err != nil {
			stopQueues(queues)
			return nil, fmt.Errorf("invalid offloadCidr: %w", err)
		}
		offloadCIDR = cidr
		if config.OffloadTTL == 0 {
			config.OffloadTTL = 60 * time.Second
		}
		if config.OffloadThreshold <= 0 {
			config.OffloadThreshold = 3
		}
		if config.OffloadConvergence > 0 && config.OffloadConvergenceTTL == 0 {
			config.OffloadConvergenceTTL = 30 * time.Minute
		}
	}
	io := &nfqueuePacketIO{
		queues:     queues,
		queueCount: len(queues),
		local:      config.Local,
		rst:        config.RST,
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
		io.offloadConvergence = config.OffloadConvergence
		io.offloadConvergenceTTL = config.OffloadConvergenceTTL
		if io.offloadConvergence > 0 {
			io.convergenceMap = newConvergenceMap()
		}
		if err := io.initNft(); err != nil {
			stopQueues(io.queues)
			return nil, fmt.Errorf("init nftables: %w", err)
		}
		io.offloadWg.Add(2)
		go func() {
			defer io.offloadWg.Done()
			io.offloadWorker()
		}()
		go func() {
			defer io.offloadWg.Done()
			io.offloadCleanup()
		}()
	}
	io.startPostCommand = config.StartPostCommand
	return io, nil
}

// initNft creates the nftables table/chains/sets via text commands,
// then obtains set references via the Go API for runtime element operations.
func (n *nfqueuePacketIO) initNft() error {
	// Create full table (including rules) via text commands.
	// Rules with concatenated set lookups cannot be expressed via the Go API.
	if err := n.setupNft(n.local, n.rst, false, n.protos); err != nil {
		return err
	}
	// Mark table as set so Register() skips the redundant delete+recreate
	// that would destroy set references held by offloadWorker.
	n.rSet = true

	// Connect via Go API to get set references for runtime operations.
	// Transient mode: each Flush() creates its own socket, avoiding stale
	// netlink messages that cause "mismatched sequence" errors with AsLasting().
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connect: %w", err)
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable}

	offloadInAllow, err := conn.GetSetByName(table, "offload_in_allow")
	if err != nil {
		return fmt.Errorf("get offload_in_allow set: %w", err)
	}
	offloadInDrop, err := conn.GetSetByName(table, "offload_in_drop")
	if err != nil {
		return fmt.Errorf("get offload_in_drop set: %w", err)
	}
	offloadOutAllow, err := conn.GetSetByName(table, "offload_out_allow")
	if err != nil {
		return fmt.Errorf("get offload_out_allow set: %w", err)
	}
	offloadOutDrop, err := conn.GetSetByName(table, "offload_out_drop")
	if err != nil {
		return fmt.Errorf("get offload_out_drop set: %w", err)
	}
	var convergenceDrop *nftables.Set
	if n.offloadConvergence > 0 {
		convergenceDrop, _ = conn.GetSetByName(table, "convergence_drop")
	}

	n.nftCtx = &nftCtx{
		conn:            conn,
		table:           table,
		offloadInAllow:  offloadInAllow,
		offloadInDrop:   offloadInDrop,
		offloadOutAllow: offloadOutAllow,
		offloadOutDrop:  offloadOutDrop,
		convergenceDrop: convergenceDrop,
	}
	return nil
}

func (n *nfqueuePacketIO) Register(ctx context.Context, cb PacketCallback) error {
	for _, q := range n.queues {
		q := q
		err := q.n.RegisterWithErrorFunc(ctx,
			func(a nfqueue.Attribute) int {
				if ok, verdict := n.packetAttributeSanityCheck(a); !ok {
					if a.PacketID != nil {
						_ = q.n.SetVerdict(*a.PacketID, verdict)
					}
					return 0
				}
				p := &nfqueuePacket{
					id:       *a.PacketID,
					streamID: ctIDFromCtBytes(*a.Ct),
					data:     *a.Payload,
					queue:    q,
				}
				if a.CtInfo != nil {
					p.ctInfo = *a.CtInfo
					p.hasCt = true
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
	}
	if !n.rSet {
		err := n.setupNft(n.local, n.rst, false, n.protos)
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
	q := nP.queue
	switch v {
	case VerdictAccept:
		q.enqueue(verdictRequest{id: nP.id, verdict: nfqueue.NfAccept})
	case VerdictAcceptModify:
		// The caller may reuse its serialization buffer as soon as we
		// return, so take a copy before handing the payload to the async
		// sender.
		var payload []byte
		if len(newPacket) > 0 {
			payload = make([]byte, len(newPacket))
			copy(payload, newPacket)
		}
		q.enqueue(verdictRequest{id: nP.id, verdict: nfqueue.NfAccept, payload: payload})
	case VerdictAcceptStream:
		if n.offloadEnabled {
			n.checkOffload(nP, true, ruleName)
		}
		q.enqueue(verdictRequest{
			id:      nP.id,
			verdict: nfqueue.NfAccept,
			mark:    nfqueueConnMarkAccept,
			hasMark: true,
		})
	case VerdictDrop:
		q.enqueue(verdictRequest{id: nP.id, verdict: nfqueue.NfDrop})
	case VerdictDropStream:
		if n.offloadEnabled {
			n.checkOffload(nP, false, ruleName)
		}
		q.enqueue(verdictRequest{
			id:      nP.id,
			verdict: nfqueue.NfDrop,
			mark:    nfqueueConnMarkDrop,
			hasMark: true,
		})
	default:
		// Invalid verdict, ignore for now
		return nil
	}
	return nil
}

func (n *nfqueuePacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.protectedDialer.DialContext(ctx, network, address)
}

func (n *nfqueuePacketIO) Close() error {
	if n.offloadEnabled {
		n.offloadCancel()
		// Wait for the offload goroutines to finish before tearing down the
		// nftables connection they use.
		n.offloadWg.Wait()
	}
	// Stop verdict senders before closing their netlink sockets.
	for _, q := range n.queues {
		select {
		case <-q.done:
		default:
			close(q.done)
		}
		q.wg.Wait()
	}
	if n.nftCtx != nil {
		n.nftCtx.conn.DelTable(n.nftCtx.table)
		_ = n.nftCtx.conn.Flush()
		n.nftCtx = nil
		n.rSet = false
	} else if n.rSet {
		_ = n.setupNft(n.local, n.rst, true, n.protos)
		n.rSet = false
	}
	var firstErr error
	for _, q := range n.queues {
		if err := q.n.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (n *nfqueuePacketIO) setupNft(local, rst, remove bool, protos nfProtocolConfig) error {
	rules, err := generateNftRules(local, rst, protos, n.queueCount, n.offloadEnabled, n.offloadTTL, n.offloadConvergence > 0, n.offloadConvergenceTTL)
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
	queue    *nfqueueQueue
	ctInfo   uint32
	hasCt    bool
}

// reply reports whether the packet is in the reply direction of its
// conntrack entry. NFQA_CT_INFO may be delivered in native or network byte
// order depending on the kernel, so accept either position of the reply bit.
func (p *nfqueuePacket) reply() bool {
	if !p.hasCt {
		return false
	}
	return p.ctInfo&ipCtIsReply != 0 || p.ctInfo&(ipCtIsReply<<24) != 0
}

func (p *nfqueuePacket) StreamID() uint32 {
	return p.streamID
}

func (p *nfqueuePacket) Data() []byte {
	return p.data
}

// enqueue hands a verdict to the queue's sender goroutine. It blocks when the
// buffer is full (backpressure) and returns silently once the queue is shut
// down, in which case the kernel releases the packet when the socket closes.
func (q *nfqueueQueue) enqueue(req verdictRequest) {
	select {
	case q.verdictCh <- req:
	case <-q.done:
	}
}

// verdictWorker collects pending verdicts and writes them to the kernel with
// one sendmsg per batch instead of one syscall per packet.
func (q *nfqueueQueue) verdictWorker() {
	msgs := make([]netlink.Message, 0, maxVerdictBatch)
	batchBytes := 0
	for {
		select {
		case req := <-q.verdictCh:
			msgs = msgs[:0]
			batchBytes = 0
			msgs = appendVerdictMessage(msgs, q.num, q.family, req)
			batchBytes += len(msgs[len(msgs)-1].Data) + 16
		drain:
			for len(msgs) < maxVerdictBatch && batchBytes < maxVerdictBatchBytes {
				select {
				case req := <-q.verdictCh:
					msgs = appendVerdictMessage(msgs, q.num, q.family, req)
					batchBytes += len(msgs[len(msgs)-1].Data) + 16
				default:
					break drain
				}
			}
			if len(msgs) > 0 {
				if _, err := q.n.Con.SendMessages(msgs); err != nil {
					// If the batch is rejected (for example because one
					// message is too large), retry individually so a single
					// bad verdict does not discard the rest.
					for i := range msgs {
						_, _ = q.n.Con.SendMessages(msgs[i : i+1])
					}
				}
				// Drop references to payload buffers held by the batch.
				clear(msgs)
			}
		case <-q.done:
			return
		}
	}
}

// appendNetlinkAttr appends a netlink attribute (header + data + padding).
func appendNetlinkAttr(dst []byte, typ uint16, data []byte) []byte {
	off := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.NativeEndian.PutUint16(dst[off:off+2], uint16(4+len(data)))
	binary.NativeEndian.PutUint16(dst[off+2:off+4], typ)
	dst = append(dst, data...)
	for len(dst)&3 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

// appendVerdictMessage builds an NFQNL_MSG_VERDICT netlink message. It
// replicates the wire format used by go-nfqueue so that verdicts can be
// batched with netlink.Conn.SendMessages.
func appendVerdictMessage(msgs []netlink.Message, queueNum uint16, family uint8, req verdictRequest) []netlink.Message {
	size := 4 + 12 + 4 + len(req.payload) + 3
	if req.hasMark {
		size += 12
	}
	data := make([]byte, 0, size)
	// nfgenmsg: address family, version, resource id (queue number).
	data = append(data, family, nfnetlinkVersion, byte(queueNum>>8), byte(queueNum))

	var verdictHdr [8]byte
	binary.BigEndian.PutUint32(verdictHdr[0:4], uint32(req.verdict))
	binary.BigEndian.PutUint32(verdictHdr[4:8], req.id)
	data = appendNetlinkAttr(data, nfqnlVerAttrHdr, verdictHdr[:])

	if req.hasMark {
		var markBuf [4]byte
		binary.BigEndian.PutUint32(markBuf[:], req.mark)
		inner := appendNetlinkAttr(nil, nfqnlAttrMark, markBuf[:])
		data = appendNetlinkAttr(data, netlink.Nested|nfqnlAttrCt, inner)
	}
	if len(req.payload) > 0 {
		data = appendNetlinkAttr(data, nfqnlAttrPayload, req.payload)
	}

	msgs = append(msgs, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((nfqnlSubsysQueue << 8) | nfqnlMsgVerdict),
			Flags: netlink.Request,
		},
		Data: data,
	})
	return msgs
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
	// Parse netlink attributes manually instead of calling
	// netlink.UnmarshalAttributes, which allocates a slice for every packet.
	// We only need CTA_ID (12).
	for len(ct) >= 4 {
		length := int(binary.NativeEndian.Uint16(ct[0:2]))
		attrType := binary.NativeEndian.Uint16(ct[2:4]) & 0x3fff
		if length < 4 || length > len(ct) {
			return 0
		}
		if attrType == 12 { // CTA_ID
			if length < 8 {
				return 0
			}
			return binary.BigEndian.Uint32(ct[4:8])
		}
		// Attributes are 4-byte aligned.
		aligned := (length + 3) &^ 3
		if aligned > len(ct) {
			return 0
		}
		ct = ct[aligned:]
	}
	return 0
}

// offloadKeyFor returns the stable offload key for a packet. Inbound keys use
// the client IP and the destination service port; outbound keys use the remote
// IP and remote port. The key is normalized to the original (request)
// direction first, so reply packets do not create bogus outbound entries with
// ephemeral client ports.
func offloadKeyFor(srcIP, dstIP [4]byte, srcPort, dstPort uint16, reply bool, cidr *net.IPNet) (offloadKey, bool) {
	if reply {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	if cidr.Contains(net.IP(dstIP[:])) {
		return offloadKey{ip: srcIP, dstIP: dstIP, port: dstPort, inbound: true}, true
	}
	if cidr.Contains(net.IP(srcIP[:])) {
		return offloadKey{ip: dstIP, port: dstPort, inbound: false}, true
	}
	return offloadKey{}, false
}

func (n *nfqueuePacketIO) checkOffload(p *nfqueuePacket, allow bool, ruleName string) {
	data := p.data
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

	key, ok := offloadKeyFor(srcIP, dstIP, srcPort, dstPort, p.reply(), n.offloadCIDR)
	if !ok {
		return
	}

	if n.offloadCounter.increment(key, allow, n.offloadThreshold) {
		entry := offloadEntry{
			ip:       net.IP(key.ip[:]),
			port:     key.port,
			allow:    allow,
			inbound:  key.inbound,
			ruleName: ruleName,
		}
		if key.inbound {
			entry.dstIP = net.IP(key.dstIP[:])
		}
		select {
		case n.offloadCh <- entry:
		default:
		}
	}
}

func (n *nfqueuePacketIO) offloadWorker() {
	// maxOffloadBatch bounds how many set elements are accumulated before
	// a single nftables flush. Batching avoids opening/closing a netlink
	// socket for every offloaded stream.
	const maxOffloadBatch = 256
	inAllow := make([]nftables.SetElement, 0, maxOffloadBatch)
	inDrop := make([]nftables.SetElement, 0, maxOffloadBatch)
	outAllow := make([]nftables.SetElement, 0, maxOffloadBatch)
	outDrop := make([]nftables.SetElement, 0, maxOffloadBatch)

	appendElement := func(e offloadEntry) {
		var list *[]nftables.SetElement
		switch {
		case e.inbound && e.allow:
			list = &inAllow
		case e.inbound:
			list = &inDrop
		case e.allow:
			list = &outAllow
		default:
			list = &outDrop
		}
		key := makeConcatKey(e.ip, e.port)
		if e.inbound {
			key = makeInboundConcatKey(e.ip, e.dstIP, e.port)
		}
		elem := nftables.SetElement{
			Key:     key,
			Timeout: n.offloadTTL,
		}
		if e.ruleName != "" {
			elem.Comment = e.ruleName
		}
		*list = append(*list, elem)
		if !e.allow && n.convergenceMap != nil {
			var ip [4]byte
			copy(ip[:], e.ip.To4())
			n.convergenceMap.add(ip, e.port)
		}
	}

	for {
		select {
		case e := <-n.offloadCh:
			inAllow = inAllow[:0]
			inDrop = inDrop[:0]
			outAllow = outAllow[:0]
			outDrop = outDrop[:0]
			appendElement(e)
		drain:
			for len(inAllow)+len(inDrop)+len(outAllow)+len(outDrop) < maxOffloadBatch {
				select {
				case e2 := <-n.offloadCh:
					appendElement(e2)
				default:
					break drain
				}
			}

			added := false
			add := func(set *nftables.Set, elems []nftables.SetElement) {
				if len(elems) == 0 || set == nil {
					return
				}
				_ = n.nftCtx.conn.SetAddElements(set, elems)
				added = true
			}
			add(n.nftCtx.offloadInAllow, inAllow)
			add(n.nftCtx.offloadInDrop, inDrop)
			add(n.nftCtx.offloadOutAllow, outAllow)
			add(n.nftCtx.offloadOutDrop, outDrop)
			if added {
				_ = n.nftCtx.conn.Flush()
			}

			if n.convergenceMap != nil {
				dropIPs := n.convergenceMap.checkAndPromote(n.offloadConvergence, n.offloadTTL)
				if len(dropIPs) > 0 && n.nftCtx.convergenceDrop != nil {
					_ = n.nftCtx.conn.SetAddElements(n.nftCtx.convergenceDrop, makeIPElemList(dropIPs, n.offloadConvergenceTTL))
					_ = n.nftCtx.conn.Flush()
				}
			}
		case <-n.offloadCtx.Done():
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
