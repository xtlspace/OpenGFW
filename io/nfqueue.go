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
	h ^= uint32(k.port)
	h *= 16777619
	return h % offloadCounterShardCount
}

func (c *offloadCounter) increment(key offloadKey, allow bool, threshold int) bool {
	shard := &c.shards[key.shard()]
	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, exists := shard.counts[key]
	if !exists {
		shard.counts[key] = &offloadCounterEntry{
			count:    1,
			allow:    allow,
			lastSeen: now,
		}
		return false
	}
	entry.count++
	entry.allow = allow
	entry.lastSeen = now
	if entry.count >= threshold {
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
	ip       net.IP
	port     uint16
	allow    bool
	ruleName string
}

// nftCtx holds the google/nftables connection and set references
// for runtime element operations (offload hot path).
// Uses transient mode (no AsLasting) to avoid stale netlink messages.
type nftCtx struct {
	conn             *nftables.Conn
	table            *nftables.Table
	offloadAllow     *nftables.Set
	offloadDrop      *nftables.Set
	convergenceAllow *nftables.Set // nil if convergence disabled
}

// makeConcatKey builds a concatenated key for ipv4_addr . inet_service sets.
// Layout: [IPv4 4 bytes][port 2 bytes][padding 2 bytes] = 8 bytes.
func makeConcatKey(ip net.IP, port uint16) []byte {
	key := make([]byte, 8)
	copy(key[:4], ip.To4())
	binary.BigEndian.PutUint16(key[4:6], port)
	return key
}

type convergenceEntry struct {
	ports     map[uint16]struct{}
	firstSeen time.Time
}

type convergenceMap struct {
	mu      sync.Mutex
	entries map[[4]byte]*convergenceEntry
}

func newConvergenceMap() *convergenceMap {
	return &convergenceMap{
		entries: make(map[[4]byte]*convergenceEntry),
	}
}

func (m *convergenceMap) add(ip [4]byte, port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.entries[ip]
	if !exists {
		entry = &convergenceEntry{
			ports:     make(map[uint16]struct{}),
			firstSeen: time.Now(),
		}
		m.entries[ip] = entry
	}
	entry.ports[port] = struct{}{}
}

func (m *convergenceMap) checkAndPromote(threshold int, maxAge time.Duration) []net.IP {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var result []net.IP
	for ip, entry := range m.entries {
		if now.Sub(entry.firstSeen) > maxAge {
			delete(m.entries, ip)
			continue
		}
		if len(entry.ports) >= threshold {
			ipCopy := make(net.IP, 4)
			copy(ipCopy, ip[:])
			result = append(result, ipCopy)
			delete(m.entries, ip)
		}
	}
	return result
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
	if convergenceEnabled {
		ttl := fmt.Sprintf("%ds", int(convergenceTTL.Seconds()))
		table.Sets = append(table.Sets, nftSetSpec{
			Name:    "convergence_allow",
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
		c.Rules = append(c.Rules, "ct mark $ACCEPT_CTMARK counter accept")
		if convergenceEnabled {
			c.Rules = append(c.Rules, convergenceLookupRules()...)
		}
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

func convergenceLookupRules() []string {
	var rules []string
	rules = append(rules, "ip saddr @convergence_allow accept")
	rules = append(rules, "ip daddr @convergence_allow accept")
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

	offloadAllow, err := conn.GetSetByName(table, "offload_allow")
	if err != nil {
		return fmt.Errorf("get offload_allow set: %w", err)
	}
	offloadDrop, err := conn.GetSetByName(table, "offload_drop")
	if err != nil {
		return fmt.Errorf("get offload_drop set: %w", err)
	}
	var convergenceAllow *nftables.Set
	if n.offloadConvergence > 0 {
		convergenceAllow, _ = conn.GetSetByName(table, "convergence_allow")
	}

	n.nftCtx = &nftCtx{
		conn:             conn,
		table:            table,
		offloadAllow:     offloadAllow,
		offloadDrop:      offloadDrop,
		convergenceAllow: convergenceAllow,
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
			n.checkOffload(nP.data, true, ruleName)
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
			n.checkOffload(nP.data, false, ruleName)
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
	// maxOffloadBatch bounds how many set elements are accumulated before
	// a single nftables flush. Batching avoids opening/closing a netlink
	// socket for every offloaded stream.
	const maxOffloadBatch = 256
	allowElems := make([]nftables.SetElement, 0, maxOffloadBatch)
	dropElems := make([]nftables.SetElement, 0, maxOffloadBatch)

	appendElement := func(e offloadEntry) {
		set := &allowElems
		if !e.allow {
			set = &dropElems
		}
		elem := nftables.SetElement{
			Key:     makeConcatKey(e.ip, e.port),
			Timeout: n.offloadTTL,
		}
		if e.ruleName != "" {
			elem.Comment = e.ruleName
		}
		*set = append(*set, elem)
		if n.convergenceMap != nil {
			var ip [4]byte
			copy(ip[:], e.ip.To4())
			n.convergenceMap.add(ip, e.port)
		}
	}

	for {
		select {
		case e := <-n.offloadCh:
			allowElems = allowElems[:0]
			dropElems = dropElems[:0]
			appendElement(e)
		drain:
			for len(allowElems)+len(dropElems) < maxOffloadBatch {
				select {
				case e2 := <-n.offloadCh:
					appendElement(e2)
				default:
					break drain
				}
			}

			if len(allowElems) > 0 {
				_ = n.nftCtx.conn.SetAddElements(n.nftCtx.offloadAllow, allowElems)
			}
			if len(dropElems) > 0 {
				_ = n.nftCtx.conn.SetAddElements(n.nftCtx.offloadDrop, dropElems)
			}
			if len(allowElems) > 0 || len(dropElems) > 0 {
				_ = n.nftCtx.conn.Flush()
			}

			if n.convergenceMap != nil {
				ips := n.convergenceMap.checkAndPromote(n.offloadConvergence, n.offloadTTL)
				if len(ips) > 0 && n.nftCtx.convergenceAllow != nil {
					elems := make([]nftables.SetElement, 0, len(ips))
					for _, ip := range ips {
						elems = append(elems, nftables.SetElement{
							Key:     ip.To4(),
							Timeout: n.offloadConvergenceTTL,
						})
					}
					_ = n.nftCtx.conn.SetAddElements(n.nftCtx.convergenceAllow, elems)
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
