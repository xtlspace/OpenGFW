package engine

import (
	"context"
	"sync"
	"time"

	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/bwmarrin/snowflake"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

const (
	defaultChanSize                         = 1024
	defaultTCPMaxBufferedPagesTotal         = 4096
	defaultTCPMaxBufferedPagesPerConnection = 64
	defaultUDPMaxStreams                    = 4096

	// tcpFlushInterval is how often the reassembler is flushed to close
	// idle/abandoned streams.
	tcpFlushInterval = 5 * time.Second
	// tcpStreamTimeout is how long a stream can stay idle before the
	// reassembler closes and releases it from the stream pool.
	tcpStreamTimeout = 5 * time.Minute
)

type workerPacket struct {
	StreamID uint32
	Data     []byte
	Packet   io.Packet
}

type worker struct {
	id         int
	packetChan chan *workerPacket
	logger     Logger
	packetIO   io.PacketIO
	done       chan struct{}

	tcpStreamFactory *tcpStreamFactory
	tcpStreamPool    *reassembly.StreamPool
	tcpAssembler     *reassembly.Assembler

	udpStreamFactory *udpStreamFactory
	udpStreamManager *udpStreamManager

	// packetPool recycles workerPacket structs to avoid one heap allocation
	// per packet on the IO read goroutine.
	packetPool sync.Pool

	// Per-worker contexts reused for every packet. Reassembly and stream
	// matching only use them synchronously, so they can be shared within
	// the worker goroutine.
	tcpCtx tcpContext
	udpCtx udpContext

	modSerializeBuffer gopacket.SerializeBuffer
}

type workerConfig struct {
	ID                         int
	ChanSize                   int
	Logger                     Logger
	Ruleset                    ruleset.Ruleset
	TCPMaxBufferedPagesTotal   int
	TCPMaxBufferedPagesPerConn int
	UDPMaxStreams              int
	PacketIO                   io.PacketIO
}

func (c *workerConfig) fillDefaults() {
	if c.ChanSize <= 0 {
		c.ChanSize = defaultChanSize
	}
	if c.TCPMaxBufferedPagesTotal <= 0 {
		c.TCPMaxBufferedPagesTotal = defaultTCPMaxBufferedPagesTotal
	}
	if c.TCPMaxBufferedPagesPerConn <= 0 {
		c.TCPMaxBufferedPagesPerConn = defaultTCPMaxBufferedPagesPerConnection
	}
	if c.UDPMaxStreams <= 0 {
		c.UDPMaxStreams = defaultUDPMaxStreams
	}
}

func newWorker(config workerConfig) (*worker, error) {
	config.fillDefaults()
	sfNode, err := snowflake.NewNode(int64(config.ID))
	if err != nil {
		return nil, err
	}
	tcpSF := &tcpStreamFactory{
		WorkerID: config.ID,
		Logger:   config.Logger,
		Node:     sfNode,
		Ruleset:  config.Ruleset,
	}
	tcpStreamPool := reassembly.NewStreamPool(tcpSF)
	tcpAssembler := reassembly.NewAssembler(tcpStreamPool)
	tcpAssembler.MaxBufferedPagesTotal = config.TCPMaxBufferedPagesTotal
	tcpAssembler.MaxBufferedPagesPerConnection = config.TCPMaxBufferedPagesPerConn
	udpSF := &udpStreamFactory{
		WorkerID: config.ID,
		Logger:   config.Logger,
		Node:     sfNode,
		Ruleset:  config.Ruleset,
	}
	udpSM, err := newUDPStreamManager(udpSF, config.UDPMaxStreams)
	if err != nil {
		return nil, err
	}
	w := &worker{
		id:                 config.ID,
		packetChan:         make(chan *workerPacket, config.ChanSize),
		logger:             config.Logger,
		packetIO:           config.PacketIO,
		done:               make(chan struct{}),
		tcpStreamFactory:   tcpSF,
		tcpStreamPool:      tcpStreamPool,
		tcpAssembler:       tcpAssembler,
		udpStreamFactory:   udpSF,
		udpStreamManager:   udpSM,
		modSerializeBuffer: gopacket.NewSerializeBuffer(),
	}
	w.packetPool.New = func() any { return &workerPacket{} }
	return w, nil
}

// Feed hands a packet to this worker. It reports false if the worker has
// stopped, so the IO read goroutine never blocks forever during shutdown.
func (w *worker) Feed(p *workerPacket) bool {
	select {
	case w.packetChan <- p:
		return true
	case <-w.done:
		return false
	}
}

func (w *worker) Run(ctx context.Context) {
	w.logger.WorkerStart(w.id)
	defer w.logger.WorkerStop(w.id)
	defer close(w.done)
	flushTicker := time.NewTicker(tcpFlushInterval)
	defer flushTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flushTicker.C:
			// Close streams that have been idle for too long, so abandoned
			// connections don't accumulate in the reassembly stream pool.
			w.tcpAssembler.FlushCloseOlderThan(time.Now().Add(-tcpStreamTimeout))
		case wPkt := <-w.packetChan:
			if wPkt == nil {
				// Closed
				return
			}
			v, b, ruleName := w.handle(wPkt.StreamID, wPkt.Data)
			_ = w.packetIO.SetVerdict(wPkt.Packet, v, b, ruleName)
			// Release the packet back to the pool. Data and Packet are
			// cleared so the pool does not retain stream buffers.
			wPkt.Data = nil
			wPkt.Packet = nil
			w.packetPool.Put(wPkt)
		}
	}
}

func (w *worker) UpdateRuleset(r ruleset.Ruleset) error {
	if err := w.tcpStreamFactory.UpdateRuleset(r); err != nil {
		return err
	}
	return w.udpStreamFactory.UpdateRuleset(r)
}

func (w *worker) handle(streamID uint32, data []byte) (io.Verdict, []byte, string) {
	ipVersion := data[0] >> 4
	var layerType gopacket.LayerType
	if ipVersion == 4 {
		layerType = layers.LayerTypeIPv4
	} else {
		layerType = layers.LayerTypeIPv6
	}
	p := gopacket.NewPacket(data, layerType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	netLayer, trLayer := p.NetworkLayer(), p.TransportLayer()
	if netLayer == nil || trLayer == nil {
		// Invalid packet
		return io.VerdictAccept, nil, ""
	}
	ipFlow := netLayer.NetworkFlow()
	switch tr := trLayer.(type) {
	case *layers.TCP:
		v, rn := w.handleTCP(ipFlow, p.Metadata(), tr)
		return v, nil, rn
	case *layers.UDP:
		v, modPayload, ruleName := w.handleUDP(streamID, ipFlow, tr)
		if v == io.VerdictAcceptModify && modPayload != nil {
			tr.Payload = modPayload
			_ = tr.SetNetworkLayerForChecksum(netLayer)
			_ = w.modSerializeBuffer.Clear()
			err := gopacket.SerializePacket(w.modSerializeBuffer,
				gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}, p)
			if err != nil {
				// Just accept without modification for now
				return io.VerdictAccept, nil, ""
			}
			return v, w.modSerializeBuffer.Bytes(), ruleName
		}
		return v, nil, ruleName
	default:
		// Unsupported protocol
		return io.VerdictAccept, nil, ""
	}
}

func (w *worker) handleTCP(ipFlow gopacket.Flow, pMeta *gopacket.PacketMetadata, tcp *layers.TCP) (io.Verdict, string) {
	ctx := &w.tcpCtx
	ctx.PacketMetadata = pMeta
	ctx.Verdict = tcpVerdictAccept
	ctx.RuleName = ""
	w.tcpAssembler.AssembleWithContext(ipFlow, tcp, ctx)
	return io.Verdict(ctx.Verdict), ctx.RuleName
}

func (w *worker) handleUDP(streamID uint32, ipFlow gopacket.Flow, udp *layers.UDP) (io.Verdict, []byte, string) {
	ctx := &w.udpCtx
	ctx.Verdict = udpVerdictAccept
	ctx.Packet = nil
	ctx.RuleName = ""
	w.udpStreamManager.MatchWithContext(streamID, ipFlow, udp, ctx)
	return io.Verdict(ctx.Verdict), ctx.Packet, ctx.RuleName
}
