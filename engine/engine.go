package engine

import (
	"context"
	"runtime"

	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"
)

var _ Engine = (*engine)(nil)

type engine struct {
	logger  Logger
	io      io.PacketIO
	workers []*worker

	// workerMask is len(workers)-1 when the worker count is a power of two,
	// allowing modulo-free stream-to-worker load balancing.
	workerMask uint32
}

func NewEngine(config Config) (Engine, error) {
	workerCount := config.Workers
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	var err error
	workers := make([]*worker, workerCount)
	for i := range workers {
		workers[i], err = newWorker(workerConfig{
			ID:                         i,
			ChanSize:                   config.WorkerQueueSize,
			Logger:                     config.Logger,
			Ruleset:                    config.Ruleset,
			TCPMaxBufferedPagesTotal:   config.WorkerTCPMaxBufferedPagesTotal,
			TCPMaxBufferedPagesPerConn: config.WorkerTCPMaxBufferedPagesPerConn,
			UDPMaxStreams:              config.WorkerUDPMaxStreams,
			PacketIO:                   config.IO,
		})
		if err != nil {
			return nil, err
		}
	}
	var workerMask uint32
	if workerCount > 0 && workerCount&(workerCount-1) == 0 {
		workerMask = uint32(workerCount - 1)
	}
	return &engine{
		logger:     config.Logger,
		io:         config.IO,
		workers:    workers,
		workerMask: workerMask,
	}, nil
}

func (e *engine) UpdateRuleset(r ruleset.Ruleset) error {
	for _, w := range e.workers {
		if err := w.UpdateRuleset(r); err != nil {
			return err
		}
	}
	return nil
}

func (e *engine) Run(ctx context.Context) error {
	ioCtx, ioCancel := context.WithCancel(ctx)
	defer ioCancel() // Stop workers & IO

	// Start workers
	for _, w := range e.workers {
		go w.Run(ioCtx)
	}

	// Register IO callback
	errChan := make(chan error, 1)
	err := e.io.Register(ioCtx, func(p io.Packet, err error) bool {
		if err != nil {
			// Multiple queue readers may report errors concurrently; only the
			// first one matters, so never block the callback.
			select {
			case errChan <- err:
			default:
			}
			return false
		}
		return e.dispatch(p)
	})
	if err != nil {
		return err
	}

	// Block until IO errors or context is cancelled
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

// dispatch dispatches a packet to a worker.
func (e *engine) dispatch(p io.Packet) bool {
	data := p.Data()
	if len(data) < 1 {
		_ = e.io.SetVerdict(p, io.VerdictAcceptStream, nil, "")
		return true
	}
	ipVersion := data[0] >> 4
	if ipVersion != 4 && ipVersion != 6 {
		// Unsupported network layer
		_ = e.io.SetVerdict(p, io.VerdictAcceptStream, nil, "")
		return true
	}
	// Load balance by stream ID
	streamID := p.StreamID()
	var index uint32
	if e.workerMask != 0 {
		index = streamID & e.workerMask
	} else {
		index = streamID % uint32(len(e.workers))
	}
	w := e.workers[index]
	pkt := w.packetPool.Get().(*workerPacket)
	pkt.StreamID = streamID
	pkt.Data = data
	pkt.Packet = p
	if !w.Feed(pkt) {
		// The worker has stopped (shutdown). Recycle the packet and release
		// it so the IO read goroutine is never blocked indefinitely.
		pkt.Data = nil
		pkt.Packet = nil
		w.packetPool.Put(pkt)
		_ = e.io.SetVerdict(p, io.VerdictAccept, nil, "")
	}
	return true
}
