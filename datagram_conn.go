package cronet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/pipe"
)

const (
	// datagramConnQueueSize is how many received datagrams wait for ReadDatagram, and datagramConnQueueBytes how many
	// bytes of them. Past either, new ones are dropped.
	datagramConnQueueSize  = 256
	datagramConnQueueBytes = 1 << 20
	// datagramConnSlotSize is the capacity a slot of the queue starts with, and datagramConnSlotKeep the most it
	// keeps between datagrams: a capsule up to 64 KiB gets a buffer of its own, which goes once it is read.
	datagramConnSlotSize = 2048
	datagramConnSlotKeep = 4096
)

// ErrDatagramTruncated is returned by ReadDatagram with a datagram cut to the buffer given.
var ErrDatagramTruncated = errors.New("cronet: datagram truncated")

// errDatagramNotStarted matches os.ErrInvalid, as the error of BidirectionalConn.Start does.
var errDatagramNotStarted = fmt.Errorf("cronet: datagram stream not started: %w", os.ErrInvalid)

// datagramStreamHandle is what DatagramConn uses of a DatagramStream.
type datagramStreamHandle interface {
	Start(url string, headers map[string]string) bool
	Send(data []byte, allowCapsule bool) error
	MaxPayload() int
	DroppedCapsules() uint64
	Cancel()
	Destroy() bool
}

// DatagramConn is a DatagramStream with a receive queue, for a packet connection of the application: one per UDP
// socket. Reads and writes are safe from any number of goroutines and never wait for the network thread.
type DatagramConn struct {
	// access orders the calls into the stream against its destruction: they take it for reading, terminate for
	// writing. The stream is not used once destroyed is set.
	access    sync.RWMutex
	stream    datagramStreamHandle
	destroyed bool
	cancelled bool
	// cancelErr is the error of the end that OnCanceled brings: net.ErrClosed after Close, the error of the setup
	// context after it ended.
	cancelErr error
	stopSetup func() bool
	err       error

	ready   chan struct{}
	status  int
	headers map[string]string

	done      chan struct{}
	doneOnce  sync.Once
	closed    chan struct{}
	closeOnce sync.Once

	// The receive queue: a ring of slots whose buffers are kept, so that a datagram costs no allocation.
	queueAccess sync.Mutex
	queue       [datagramConnQueueSize][]byte
	queueHead   int
	queueLength int
	queueBytes  int
	readable    chan struct{}

	droppedReceive  atomic.Uint64
	droppedCapsules uint64 // under access, once destroyed

	readDeadline  pipe.Deadline
	writeDeadline pipe.Deadline
}

// CreateDatagramConn opens a connect-udp request to url with headers (see DatagramStream.Start). It does not wait for
// the node: WaitReady does, and datagrams can be written at once (in capsules until the node answers). ctx bounds
// the setup: if it ends before the node answers, the request is canceled; afterwards it has no effect.
//
// A library without datagram support gives a DatagramConn that has ended with ErrDatagramUnsupported.
func (e StreamEngine) CreateDatagramConn(ctx context.Context, url string, headers map[string]string) *DatagramConn {
	return newDatagramConn(ctx, func(callback DatagramStreamCallback) (datagramStreamHandle, error) {
		if err := checkDatagramSupport(); err != nil {
			return nil, err
		}
		return e.CreateDatagramStream(callback), nil
	}, url, headers)
}

func newDatagramConn(ctx context.Context, create func(DatagramStreamCallback) (datagramStreamHandle, error), url string, headers map[string]string) *DatagramConn {
	c := &DatagramConn{
		ready:         make(chan struct{}),
		done:          make(chan struct{}),
		closed:        make(chan struct{}),
		readable:      make(chan struct{}, 1),
		readDeadline:  pipe.MakeDeadline(),
		writeDeadline: pipe.MakeDeadline(),
	}
	stream, err := create(datagramConnHandler{c})
	if err != nil {
		c.terminate(err)
		return c
	}
	if err = ctx.Err(); err != nil {
		c.stream = stream
		c.terminate(err)
		return c
	}
	// Under access: the callbacks, which may come before Start returns, and the setup context see stream and
	// stopSetup set.
	c.access.Lock()
	c.stream = stream
	c.stopSetup = context.AfterFunc(ctx, func() {
		c.cancel(ctx.Err(), true)
	})
	started := stream.Start(url, headers)
	c.access.Unlock()
	if !started {
		c.terminate(errDatagramNotStarted)
	}
	return c
}

// cancel cancels the stream once; OnCanceled then ends the conn with err. With setupOnly, a stream the node has
// answered is left alone.
func (c *DatagramConn) cancel(err error, setupOnly bool) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.destroyed || c.cancelled {
		return
	}
	if setupOnly {
		select {
		case <-c.ready:
			return
		default:
		}
	}
	c.cancelled = true
	c.cancelErr = err
	c.stream.Cancel()
}

// terminate ends the conn with err and destroys the stream, once. It runs on the network thread in the terminal
// callbacks, where destroying is allowed: the deletion is posted.
func (c *DatagramConn) terminate(err error) {
	c.doneOnce.Do(func() {
		c.access.Lock()
		c.err = err
		if c.stream != nil {
			c.droppedCapsules = c.stream.DroppedCapsules()
			c.stream.Destroy()
		}
		c.destroyed = true
		stopSetup := c.stopSetup
		// Before Err() can return err: Done is closed when Err is set.
		close(c.done)
		c.access.Unlock()
		if stopSetup != nil {
			stopSetup()
		}
	})
}

// WaitReady waits for the response of the node: 200, 429 (limit), 503 (try later), or the response of the site (the
// feature is off, or the node is old: stay on UDP over TCP in this network). The error comes from OnFailed (with
// NetErrorMethodNotSupported when the node announces no HTTP/3 datagrams), OnCanceled, Close or ctx. A 200 without
// "niko-udp: 1" in headers is no success either (naive-udp-v1 §3.3): that check is the caller's.
func (c *DatagramConn) WaitReady(ctx context.Context) (status int, headers map[string]string, err error) {
	select {
	case <-c.ready:
		return c.status, c.headers, nil
	default:
	}
	select {
	case <-c.ready:
		return c.status, c.headers, nil
	case <-c.done:
		select {
		case <-c.ready:
			return c.status, c.headers, nil
		default:
		}
		return 0, nil, c.Err()
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

// ReadDatagram reads the next datagram into b, without an allocation. Up to 256 received datagrams, and 1 MiB of
// them, wait to be read; past that, new ones are dropped and counted (Dropped). A datagram longer than b is cut to len(b) and
// reported with ErrDatagramTruncated. Once the stream has ended, the datagrams still queued are read first, then the
// error of the end: io.EOF after a clean close by the node.
func (c *DatagramConn) ReadDatagram(ctx context.Context, b []byte) (n int, err error) {
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		if n, truncated, ok := c.dequeue(b); ok {
			if truncated {
				return n, ErrDatagramTruncated
			}
			return n, nil
		}
		select {
		case <-c.done:
			if n, truncated, ok := c.dequeue(b); ok {
				if truncated {
					return n, ErrDatagramTruncated
				}
				return n, nil
			}
			return 0, c.Err()
		default:
		}
		select {
		case <-c.readable:
		case <-c.done:
		case <-c.closed:
		case <-c.readDeadline.Wait():
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (c *DatagramConn) dequeue(b []byte) (n int, truncated bool, ok bool) {
	c.queueAccess.Lock()
	if c.queueLength == 0 {
		c.queueAccess.Unlock()
		return 0, false, false
	}
	slot := &c.queue[c.queueHead]
	n = copy(b, *slot)
	truncated = n < len(*slot)
	c.queueBytes -= len(*slot)
	if cap(*slot) > datagramConnSlotKeep {
		*slot = nil
	} else {
		*slot = (*slot)[:0]
	}
	c.queueHead = (c.queueHead + 1) % datagramConnQueueSize
	c.queueLength--
	more := c.queueLength > 0
	c.queueAccess.Unlock()
	if more {
		c.signalReadable()
	}
	return n, truncated, true
}

func (c *DatagramConn) enqueue(data []byte) {
	c.queueAccess.Lock()
	if c.queueLength == datagramConnQueueSize || c.queueBytes+len(data) > datagramConnQueueBytes {
		c.queueAccess.Unlock()
		c.droppedReceive.Add(1)
		return
	}
	slot := &c.queue[(c.queueHead+c.queueLength)%datagramConnQueueSize]
	if cap(*slot) < len(data) {
		*slot = make([]byte, 0, max(len(data), datagramConnSlotSize))
	}
	*slot = append((*slot)[:0], data...)
	c.queueLength++
	c.queueBytes += len(data)
	c.queueAccess.Unlock()
	c.signalReadable()
}

func (c *DatagramConn) signalReadable() {
	select {
	case c.readable <- struct{}{}:
	default:
	}
}

// WriteDatagram sends b, copied, without blocking; what does not fit in a QUIC datagram goes in a capsule
// (naive-udp-v1 §4.4). It returns the errors of DatagramStream.Send, ErrDatagramClosed once the stream has ended (Err
// tells why), net.ErrClosed after Close, and os.ErrDeadlineExceeded past the write deadline.
func (c *DatagramConn) WriteDatagram(b []byte) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	case <-c.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if c.destroyed {
		return ErrDatagramClosed
	}
	return c.stream.Send(b, true)
}

// MaxPayload is the payload that fits in one QUIC datagram: 0 until the node answers 200, and after the end.
func (c *DatagramConn) MaxPayload() int {
	c.access.RLock()
	defer c.access.RUnlock()
	if c.destroyed {
		return 0
	}
	return c.stream.MaxPayload()
}

// SetReadDeadline sets the deadline of ReadDatagram; the zero time removes it.
func (c *DatagramConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

// SetWriteDeadline sets the deadline of WriteDatagram, which never waits: past it, writes fail at once.
func (c *DatagramConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

// SetDeadline sets both deadlines.
func (c *DatagramConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

// Dropped counts the datagrams dropped because the receive queue was full (256 datagrams or 1 MiB), and those the
// library dropped after it took them (see DatagramStream.DroppedCapsules).
func (c *DatagramConn) Dropped() (receive, capsules uint64) {
	c.access.RLock()
	if c.destroyed {
		capsules = c.droppedCapsules
	} else {
		capsules = c.stream.DroppedCapsules()
	}
	c.access.RUnlock()
	return c.droppedReceive.Load(), capsules
}

// Done is closed when the stream has ended: Err tells why.
func (c *DatagramConn) Done() <-chan struct{} {
	return c.done
}

// Err is the error the stream ended with: io.EOF after a clean close by the node (idle, or a status other than 200),
// a NetError after OnFailed, net.ErrClosed after Close, the error of the setup context. Nil until Done is closed.
func (c *DatagramConn) Err() error {
	c.access.RLock()
	defer c.access.RUnlock()
	return c.err
}

// Close cancels the stream. Reads and writes fail with net.ErrClosed from then on; Done is closed once the library
// confirms. A second Close returns net.ErrClosed.
func (c *DatagramConn) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		close(c.closed)
	})
	if !first {
		return net.ErrClosed
	}
	c.cancel(net.ErrClosed, false)
	return nil
}

// datagramConnHandler is the DatagramStreamCallback of a DatagramConn, kept apart to leave its methods out of the
// API of DatagramConn.
type datagramConnHandler struct {
	*DatagramConn
}

func (h datagramConnHandler) OnReady(stream DatagramStream, status int, headers map[string]string) {
	c := h.DatagramConn
	select {
	case <-c.ready:
		return
	default:
	}
	c.status = status
	c.headers = headers
	close(c.ready)
	c.access.RLock()
	stopSetup := c.stopSetup
	c.access.RUnlock()
	if stopSetup != nil {
		stopSetup()
	}
}

func (h datagramConnHandler) OnDatagram(stream DatagramStream, data []byte) {
	select {
	case <-h.closed:
		return
	default:
	}
	h.enqueue(data)
}

func (h datagramConnHandler) OnMaxPayloadChanged(stream DatagramStream, maxPayload int) {
}

func (h datagramConnHandler) OnClosed(stream DatagramStream) {
	h.terminate(io.EOF)
}

func (h datagramConnHandler) OnFailed(stream DatagramStream, netError int) {
	h.terminate(NetError(netError))
}

func (h datagramConnHandler) OnCanceled(stream DatagramStream) {
	h.access.RLock()
	err := h.cancelErr
	h.access.RUnlock()
	if err == nil {
		err = context.Canceled
	}
	h.terminate(err)
}
