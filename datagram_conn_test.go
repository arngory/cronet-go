package cronet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDatagramStream stands for the library: its callbacks run one at a time on a goroutine of their own, the
// network thread, and it reports any call made after Destroy.
type fakeDatagramStream struct {
	t        *testing.T
	callback DatagramStreamCallback
	network  chan func()
	stopped  chan struct{}

	access       sync.Mutex
	started      bool
	destroyed    bool
	ended        bool // a terminal callback was made
	cancelCount  int
	destroyCount int
	sent         [][]byte
	startResult  bool
	sendErr      error

	maxPayload      atomic.Int64
	droppedCapsules atomic.Uint64
	afterDestroy    atomic.Int64
	sendCount       atomic.Int64
}

func newFakeDatagramStream(t *testing.T) *fakeDatagramStream {
	s := &fakeDatagramStream{
		t:           t,
		network:     make(chan func(), 1024),
		stopped:     make(chan struct{}),
		startResult: true,
	}
	go func() {
		defer close(s.stopped)
		for task := range s.network {
			task()
		}
	}()
	t.Cleanup(func() {
		close(s.network)
		<-s.stopped
		if n := s.afterDestroy.Load(); n != 0 {
			t.Errorf("%d calls into the stream after Destroy", n)
		}
	})
	return s
}

// create is the create function of newDatagramConn.
func (s *fakeDatagramStream) create(callback DatagramStreamCallback) (datagramStreamHandle, error) {
	s.callback = callback
	return s, nil
}

func (s *fakeDatagramStream) checkLive() bool {
	if s.destroyed {
		s.afterDestroy.Add(1)
		return false
	}
	return true
}

func (s *fakeDatagramStream) Start(url string, headers map[string]string) bool {
	s.access.Lock()
	defer s.access.Unlock()
	s.checkLive()
	s.started = s.startResult
	return s.startResult
}

func (s *fakeDatagramStream) Send(data []byte, allowCapsule bool) error {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.checkLive() {
		return ErrDatagramClosed
	}
	s.sendCount.Add(1)
	if s.sendErr != nil {
		return s.sendErr
	}
	if !allowCapsule {
		s.t.Error("DatagramConn sent without allowing a capsule")
	}
	s.sent = append(s.sent, bytes.Clone(data))
	return nil
}

func (s *fakeDatagramStream) MaxPayload() int {
	s.access.Lock()
	defer s.access.Unlock()
	s.checkLive()
	return int(s.maxPayload.Load())
}

func (s *fakeDatagramStream) DroppedCapsules() uint64 {
	s.access.Lock()
	defer s.access.Unlock()
	s.checkLive()
	return s.droppedCapsules.Load()
}

// Cancel posts the cancellation, like the library: OnCanceled follows unless the stream has ended.
func (s *fakeDatagramStream) Cancel() {
	s.access.Lock()
	defer s.access.Unlock()
	s.checkLive()
	s.cancelCount++
	s.post(func() {
		if s.end() {
			s.callback.OnCanceled(DatagramStream{})
		}
	})
}

func (s *fakeDatagramStream) Destroy() bool {
	s.access.Lock()
	defer s.access.Unlock()
	s.checkLive()
	s.destroyed = true
	s.destroyCount++
	return true
}

func (s *fakeDatagramStream) post(task func()) {
	s.network <- task
}

// end marks the stream ended, and reports whether it was not already.
func (s *fakeDatagramStream) end() bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.ended || !s.started {
		return false
	}
	s.ended = true
	return true
}

// sync waits for the tasks posted so far to run.
func (s *fakeDatagramStream) sync() {
	done := make(chan struct{})
	s.post(func() { close(done) })
	<-done
}

func (s *fakeDatagramStream) ready(status int, headers map[string]string) {
	s.post(func() { s.callback.OnReady(DatagramStream{}, status, headers) })
}

// datagram delivers data in a buffer that is overwritten once the callback returns, as the library's is.
func (s *fakeDatagramStream) datagram(data []byte) {
	s.post(func() {
		buffer := bytes.Clone(data)
		s.callback.OnDatagram(DatagramStream{}, buffer)
		for i := range buffer {
			buffer[i] = 0xEE
		}
	})
}

func (s *fakeDatagramStream) closeStream() {
	s.post(func() {
		if s.end() {
			s.callback.OnClosed(DatagramStream{})
		}
	})
}

func (s *fakeDatagramStream) fail(netError NetError) {
	s.post(func() {
		if s.end() {
			s.callback.OnFailed(DatagramStream{}, int(netError))
		}
	})
}

func (s *fakeDatagramStream) counts() (cancels, destroys int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.cancelCount, s.destroyCount
}

func newTestDatagramConn(t *testing.T) (*DatagramConn, *fakeDatagramStream) {
	stream := newFakeDatagramStream(t)
	conn := newDatagramConn(context.Background(), stream.create, "https://example.org/.well-known/masque/udp/%2A/%2A/", map[string]string{"padding": "x"})
	return conn, stream
}

func waitDone(t *testing.T, conn *DatagramConn) {
	t.Helper()
	select {
	case <-conn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the conn did not end")
	}
}

func readOne(t *testing.T, conn *DatagramConn, size int) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buffer := make([]byte, size)
	n, err := conn.ReadDatagram(ctx, buffer)
	return buffer[:n], err
}

func TestDatagramConnReadyAndRead(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.maxPayload.Store(1200)
	stream.ready(200, map[string]string{":status": "200", "niko-udp": "1"})

	status, headers, err := conn.WaitReady(context.Background())
	if err != nil || status != 200 || headers["niko-udp"] != "1" {
		t.Fatalf("WaitReady = %d, %v, %v", status, headers, err)
	}
	if got := conn.MaxPayload(); got != 1200 {
		t.Fatalf("MaxPayload = %d", got)
	}
	for i := 0; i < 10; i++ {
		stream.datagram([]byte{byte(i), 1, 2, 3})
	}
	for i := 0; i < 10; i++ {
		data, err := readOne(t, conn, 64)
		if err != nil || !bytes.Equal(data, []byte{byte(i), 1, 2, 3}) {
			t.Fatalf("datagram %d = %x, %v", i, data, err)
		}
	}
	if err := conn.WriteDatagram([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	stream.access.Lock()
	sent := stream.sent
	stream.access.Unlock()
	if len(sent) != 1 || string(sent[0]) != "hello" {
		t.Fatalf("sent %q", sent)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, conn)
}

func TestDatagramConnWriteBeforeReady(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	if err := conn.WriteDatagram([]byte("early")); err != nil {
		t.Fatal(err)
	}
	if got := conn.MaxPayload(); got != 0 {
		t.Fatalf("MaxPayload before ready = %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := conn.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady = %v", err)
	}
	stream.ready(200, nil)
	if status, _, err := conn.WaitReady(context.Background()); status != 200 || err != nil {
		t.Fatalf("WaitReady = %d, %v", status, err)
	}
}

func TestDatagramConnQueueOverflow(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	const total = datagramConnQueueSize + 44
	for i := 0; i < total; i++ {
		stream.datagram([]byte{byte(i), byte(i >> 8)})
	}
	stream.sync()
	if receive, _ := conn.Dropped(); receive != total-datagramConnQueueSize {
		t.Fatalf("dropped %d, want %d", receive, total-datagramConnQueueSize)
	}
	// The oldest are kept: new datagrams are dropped.
	for i := 0; i < datagramConnQueueSize; i++ {
		data, err := readOne(t, conn, 8)
		if err != nil || !bytes.Equal(data, []byte{byte(i), byte(i >> 8)}) {
			t.Fatalf("datagram %d = %x, %v", i, data, err)
		}
	}
	// Room again.
	stream.datagram([]byte("after"))
	if data, err := readOne(t, conn, 8); err != nil || string(data) != "after" {
		t.Fatalf("after overflow: %q, %v", data, err)
	}
	if receive, _ := conn.Dropped(); receive != total-datagramConnQueueSize {
		t.Fatalf("dropped %d after reading", receive)
	}
}

func TestDatagramConnTruncation(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	long := bytes.Repeat([]byte("0123456789"), 10)
	stream.datagram(long)
	stream.datagram([]byte("next"))

	data, err := readOne(t, conn, 10)
	if !errors.Is(err, ErrDatagramTruncated) || !bytes.Equal(data, long[:10]) {
		t.Fatalf("truncated read = %q, %v", data, err)
	}
	if data, err := readOne(t, conn, 10); err != nil || string(data) != "next" {
		t.Fatalf("read after truncation = %q, %v", data, err)
	}
	// A capsule-sized datagram does not stay in the queue's buffers.
	huge := bytes.Repeat([]byte{7}, 65000)
	stream.datagram(huge)
	if data, err := readOne(t, conn, 70000); err != nil || !bytes.Equal(data, huge) {
		t.Fatalf("huge read: %d bytes, %v", len(data), err)
	}
	conn.queueAccess.Lock()
	defer conn.queueAccess.Unlock()
	for i, slot := range conn.queue {
		if cap(slot) > datagramConnSlotKeep {
			t.Fatalf("slot %d keeps %d bytes", i, cap(slot))
		}
	}
}

func TestDatagramConnReadDeadline(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)

	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	start := time.Now()
	_, err := readOne(t, conn, 8)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past deadline = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("deadline after %v", elapsed)
	}
	// An expired deadline fails reads at once, a queued datagram notwithstanding, as a socket does.
	stream.datagram([]byte("queued"))
	stream.sync()
	if _, err := readOne(t, conn, 8); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read with expired deadline = %v", err)
	}
	// Cleared, the queued datagram is read.
	conn.SetReadDeadline(time.Time{})
	if data, err := readOne(t, conn, 8); err != nil || string(data) != "queued" {
		t.Fatalf("read after clearing = %q, %v", data, err)
	}
	// A deadline set while a read waits wakes it.
	errs := make(chan error, 1)
	go func() {
		_, err := readOne(t, conn, 8)
		errs <- err
	}()
	time.Sleep(20 * time.Millisecond)
	conn.SetReadDeadline(time.Now())
	select {
	case err := <-errs:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("waiting read = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting read did not see the deadline")
	}
	// The context of the read.
	conn.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := conn.ReadDatagram(ctx, make([]byte, 8)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read with context = %v", err)
	}
}

func TestDatagramConnWriteDeadline(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if err := conn.WriteDatagram([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write past deadline = %v", err)
	}
	if n := stream.sendCount.Load(); n != 0 {
		t.Fatalf("%d sends past the deadline", n)
	}
	conn.SetDeadline(time.Time{})
	if err := conn.WriteDatagram([]byte("x")); err != nil {
		t.Fatalf("write after clearing = %v", err)
	}
}

func TestDatagramConnSendErrors(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	for _, want := range []error{ErrDatagramQueueFull, ErrDatagramTooLarge, ErrDatagramCapsuleTimeout, ErrDatagramClosed} {
		stream.access.Lock()
		stream.sendErr = want
		stream.access.Unlock()
		if err := conn.WriteDatagram([]byte("x")); err != want {
			t.Fatalf("WriteDatagram = %v, want %v", err, want)
		}
	}
}

func TestDatagramConnConcurrentWritesAndEnd(t *testing.T) {
	for round := 0; round < 20; round++ {
		conn, stream := newTestDatagramConn(t)
		stream.ready(200, nil)
		var wg sync.WaitGroup
		var accepted atomic.Int64
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload := []byte{byte(g)}
				for i := 0; i < 500; i++ {
					switch err := conn.WriteDatagram(payload); err {
					case nil:
						accepted.Add(1)
					case ErrDatagramClosed, net.ErrClosed:
						return
					default:
						t.Errorf("WriteDatagram = %v", err)
						return
					}
					_ = conn.MaxPayload()
					_, _ = conn.Dropped()
				}
			}()
		}
		if round%2 == 0 {
			stream.fail(NetErrorConnectionReset)
		} else {
			conn.Close()
		}
		wg.Wait()
		waitDone(t, conn)
		if got := stream.sendCount.Load(); got != accepted.Load() {
			t.Fatalf("stream took %d sends, writers saw %d", got, accepted.Load())
		}
		if _, destroys := stream.counts(); destroys != 1 {
			t.Fatalf("destroyed %d times", destroys)
		}
		if err := conn.WriteDatagram([]byte("late")); err != ErrDatagramClosed && err != net.ErrClosed {
			t.Fatalf("write after the end = %v", err)
		}
	}
}

func TestDatagramConnClose(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	stream.datagram([]byte("unread"))
	stream.sync()

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v", err)
	}
	if _, err := readOne(t, conn, 8); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close = %v", err)
	}
	if err := conn.WriteDatagram([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close = %v", err)
	}
	waitDone(t, conn)
	if !errors.Is(conn.Err(), net.ErrClosed) {
		t.Fatalf("Err after Close = %v", conn.Err())
	}
	stream.sync()
	if cancels, destroys := stream.counts(); cancels != 1 || destroys != 1 {
		t.Fatalf("cancels %d, destroys %d", cancels, destroys)
	}
	if got := conn.MaxPayload(); got != 0 {
		t.Fatalf("MaxPayload after the end = %d", got)
	}
}

// TestDatagramConnCloseAfterEnd: the stream ended before Close, which then cancels nothing.
func TestDatagramConnCloseAfterEnd(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	stream.closeStream()
	waitDone(t, conn)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	stream.sync()
	if cancels, destroys := stream.counts(); cancels != 0 || destroys != 1 {
		t.Fatalf("cancels %d, destroys %d", cancels, destroys)
	}
	if !errors.Is(conn.Err(), io.EOF) {
		t.Fatalf("Err = %v", conn.Err())
	}
}

// TestDatagramConnCloseRacesEnd: Close and the end of the stream cross; the library makes one terminal callback.
func TestDatagramConnCloseRacesEnd(t *testing.T) {
	for round := 0; round < 50; round++ {
		conn, stream := newTestDatagramConn(t)
		stream.ready(200, nil)
		stream.closeStream()
		conn.Close()
		waitDone(t, conn)
		stream.sync()
		if err := conn.Err(); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Err = %v", err)
		}
		if _, destroys := stream.counts(); destroys != 1 {
			t.Fatalf("destroyed %d times", destroys)
		}
	}
}

func TestDatagramConnNotOKThenClosed(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(429, map[string]string{":status": "429"})
	stream.closeStream()
	status, _, err := conn.WaitReady(context.Background())
	if status != 429 || err != nil {
		t.Fatalf("WaitReady = %d, %v", status, err)
	}
	waitDone(t, conn)
	// Still the status after the end.
	if status, _, err := conn.WaitReady(context.Background()); status != 429 || err != nil {
		t.Fatalf("WaitReady after the end = %d, %v", status, err)
	}
	if _, err := readOne(t, conn, 8); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %v", err)
	}
}

func TestDatagramConnDrainAfterEnd(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	stream.datagram([]byte("one"))
	stream.datagram([]byte("two"))
	stream.closeStream()
	waitDone(t, conn)
	for _, want := range []string{"one", "two"} {
		if data, err := readOne(t, conn, 8); err != nil || string(data) != want {
			t.Fatalf("read = %q, %v; want %q", data, err, want)
		}
	}
	if _, err := readOne(t, conn, 8); !errors.Is(err, io.EOF) {
		t.Fatalf("read after the queue = %v", err)
	}
	if err := conn.WriteDatagram([]byte("x")); err != ErrDatagramClosed {
		t.Fatalf("write after the end = %v", err)
	}
}

func TestDatagramConnFailedBeforeReady(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.fail(NetErrorMethodNotSupported)
	_, _, err := conn.WaitReady(context.Background())
	if !errors.Is(err, NetErrorMethodNotSupported) {
		t.Fatalf("WaitReady = %v", err)
	}
	waitDone(t, conn)
	if _, err := readOne(t, conn, 8); !errors.Is(err, NetErrorMethodNotSupported) {
		t.Fatalf("read = %v", err)
	}
}

func TestDatagramConnSetupContext(t *testing.T) {
	stream := newFakeDatagramStream(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn := newDatagramConn(ctx, stream.create, "https://example.org/", nil)
	cancel()
	waitDone(t, conn)
	if !errors.Is(conn.Err(), context.Canceled) {
		t.Fatalf("Err = %v", conn.Err())
	}
	if cancels, destroys := stream.counts(); cancels != 1 || destroys != 1 {
		t.Fatalf("cancels %d, destroys %d", cancels, destroys)
	}

	// Once the node has answered, the context of the setup no longer matters.
	stream = newFakeDatagramStream(t)
	ctx, cancel = context.WithCancel(context.Background())
	conn = newDatagramConn(ctx, stream.create, "https://example.org/", nil)
	stream.ready(200, nil)
	if _, _, err := conn.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	stream.sync()
	select {
	case <-conn.Done():
		t.Fatalf("ended by the setup context: %v", conn.Err())
	default:
	}
	if cancels, _ := stream.counts(); cancels != 0 {
		t.Fatalf("%d cancels", cancels)
	}

	// A context that has already ended starts nothing.
	stream = newFakeDatagramStream(t)
	conn = newDatagramConn(ctx, stream.create, "https://example.org/", nil)
	waitDone(t, conn)
	if !errors.Is(conn.Err(), context.Canceled) {
		t.Fatalf("Err = %v", conn.Err())
	}
	stream.access.Lock()
	started := stream.started
	stream.access.Unlock()
	if started {
		t.Fatal("started with a done context")
	}
}

func TestDatagramConnStartFailure(t *testing.T) {
	stream := newFakeDatagramStream(t)
	stream.startResult = false
	conn := newDatagramConn(context.Background(), stream.create, "https://example.org/", nil)
	waitDone(t, conn)
	if !errors.Is(conn.Err(), errDatagramNotStarted) {
		t.Fatalf("Err = %v", conn.Err())
	}
	if _, destroys := stream.counts(); destroys != 1 {
		t.Fatalf("destroyed %d times", destroys)
	}
	if err := conn.WriteDatagram([]byte("x")); err != ErrDatagramClosed {
		t.Fatalf("write = %v", err)
	}
}

func TestDatagramConnUnsupported(t *testing.T) {
	conn := newDatagramConn(context.Background(), func(DatagramStreamCallback) (datagramStreamHandle, error) {
		return nil, ErrDatagramUnsupported
	}, "https://example.org/", nil)
	waitDone(t, conn)
	if _, _, err := conn.WaitReady(context.Background()); !errors.Is(err, ErrDatagramUnsupported) {
		t.Fatalf("WaitReady = %v", err)
	}
	if err := conn.WriteDatagram([]byte("x")); err != ErrDatagramClosed {
		t.Fatalf("write = %v", err)
	}
	if got := conn.MaxPayload(); got != 0 {
		t.Fatalf("MaxPayload = %d", got)
	}
	if receive, capsules := conn.Dropped(); receive != 0 || capsules != 0 {
		t.Fatalf("Dropped = %d, %d", receive, capsules)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDatagramConnDroppedCapsules(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.droppedCapsules.Store(3)
	if _, capsules := conn.Dropped(); capsules != 3 {
		t.Fatalf("capsules %d", capsules)
	}
	stream.droppedCapsules.Store(5)
	stream.fail(NetErrorConnectionClosed)
	waitDone(t, conn)
	// The count survives the stream.
	if _, capsules := conn.Dropped(); capsules != 5 {
		t.Fatalf("capsules after the end %d", capsules)
	}
}

func TestDatagramConnConcurrentReaders(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	const total = 2000
	var received atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, 8)
			for {
				_, err := conn.ReadDatagram(context.Background(), buffer)
				if err != nil {
					return
				}
				received.Add(1)
			}
		}()
	}
	for i := 0; i < total; i++ {
		stream.datagram([]byte{byte(i)})
		if i%100 == 0 {
			stream.sync()
		}
	}
	stream.sync()
	for received.Load()+int64(conn.droppedReceive.Load()) < total {
		time.Sleep(time.Millisecond)
	}
	stream.closeStream()
	wg.Wait()
	if got := received.Load() + int64(conn.droppedReceive.Load()); got != total {
		t.Fatalf("received and dropped %d, want %d", got, total)
	}
}

func TestDatagramConnNoAllocations(t *testing.T) {
	conn, stream := newTestDatagramConn(t)
	stream.ready(200, nil)
	stream.sync()
	handler := datagramConnHandler{conn}
	payload := bytes.Repeat([]byte{1}, 1300)
	buffer := make([]byte, 1500)
	ctx := context.Background()
	// The first pass gives each slot its buffer.
	for i := 0; i < datagramConnQueueSize; i++ {
		handler.OnDatagram(DatagramStream{}, payload)
		if _, err := conn.ReadDatagram(ctx, buffer); err != nil {
			t.Fatal(err)
		}
	}
	allocs := testing.AllocsPerRun(1000, func() {
		handler.OnDatagram(DatagramStream{}, payload)
		if _, err := conn.ReadDatagram(ctx, buffer); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("%v allocations a datagram", allocs)
	}
}

func TestDatagramSendError(t *testing.T) {
	for code, want := range map[int]error{
		datagramStreamOK:             nil,
		datagramStreamQueueFull:      ErrDatagramQueueFull,
		datagramStreamTooLarge:       ErrDatagramTooLarge,
		datagramStreamClosed:         ErrDatagramClosed,
		datagramStreamCapsuleTimeout: ErrDatagramCapsuleTimeout,
	} {
		if got := datagramSendError(code); got != want {
			t.Errorf("datagramSendError(%d) = %v, want %v", code, got, want)
		}
	}
	if datagramSendError(-99) == nil {
		t.Error("an unknown code is no error")
	}
}

func TestDatagramStreamWithoutLibrarySupport(t *testing.T) {
	var stream DatagramStream
	if stream.Start("https://example.org/", nil) {
		t.Fatal("a null stream started")
	}
	if err := stream.Send([]byte("x"), true); !errors.Is(err, ErrDatagramUnsupported) {
		t.Fatalf("Send = %v", err)
	}
	if stream.MaxPayload() != 0 || stream.DroppedCapsules() != 0 || stream.Destroy() {
		t.Fatal("a null stream answered")
	}
	stream.Cancel()
}
