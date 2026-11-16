package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// The datagrams of naive-udp-v1 (§3.2): Context ID 2, then [address type][address][port][UDP data].
const (
	datagramContextID   = 2
	datagramCapsuleType = http3.CapsuleType(0)
	datagramPath        = "/.well-known/masque/udp/%2A/%2A/"
	// The commands of the echo server, in the UDP data of a datagram: close the stream cleanly (FIN), close it as
	// quic-go and the node do when they end a stream (STOP_SENDING and FIN), reset it, send N capsules at once, send
	// a datagram with another Context ID and then "ctx2".
	datagramCloseData     = "close"
	datagramCloseStopData = "close-stop"
	datagramResetData     = "reset"
	datagramBurstPrefix   = "burst-capsules "
	datagramWrongContext  = "wrong-context"
	// The command of the server that reads nothing (datagramStallHeader), in a QUIC datagram: stop reading the
	// stream with STOP_SENDING alone, then send datagramStoppedData in a datagram.
	datagramStopReadingData = "stop-reading"
	datagramStoppedData     = "stopped"
)

// The request headers of the echo server's modes: answer nothing; send datagrams and capsules without end; answer
// with a capsule and the end of the stream at once ("fin", or "stop" for STOP_SENDING and FIN); read nothing.
const (
	datagramHoldHeader        = "x-test-hold"
	datagramFloodHeader       = "x-test-flood"
	datagramAnswerCloseHeader = "x-test-answer-close"
	datagramStallHeader       = "x-test-stall"
	// datagramAnswerCloseData is the data of the capsule that comes with the answer and the end.
	datagramAnswerCloseData = "with the answer"
)

// udpPayload is a payload of the format: to 127.0.0.1:53 with data.
func udpPayload(data []byte) []byte {
	payload := make([]byte, 0, 7+len(data))
	payload = append(payload, 4, 127, 0, 0, 1)
	payload = binary.BigEndian.AppendUint16(payload, 53)
	return append(payload, data...)
}

// udpPayloadToName is a payload of the format to a name of 255 bytes, port 53: with 65507 bytes of data, the longest.
func udpPayloadToName(data []byte) []byte {
	payload := make([]byte, 0, 1+1+255+2+len(data))
	payload = append(payload, 3, 255)
	payload = append(payload, bytes.Repeat([]byte{'n'}, 255)...)
	payload = binary.BigEndian.AppendUint16(payload, 53)
	return append(payload, data...)
}

// udpData checks the format of a payload and returns its UDP data.
func udpData(payload []byte) ([]byte, bool) {
	if len(payload) < 1 {
		return nil, false
	}
	var addressLength int
	switch payload[0] {
	case 4:
		addressLength = 4
	case 6:
		addressLength = 16
	case 3:
		if len(payload) < 2 || payload[1] == 0 {
			return nil, false
		}
		addressLength = 1 + int(payload[1])
	default:
		return nil, false
	}
	if len(payload) < 1+addressLength+2 {
		return nil, false
	}
	if binary.BigEndian.Uint16(payload[1+addressLength:]) == 0 {
		return nil, false
	}
	return payload[1+addressLength+2:], true
}

// udpEchoServer is a connect-udp server of naive-udp-v1 on quic-go: it answers the datagrams it receives with the same
// payload, the way it came: a capsule with a capsule, which keeps the answers to the capsules sent before the
// response after its headers, and a QUIC datagram with a QUIC datagram, or a capsule if it does not fit.
type udpEchoServer struct {
	t      *testing.T
	port   uint16
	server *http3.Server

	requests  atomic.Int64
	datagrams atomic.Int64
	capsules  atomic.Int64

	headerAccess sync.Mutex
	headers      http.Header
	proto        string
	path         string

	handlers sync.WaitGroup
}

func startUDPEchoServer(t *testing.T, certPem, keyPem string, enableDatagrams bool) *udpEchoServer {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certPem, keyPem)
	require.NoError(t, err)
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &udpEchoServer{t: t, port: uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)}
	s.server = &http3.Server{
		Handler:         s,
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{certificate}}),
		QUICConfig:      &quic.Config{EnableDatagrams: enableDatagrams, MaxIdleTimeout: 30 * time.Second},
		EnableDatagrams: enableDatagrams,
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = s.server.Serve(udpConn)
	}()
	t.Cleanup(func() {
		s.server.Close()
		udpConn.Close()
		<-served
		s.handlers.Wait()
	})
	return s
}

func (s *udpEchoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	s.handlers.Add(1)
	defer s.handlers.Done()
	s.headerAccess.Lock()
	s.headers = r.Header.Clone()
	s.proto = r.Proto
	s.path = r.URL.EscapedPath()
	s.headerAccess.Unlock()
	if r.Method != http.MethodConnect || r.Proto != "connect-udp" || r.Header.Get("niko-udp") != "1" ||
		!strings.HasPrefix(r.URL.Path, "/.well-known/masque/udp/") {
		// The site, as an old or switched-off node answers.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Header.Get(datagramHoldHeader) == "1" {
		<-r.Context().Done()
		return
	}
	w.Header().Set("capsule-protocol", "?1")
	w.Header().Set("niko-udp", "1")
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	switch r.Header.Get(datagramAnswerCloseHeader) {
	case "fin", "stop":
		// The answer, a capsule and the end, in one go.
		if r.Header.Get(datagramAnswerCloseHeader) == "stop" {
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
		var capsule bytes.Buffer
		_ = http3.WriteCapsule(&capsule, datagramCapsuleType,
			append([]byte{datagramContextID}, udpPayload([]byte(datagramAnswerCloseData))...))
		_, _ = stream.Write(capsule.Bytes())
		stream.Close()
		<-r.Context().Done()
		return
	}
	if r.Header.Get(datagramStallHeader) == "1" {
		// Reads nothing of the stream: the stream of the client stalls once the flow control window is full. Of the
		// datagrams, it takes datagramStopReadingData.
		for {
			datagram, err := stream.ReceiveDatagram(r.Context())
			if err != nil {
				return
			}
			if len(datagram) == 0 || datagram[0] != datagramContextID {
				continue
			}
			if data, ok := udpData(datagram[1:]); ok && string(data) == datagramStopReadingData {
				stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
				_ = stream.SendDatagram(append([]byte{datagramContextID}, udpPayload([]byte(datagramStoppedData))...))
				<-r.Context().Done()
				return
			}
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if r.Header.Get(datagramFloodHeader) == "1" {
		// Datagrams and capsules without end, until the client goes.
		datagram := append([]byte{datagramContextID}, udpPayload([]byte("flood"))...)
		var capsule bytes.Buffer
		_ = http3.WriteCapsule(&capsule, datagramCapsuleType, datagram)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			_, _ = io.Copy(io.Discard, stream)
			cancel()
		}()
		for ctx.Err() == nil {
			_ = stream.SendDatagram(datagram)
			if _, err := stream.Write(capsule.Bytes()); err != nil {
				break
			}
		}
		<-readDone
		return
	}

	var writeAccess sync.Mutex
	echo := func(datagram []byte, inCapsule bool) {
		reader := bytes.NewReader(datagram)
		contextID, err := quicvarint.Read(reader)
		if err != nil || contextID != datagramContextID {
			return
		}
		payload := datagram[len(datagram)-reader.Len():]
		data, ok := udpData(payload)
		if !ok {
			return
		}
		writeAccess.Lock()
		defer writeAccess.Unlock()
		switch {
		case string(data) == datagramCloseData:
			// A clean close: FIN, and the stream ends once the client resets its side.
			stream.Close()
			cancel()
			return
		case string(data) == datagramCloseStopData:
			// A clean close as quic-go and the node make it: STOP_SENDING and FIN.
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			stream.Close()
			cancel()
			return
		case string(data) == datagramResetData:
			stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			cancel()
			return
		case strings.HasPrefix(string(data), datagramBurstPrefix):
			count, _ := strconv.Atoi(strings.TrimPrefix(string(data), datagramBurstPrefix))
			var capsules bytes.Buffer
			for i := 0; i < count; i++ {
				_ = http3.WriteCapsule(&capsules, datagramCapsuleType,
					append([]byte{datagramContextID}, udpPayload([]byte(strconv.Itoa(i)))...))
			}
			_, _ = stream.Write(capsules.Bytes())
			return
		case string(data) == datagramWrongContext:
			// Context ID 4, then 2: only the second is the client's.
			_ = stream.SendDatagram(append(quicvarint.Append(nil, 4), udpPayload([]byte("ctx4"))...))
			_ = stream.SendDatagram(append([]byte{datagramContextID}, udpPayload([]byte("ctx2"))...))
			return
		}
		if !inCapsule && stream.SendDatagram(datagram) == nil {
			return
		}
		var capsule bytes.Buffer
		if http3.WriteCapsule(&capsule, datagramCapsuleType, datagram) != nil {
			return
		}
		_, _ = stream.Write(capsule.Bytes())
	}

	capsulesDone := make(chan struct{})
	go func() {
		defer close(capsulesDone)
		defer cancel()
		parser := http3.NewCapsuleParser(stream)
		for {
			capsuleType, reader, err := parser.Next()
			if err != nil {
				return
			}
			if capsuleType != datagramCapsuleType {
				if reader.Discard() != nil {
					return
				}
				continue
			}
			datagram, err := io.ReadAll(reader)
			if err != nil {
				return
			}
			s.capsules.Add(1)
			echo(datagram, true)
		}
	}()
	for {
		datagram, err := stream.ReceiveDatagram(ctx)
		if err != nil {
			break
		}
		s.datagrams.Add(1)
		echo(datagram, false)
	}
	// Until the client resets the stream, or the server closes.
	<-capsulesDone
}

func (s *udpEchoServer) url() string {
	return fmt.Sprintf("https://example.org:%d%s", s.port, datagramPath)
}

func (s *udpEchoServer) requestHeaders() (http.Header, string, string) {
	s.headerAccess.Lock()
	defer s.headerAccess.Unlock()
	return s.headers, s.proto, s.path
}

// datagramTestClient starts a QUIC client of the server and returns its stream engine.
func datagramTestClient(t *testing.T, caPem string, port uint16) cronet.StreamEngine {
	t.Helper()
	caPemContent, err := os.ReadFile(caPem)
	require.NoError(t, err)
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", port),
		ServerName:              "example.org",
		Username:                "test",
		Password:                "test",
		TrustedRootCertificates: string(caPemContent),
		DNSResolver:             localhostDNSResolverWithHTTPSResponse(t, port, []string{"h3"}),
		QUIC:                    true,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() { client.Close() })
	_ = startNetLogForTest(t, client, t.Name()+"_netlog.json", false)
	return client.Engine().StreamEngine()
}

func datagramRequestHeaders(nikoUDP bool) map[string]string {
	headers := map[string]string{
		"padding":             strings.Repeat("~", 37),
		"proxy-authorization": "Basic dGVzdDp0ZXN0",
		"-force-quic":         "true",
	}
	if nikoUDP {
		headers["niko-udp"] = "1"
	}
	return headers
}

func readDatagram(t *testing.T, conn *cronet.DatagramConn, buffer []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, err := conn.ReadDatagram(ctx, buffer)
	require.NoError(t, err)
	return buffer[:n]
}

// TestDatagramStreamQUIC carries connect-udp datagrams through libcronet to a quic-go server: capsules before the
// answer, QUIC datagrams after it, capsules for what does not fit.
func TestDatagramStreamQUIC(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	// The headers of the caller go through; "-force-quic", which the library sets too, and a capsule-protocol of the
	// caller's spelling are sent once (and the first not at all).
	headers := datagramRequestHeaders(true)
	headers["X-Extra-Header"] = "extra"
	headers["Capsule-Protocol"] = "?1"
	conn := engine.CreateDatagramConn(context.Background(), server.url(), headers)
	defer conn.Close()

	// Before the answer: a capsule, at once.
	early := udpPayload([]byte("early"))
	require.NoError(t, conn.WriteDatagram(early))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, headers, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, "1", headers["niko-udp"])

	buffer := make([]byte, 70000)
	require.Equal(t, early, readDatagram(t, conn, buffer))
	require.GreaterOrEqual(t, server.capsules.Load(), int64(1), "the early datagram came in a capsule")

	requestHeaders, proto, path := server.requestHeaders()
	require.Equal(t, "connect-udp", proto)
	require.Equal(t, []string{"?1"}, requestHeaders.Values("capsule-protocol"))
	require.Equal(t, "extra", requestHeaders.Get("x-extra-header"))
	require.Empty(t, requestHeaders.Values("-connect-protocol"))
	require.Empty(t, requestHeaders.Values("-force-quic"))
	t.Logf("request path %q, headers %v", path, requestHeaders)

	maxPayload := conn.MaxPayload()
	t.Logf("max payload %d", maxPayload)
	require.Greater(t, maxPayload, 1000)
	require.Less(t, maxPayload, 1500)

	// QUIC datagrams, one at a time.
	capsulesBefore := server.capsules.Load()
	for i := 0; i < 20; i++ {
		payload := udpPayload([]byte(fmt.Sprintf("datagram %d", i)))
		require.NoError(t, conn.WriteDatagram(payload))
		require.Equal(t, payload, readDatagram(t, conn, buffer))
	}
	require.GreaterOrEqual(t, server.datagrams.Load(), int64(20))
	require.Equal(t, capsulesBefore, server.capsules.Load(), "datagrams that fit went in capsules")

	// Just above the QUIC datagram, and the longest payload (a name of 255 bytes and 65507 bytes of data): capsules
	// both ways.
	for _, payload := range [][]byte{
		udpPayload(bytes.Repeat([]byte{1}, maxPayload+1-7)),
		udpPayloadToName(bytes.Repeat([]byte{2}, 65507)),
	} {
		capsules := server.capsules.Load()
		require.NoError(t, conn.WriteDatagram(payload))
		require.Equal(t, payload, readDatagram(t, conn, buffer))
		require.Equal(t, capsules+1, server.capsules.Load())
	}
	require.Len(t, udpPayloadToName(make([]byte, 65507)), 65766)

	// A datagram cut to the buffer.
	payload := udpPayload([]byte("0123456789"))
	require.NoError(t, conn.WriteDatagram(payload))
	readCtx, readCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readCancel()
	n, err := conn.ReadDatagram(readCtx, buffer[:9])
	require.ErrorIs(t, err, cronet.ErrDatagramTruncated)
	require.Equal(t, payload[:9], buffer[:n])

	receive, capsules := conn.Dropped()
	require.Zero(t, receive)
	require.Zero(t, capsules)

	require.NoError(t, conn.Close())
	select {
	case <-conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the stream did not end after Close")
	}
	require.ErrorIs(t, conn.Err(), net.ErrClosed)
}

// datagramStreamRecorder is a DatagramStreamCallback that queues what it is told.
type datagramStreamRecorder struct {
	ready       chan int
	datagrams   chan []byte
	maxPayloads chan int
	end         chan string
}

func newDatagramStreamRecorder() *datagramStreamRecorder {
	return &datagramStreamRecorder{
		ready:       make(chan int, 1),
		datagrams:   make(chan []byte, 64),
		maxPayloads: make(chan int, 64),
		end:         make(chan string, 1),
	}
}

func (r *datagramStreamRecorder) OnReady(stream cronet.DatagramStream, status int, headers map[string]string) {
	r.ready <- status
}

func (r *datagramStreamRecorder) OnDatagram(stream cronet.DatagramStream, data []byte) {
	select {
	case r.datagrams <- bytes.Clone(data):
	default:
	}
}

func (r *datagramStreamRecorder) OnMaxPayloadChanged(stream cronet.DatagramStream, maxPayload int) {
	select {
	case r.maxPayloads <- maxPayload:
	default:
	}
}

func (r *datagramStreamRecorder) OnClosed(stream cronet.DatagramStream) { r.end <- "closed" }

func (r *datagramStreamRecorder) OnFailed(stream cronet.DatagramStream, netError int) {
	r.end <- cronet.NetError(netError).Name()
}

func (r *datagramStreamRecorder) OnCanceled(stream cronet.DatagramStream) { r.end <- "canceled" }

func receiveWithin[T any](t *testing.T, channel <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(15 * time.Second):
		t.Fatalf("no %s", what)
		panic("unreachable")
	}
}

// TestDatagramStreamTooLarge checks the flag of capsules on the stream itself: without it, nothing goes before the
// answer, and after it nothing longer than MaxPayload.
func TestDatagramStreamTooLarge(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	recorder := newDatagramStreamRecorder()
	stream := engine.CreateDatagramStream(recorder)
	require.True(t, stream.Start(server.url(), datagramRequestHeaders(true)))
	defer stream.Destroy()

	require.Zero(t, stream.MaxPayload())
	require.ErrorIs(t, stream.Send(udpPayload([]byte("small")), false), cronet.ErrDatagramTooLarge)
	require.ErrorIs(t, stream.Send(make([]byte, 65767), true), cronet.ErrDatagramTooLarge)

	require.Equal(t, 200, receiveWithin(t, recorder.ready, "response"))
	maxPayload := stream.MaxPayload()
	require.Greater(t, maxPayload, 1000)
	require.Equal(t, maxPayload, receiveWithin(t, recorder.maxPayloads, "max payload"))

	require.ErrorIs(t, stream.Send(udpPayload(make([]byte, maxPayload-7+1)), false), cronet.ErrDatagramTooLarge)
	exact := udpPayload(bytes.Repeat([]byte{'x'}, maxPayload-7))
	require.NoError(t, stream.Send(exact, false))
	require.Equal(t, exact, receiveWithin(t, recorder.datagrams, "echo of a full datagram"))
	require.Zero(t, server.capsules.Load(), "a full datagram went in a capsule")
	require.Zero(t, stream.DroppedCapsules())

	stream.Cancel()
	require.Equal(t, "canceled", receiveWithin(t, recorder.end, "end"))
	require.ErrorIs(t, stream.Send(exact, false), cronet.ErrDatagramClosed)
}

// TestDatagramStreamServerClose: the node closes the stream (idle): a clean end.
func TestDatagramStreamServerClose(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.Equal(t, 200, status)

	require.NoError(t, conn.WriteDatagram(udpPayload([]byte(datagramCloseData))))
	_, err = conn.ReadDatagram(ctx, make([]byte, 64))
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, conn.Err(), io.EOF)
	require.ErrorIs(t, conn.WriteDatagram(udpPayload([]byte("late"))), cronet.ErrDatagramClosed)
}

// TestDatagramStreamSiteResponse: a node with the feature off answers as the site: OnReady with that status, then a
// clean end.
func TestDatagramStreamSiteResponse(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(false))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.Equal(t, 404, status)
	select {
	case <-conn.Done():
	case <-ctx.Done():
		t.Fatal("no end after 404")
	}
	require.ErrorIs(t, conn.Err(), io.EOF)
	require.Zero(t, conn.MaxPayload())
}

// TestDatagramStreamWithoutH3Datagram: a node that announces no HTTP/3 datagrams gets no request; the stream fails
// with its own code.
func TestDatagramStreamWithoutH3Datagram(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, false)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.WaitReady(ctx)
	require.ErrorIs(t, err, cronet.NetErrorMethodNotSupported)
	var netError cronet.NetError
	require.True(t, errors.As(err, &netError))
	require.Zero(t, server.requests.Load(), "the request was sent")
}

// TestDatagramStreamCapsuleTimeout stalls the stream on the server, which reads nothing: once the flow control
// window is full, a capsule waits in the send buffer, and after 100 ms a send that needs a capsule is refused,
// while one that fits in a QUIC datagram is not; the capsules queued behind it are dropped and counted.
func TestDatagramStreamCapsuleTimeout(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	recorder := newDatagramStreamRecorder()
	stream := engine.CreateDatagramStream(recorder)
	headers := datagramRequestHeaders(true)
	headers["x-test-stall"] = "1"
	require.True(t, stream.Start(server.url(), headers))
	defer stream.Destroy()
	require.Equal(t, 200, receiveWithin(t, recorder.ready, "response"))

	capsule := udpPayload(make([]byte, 60000))
	deadline := time.Now().Add(20 * time.Second)
	var accepted, queueFull int
	for {
		err := stream.Send(capsule, true)
		if errors.Is(err, cronet.ErrDatagramCapsuleTimeout) {
			break
		}
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, cronet.ErrDatagramQueueFull)
			queueFull++
		}
		require.True(t, time.Now().Before(deadline), "no capsule timeout after %d capsules", accepted)
		time.Sleep(2 * time.Millisecond)
	}
	t.Logf("capsule timeout after %d capsules accepted, %d refused as queue full", accepted, queueFull)

	// A datagram that fits is not held up by the capsules.
	small := udpPayload([]byte("small"))
	require.NoError(t, stream.Send(small, false))
	require.NoError(t, stream.Send(small, true))
	require.ErrorIs(t, stream.Send(capsule, true), cronet.ErrDatagramCapsuleTimeout)

	require.Eventually(t, func() bool { return stream.DroppedCapsules() > 0 }, 5*time.Second, 10*time.Millisecond,
		"the stale capsules were not dropped")
	t.Logf("dropped capsules %d", stream.DroppedCapsules())

	stream.Cancel()
	require.Equal(t, "canceled", receiveWithin(t, recorder.end, "end"))
}

// TestDatagramStreamStopSendingWithCapsuleInStream: the server stops reading the stream with STOP_SENDING alone
// while a capsule waits in the send buffer. The capsule is dropped, and a send that needs a capsule is refused as
// closed, not as a capsule timeout for ever; datagrams still come in, and the stream does not end.
func TestDatagramStreamStopSendingWithCapsuleInStream(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	recorder := newDatagramStreamRecorder()
	stream := engine.CreateDatagramStream(recorder)
	headers := datagramRequestHeaders(true)
	headers[datagramStallHeader] = "1"
	require.True(t, stream.Start(server.url(), headers))
	defer stream.Destroy()
	require.Equal(t, 200, receiveWithin(t, recorder.ready, "response"))

	// Capsules until one waits in the send buffer for longer than 100 ms.
	capsule := udpPayload(make([]byte, 60000))
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := stream.Send(capsule, true)
		if errors.Is(err, cronet.ErrDatagramCapsuleTimeout) {
			break
		}
		if err != nil {
			require.ErrorIs(t, err, cronet.ErrDatagramQueueFull)
		}
		require.True(t, time.Now().Before(deadline), "no capsule waits in the send buffer")
		time.Sleep(2 * time.Millisecond)
	}
	// What the queue still drops goes before the count to compare with.
	time.Sleep(200 * time.Millisecond)
	dropped := stream.DroppedCapsules()

	require.NoError(t, stream.Send(udpPayload([]byte(datagramStopReadingData)), false))
	require.Equal(t, udpPayload([]byte(datagramStoppedData)),
		receiveWithin(t, recorder.datagrams, "the datagram after STOP_SENDING"))
	require.Eventually(t, func() bool {
		return errors.Is(stream.Send(capsule, true), cronet.ErrDatagramClosed)
	}, 5*time.Second, 10*time.Millisecond, "a send that needs a capsule is not refused as closed")
	require.ErrorIs(t, stream.Send(udpPayload([]byte("small")), false), cronet.ErrDatagramClosed)
	require.Greater(t, stream.DroppedCapsules(), dropped, "the capsule in the send buffer is not counted")

	select {
	case end := <-recorder.end:
		t.Fatalf("the stream ended (%s) while the server still sends", end)
	case <-time.After(200 * time.Millisecond):
	}
	stream.Cancel()
	require.Equal(t, "canceled", receiveWithin(t, recorder.end, "end"))
}

// TestDatagramStreamCancelDestroyFlood cancels and destroys streams back to back while the server floods them with
// datagrams and capsules. A call into a destroyed stream shows only if it crashes the process, as it did with the
// library before the fix; the test cannot prove there is none.
func TestDatagramStreamCancelDestroyFlood(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)
	headers := datagramRequestHeaders(true)
	headers[datagramFloodHeader] = "1"

	for round := 0; round < 60; round++ {
		recorder := newDatagramStreamRecorder()
		stream := engine.CreateDatagramStream(recorder)
		require.True(t, stream.Start(server.url(), headers))
		if round%3 != 0 {
			require.Equal(t, 200, receiveWithin(t, recorder.ready, "response"))
			if round%3 == 2 {
				receiveWithin(t, recorder.datagrams, "a datagram of the flood")
			}
		}
		_ = stream.Send(udpPayload([]byte("x")), true)
		stream.Cancel()
		require.True(t, stream.Destroy())
	}
	// What the network thread still had for the destroyed streams.
	time.Sleep(500 * time.Millisecond)

	// The engine still works.
	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.Equal(t, 200, status)
}

// TestDatagramStreamCloseWithStopSending: the node ends the stream as quic-go does, with STOP_SENDING and FIN: a
// clean end, not a failure.
func TestDatagramStreamCloseWithStopSending(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.NoError(t, conn.WriteDatagram(udpPayload([]byte(datagramCloseStopData))))
	_, err = conn.ReadDatagram(ctx, make([]byte, 64))
	require.ErrorIs(t, err, io.EOF)
	require.ErrorIs(t, conn.Err(), io.EOF)
}

// TestDatagramStreamServerReset: the node resets the stream after 200: a failure.
func TestDatagramStreamServerReset(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.NoError(t, conn.WriteDatagram(udpPayload([]byte(datagramResetData))))
	_, err = conn.ReadDatagram(ctx, make([]byte, 64))
	var netError cronet.NetError
	require.True(t, errors.As(err, &netError), "read after a reset = %v", err)
	t.Logf("reset: %v (%s)", netError, netError.Name())
}

// TestDatagramStreamAnswerWithEnd: the answer, a datagram and the end of the stream come together; the datagram is
// read before the end.
func TestDatagramStreamAnswerWithEnd(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	for _, mode := range []string{"fin", "stop"} {
		t.Run(mode, func(t *testing.T) {
			headers := datagramRequestHeaders(true)
			headers[datagramAnswerCloseHeader] = mode
			conn := engine.CreateDatagramConn(context.Background(), server.url(), headers)
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			status, _, err := conn.WaitReady(ctx)
			require.NoError(t, err)
			require.Equal(t, 200, status)
			buffer := make([]byte, 128)
			n, err := conn.ReadDatagram(ctx, buffer)
			require.NoError(t, err)
			require.Equal(t, udpPayload([]byte(datagramAnswerCloseData)), buffer[:n])
			_, err = conn.ReadDatagram(ctx, buffer)
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

// TestDatagramConnBeforeAnswer closes conns, or cancels their setup context, before the node answers (it never
// does): they end with net.ErrClosed or the context's error, and nothing keeps them alive.
func TestDatagramConnBeforeAnswer(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)
	headers := datagramRequestHeaders(true)
	headers[datagramHoldHeader] = "1"

	var conns []weak.Pointer[cronet.DatagramConn]
	for i := 0; i < 90; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn := engine.CreateDatagramConn(ctx, server.url(), headers)
		_ = conn.WriteDatagram(udpPayload([]byte("early")))
		switch i % 3 {
		case 0:
			require.NoError(t, conn.Close())
		case 1:
			cancel()
		case 2:
			conn.Close()
			cancel()
		}
		select {
		case <-conn.Done():
		case <-time.After(10 * time.Second):
			t.Fatalf("conn %d did not end", i)
		}
		err := conn.Err()
		require.True(t, errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled), "Err = %v", err)
		cancel()
		conns = append(conns, weak.Make(conn))
	}
	require.Eventually(t, func() bool {
		runtime.GC()
		for _, conn := range conns {
			if conn.Value() != nil {
				return false
			}
		}
		return true
	}, 5*time.Second, 20*time.Millisecond, "ended conns are still referenced")
}

// TestDatagramStreamOtherContextID: a datagram with another Context ID than 2 is dropped.
func TestDatagramStreamOtherContextID(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)
	require.NoError(t, conn.WriteDatagram(udpPayload([]byte(datagramWrongContext))))
	require.Equal(t, udpPayload([]byte("ctx2")), readDatagram(t, conn, make([]byte, 64)))
}

// TestDatagramConnReceiveOverflow: a burst the reader does not keep up with fills the receive queue; the rest is
// dropped and counted. Capsules lose nothing on the way, so every one is read or counted.
func TestDatagramConnReceiveOverflow(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, err := conn.WaitReady(ctx)
	require.NoError(t, err)

	const burst = 1000
	require.NoError(t, conn.WriteDatagram(udpPayload([]byte(datagramBurstPrefix+strconv.Itoa(burst)))))
	require.Eventually(t, func() bool {
		receive, _ := conn.Dropped()
		return receive >= burst-256
	}, 10*time.Second, 10*time.Millisecond)
	buffer := make([]byte, 64)
	read := 0
	for {
		readCtx, readCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		n, err := conn.ReadDatagram(readCtx, buffer)
		readCancel()
		if err != nil {
			require.ErrorIs(t, err, context.DeadlineExceeded)
			break
		}
		require.Equal(t, udpPayload([]byte(strconv.Itoa(read))), buffer[:n], "the oldest are kept")
		read++
	}
	receive, _ := conn.Dropped()
	require.Equal(t, 256, read)
	require.EqualValues(t, burst-256, receive)
}

// TestDatagramConnConcurrentWritersClose writes from many goroutines, datagrams and capsules, and closes meanwhile.
func TestDatagramConnConcurrentWritersClose(t *testing.T) {
	require.NoError(t, cronet.CheckDatagramSupport())
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	for round := 0; round < 20; round++ {
		conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload := udpPayload(bytes.Repeat([]byte{1}, 100+g*400))
				for i := 0; i < 300; i++ {
					switch err := conn.WriteDatagram(payload); {
					case err == nil, errors.Is(err, cronet.ErrDatagramQueueFull),
						errors.Is(err, cronet.ErrDatagramCapsuleTimeout):
					case errors.Is(err, net.ErrClosed), errors.Is(err, cronet.ErrDatagramClosed):
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
		time.Sleep(time.Duration(round%5) * 5 * time.Millisecond)
		conn.Close()
		wg.Wait()
		select {
		case <-conn.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("the conn did not end")
		}
	}
}

// TestDatagramUnsupportedLibrary runs against a build without datagram streams: the workflow builds the test binary
// for it from include/ without datagram_stream_c.h and without the define that goes with it, and sets
// CRONET_TEST_NO_DATAGRAM_SUPPORT=1. Everything else works; datagram streams report ErrDatagramUnsupported.
func TestDatagramUnsupportedLibrary(t *testing.T) {
	if os.Getenv("CRONET_TEST_NO_DATAGRAM_SUPPORT") != "1" {
		t.Skip("for a build without datagram streams")
	}
	require.ErrorIs(t, cronet.CheckDatagramSupport(), cronet.ErrDatagramUnsupported)
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	server := startUDPEchoServer(t, certPem, keyPem, true)
	engine := datagramTestClient(t, caPem, server.port)

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
	select {
	case <-conn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the conn did not end")
	}
	require.ErrorIs(t, conn.Err(), cronet.ErrDatagramUnsupported)
	_, _, err := conn.WaitReady(context.Background())
	require.ErrorIs(t, err, cronet.ErrDatagramUnsupported)
	require.ErrorIs(t, conn.WriteDatagram(udpPayload([]byte("x"))), cronet.ErrDatagramClosed)
	require.NoError(t, conn.Close())

	stream := engine.CreateDatagramStream(newDatagramStreamRecorder())
	require.False(t, stream.Start(server.url(), datagramRequestHeaders(true)))
	require.ErrorIs(t, stream.Send(udpPayload([]byte("x")), true), cronet.ErrDatagramUnsupported)
	require.Zero(t, stream.MaxPayload())
	require.False(t, stream.Destroy())
	require.Zero(t, server.requests.Load())
}
