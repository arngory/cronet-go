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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// datagramCloseData asks the echo server to close the stream cleanly.
	datagramCloseData = "close"
)

// udpPayload is a payload of the format: to 127.0.0.1:53 with data.
func udpPayload(data []byte) []byte {
	payload := make([]byte, 0, 7+len(data))
	payload = append(payload, 4, 127, 0, 0, 1)
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
	w.Header().Set("capsule-protocol", "?1")
	w.Header().Set("niko-udp", "1")
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

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
		if string(data) == datagramCloseData {
			// A clean close, as the node's when the socket is idle: FIN, and the stream ends once the client resets
			// its side.
			stream.Close()
			cancel()
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

	conn := engine.CreateDatagramConn(context.Background(), server.url(), datagramRequestHeaders(true))
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
	require.Equal(t, "?1", requestHeaders.Get("capsule-protocol"))
	require.Empty(t, requestHeaders.Get("-connect-protocol"))
	require.Empty(t, requestHeaders.Get("-force-quic"))
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

	// Just above the QUIC datagram, and the longest datagram of UDP: capsules both ways.
	for _, length := range []int{maxPayload + 1, 65507} {
		data := bytes.Repeat([]byte{byte(length)}, length-7)
		payload := udpPayload(data)
		require.Len(t, payload, length)
		capsules := server.capsules.Load()
		require.NoError(t, conn.WriteDatagram(payload))
		require.Equal(t, payload, readDatagram(t, conn, buffer))
		require.Equal(t, capsules+1, server.capsules.Load())
	}

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
