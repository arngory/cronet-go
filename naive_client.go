package cronet

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*NaiveClient)(nil)

type QUICCongestionControl string

const (
	QUICCongestionControlDefault QUICCongestionControl = ""
	QUICCongestionControlBBR     QUICCongestionControl = "TBBR"
	QUICCongestionControlBBRv2   QUICCongestionControl = "B2ON"
	// QUICHE selects Cubic on the QBIC tag only when the quic_default_to_bbr
	// reloadable flag is set, and Chromium builds it with that flag false; CQBC
	// is the client-only tag QuicSentPacketManager honors unconditionally.
	QUICCongestionControlCubic QUICCongestionControl = "CQBC"
	QUICCongestionControlReno  QUICCongestionControl = "RENO"
)

type clientState uint32

const (
	clientStateCreated clientState = iota
	clientStateStarting
	clientStateRunning
	clientStateClosing
	clientStateClosed
)

type NaiveClient struct {
	state                   atomic.Uint32
	ctx                     context.Context
	dialer                  N.Dialer
	logger                  logger.ContextLogger
	serverAddress           M.Socksaddr
	serverName              string
	serverURL               string
	authorization           string
	concurrency             int
	extraHeaders            map[string]string
	receiveWindow           uint64
	trustedRootCertificates string
	publicKeyPins           [][]byte
	exactCertificates       [][]byte
	dnsResolver             DNSResolverFunc
	echEnabled              bool
	echConfigList           []byte
	echQueryServerName      string
	echMutex                sync.RWMutex
	testForceUDPLoopback    bool
	quicEnabled             bool
	quicCongestionControl   QUICCongestionControl
	quicAllowLocalRoots     bool
	// the experimental options, as JSON, of the engine started last: what the client's options came to
	experimentalOptions      atomic.Pointer[string]
	quicSessionReceiveWindow uint64
	counter                  atomic.Uint64
	started                  chan struct{}
	singleEngine             bool
	engines                  []Engine
	streamEngines            []StreamEngine
	activeConnections        sync.WaitGroup
	proxyWaitGroup           sync.WaitGroup
	proxyCancel              context.CancelFunc
}

type NaiveClientOptions struct {
	Context                  context.Context
	ServerAddress            M.Socksaddr
	ServerName               string
	Username                 string
	Password                 string
	InsecureConcurrency      int
	ReceiveWindow            uint64
	ExtraHeaders             map[string]string
	TrustedRootCertificates  string
	DNSResolver              DNSResolverFunc
	Logger                   logger.ContextLogger
	Dialer                   N.Dialer
	ECHEnabled               bool
	ECHConfigList            []byte
	ECHQueryServerName       string
	TestForceUDPLoopback     bool
	TestForceSingleEngine    bool
	QUIC                     bool
	QUICCongestionControl    QUICCongestionControl
	QUICSessionReceiveWindow uint64
	// QUICAllowLocallyTrustedRoots lets QUIC take a server whose chain verifies against a locally trusted root:
	// one of the file SSL_CERT_FILE names (Linux, Android). Without it QUIC wants a root Chromium knows, as Chrome
	// does, while HTTP/2 takes such a root either way. The chain, the name and the key pins are checked as before.
	// With TrustedRootCertificates it changes nothing: those roots pass over QUIC already.
	QUICAllowLocallyTrustedRoots bool
	// CertificatePublicKeySHA256 pins the server's certificate: SHA-256 hashes of the DER SubjectPublicKeyInfo of
	// keys, one of which must be in the chain the server presents (the leaf's, to pin the server and not its CA).
	// It is checked besides the chain, not in place of it, and for certificates of TrustedRootCertificates too.
	// ServerName must be a host name: Chromium keeps no pins for an address.
	CertificatePublicKeySHA256 [][]byte
	// ExactServerCertificates, if not empty, are the only certificates the client trusts, each the DER encoding of an
	// X.509 certificate: the server must present one of them, byte for byte, as its leaf certificate. Nothing else is
	// checked: not ServerName or the address, the chain, the validity period, a root store, revocation or Certificate
	// Transparency. The TLS handshake still proves that the server holds the key of the certificate. That is what a
	// server reached by IP address with a self-signed certificate needs; use it only with certificates you distribute
	// yourself, and list the current one and the next to rotate without a gap. It applies to HTTP/2 and QUIC alike;
	// another certificate fails the handshake (NetErrorCertAuthorityInvalid over HTTP/2). It cannot be combined with
	// TrustedRootCertificates or CertificatePublicKeySHA256: it replaces the roots, and fixes the key already.
	ExactServerCertificates [][]byte
}

// publicKeyPinLifetime is how long the engine keeps the pins of a client: longer than any process lives. A pin
// without a date in the future is no pin to Chromium.
const publicKeyPinLifetime = 10 * 365 * 24 * time.Hour

func NewNaiveClient(config NaiveClientOptions) (*NaiveClient, error) {
	err := checkLibrary()
	if err != nil {
		return nil, err
	}
	if !config.ServerAddress.IsValid() {
		return nil, E.New("invalid server address")
	}
	if config.DNSResolver == nil {
		return nil, E.New("DNSResolver is required")
	}

	serverName := config.ServerName
	if serverName == "" {
		serverName = config.ServerAddress.AddrString()
	}

	if len(config.CertificatePublicKeySHA256) > 0 {
		if M.ParseAddr(serverName).IsValid() {
			return nil, E.New("public key pins need a server name, not an address: ", serverName)
		}
		for _, hash := range config.CertificatePublicKeySHA256 {
			if len(hash) != sha256.Size {
				return nil, E.New("invalid public key pin: ", len(hash), " bytes, a SHA-256 hash is ", sha256.Size)
			}
		}
	}

	if len(config.ExactServerCertificates) > 0 {
		if config.TrustedRootCertificates != "" {
			return nil, E.New("exact server certificates replace the trusted root certificates: set one of them")
		}
		if len(config.CertificatePublicKeySHA256) > 0 {
			return nil, E.New("exact server certificates fix the key already: set them or public key pins")
		}
		for index, certificate := range config.ExactServerCertificates {
			if _, err := x509.ParseCertificate(certificate); err != nil {
				return nil, E.Cause(err, "exact server certificate ", index)
			}
		}
		err = CheckExactServerCertificatesSupport()
		if err != nil {
			return nil, err
		}
	}

	serverURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(serverName, F.ToString(config.ServerAddress.Port)),
	}

	var authorization string
	if config.Username != "" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(config.Username+":"+config.Password))
	}

	concurrency := config.InsecureConcurrency
	if concurrency < 1 {
		concurrency = 1
	}

	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}

	dialer := config.Dialer
	if dialer == nil {
		dialer = N.SystemDialer
	}

	l := config.Logger
	if l == nil {
		l = logger.NOP()
	}

	return &NaiveClient{
		ctx:                      ctx,
		dialer:                   dialer,
		logger:                   l,
		serverAddress:            config.ServerAddress,
		serverName:               serverName,
		serverURL:                serverURL.String(),
		authorization:            authorization,
		extraHeaders:             config.ExtraHeaders,
		concurrency:              concurrency,
		trustedRootCertificates:  config.TrustedRootCertificates,
		publicKeyPins:            config.CertificatePublicKeySHA256,
		exactCertificates:        config.ExactServerCertificates,
		dnsResolver:              config.DNSResolver,
		echEnabled:               config.ECHEnabled,
		echConfigList:            config.ECHConfigList,
		echQueryServerName:       config.ECHQueryServerName,
		testForceUDPLoopback:     config.TestForceUDPLoopback,
		singleEngine:             config.TestForceSingleEngine || runtime.GOOS == "ios",
		quicEnabled:              config.QUIC,
		quicCongestionControl:    config.QUICCongestionControl,
		quicAllowLocalRoots:      config.QUICAllowLocallyTrustedRoots,
		receiveWindow:            config.ReceiveWindow,
		quicSessionReceiveWindow: config.QUICSessionReceiveWindow,
		started:                  make(chan struct{}),
	}, nil
}

func (c *NaiveClient) Start() error {
	if !c.state.CompareAndSwap(uint32(clientStateCreated), uint32(clientStateStarting)) {
		state := clientState(c.state.Load())
		switch state {
		case clientStateStarting:
			return errors.New("start already in progress")
		case clientStateRunning:
			return errors.New("already started")
		default:
			return net.ErrClosed
		}
	}

	var startError error
	var engines []Engine

	defer func() {
		if startError != nil {
			if c.proxyCancel != nil {
				c.proxyCancel()
			}
			for _, engine := range engines {
				engine.Shutdown()
				engine.Destroy()
			}
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
		}
	}()

	proxyContext, proxyCancel := context.WithCancel(c.ctx)
	c.proxyCancel = proxyCancel

	dnsServerAddress := M.ParseSocksaddrHostPort("127.0.0.1", 53)
	dnsResolver := wrapDNSResolverWithFakeServerAddress(c.dnsResolver, c.serverName)

	if c.echEnabled {
		echQueryServerName := c.echQueryServerName
		if echQueryServerName == "" {
			echQueryServerName = c.serverName
		}
		dnsResolver = wrapDNSResolverWithECH(dnsResolver, c.serverName, echQueryServerName, c.getECHConfigList, c.quicEnabled, c.logger)
	}

	tcpDialer := Dialer(func(address string, port uint16) int {
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createSocketPair()
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code()
			}

			go func() {
				_ = serveDNSStreamConn(proxyContext, conn, dnsResolver)
			}()

			return fd
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		if destination.Addr == fakeServerAddress {
			destination = c.serverAddress
			destination.Port = port
		}
		c.logger.DebugContext(c.ctx, "open TCP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkTCP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open TCP connection to ", destination, ": ", err)
			return toNetError(err).Code()
		}

		if tcpConn, ok := N.CastReader[*net.TCPConn](conn); ok {
			fd, duplicateError := dupSocketFD(tcpConn)
			if duplicateError == nil {
				conn.Close()
				return fd
			}
		}

		c.logger.DebugContext(c.ctx, "relaying TCP connection to ", destination)
		fd, pipeConn, err := createSocketPair()
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code()
		}

		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			bufio.CopyConn(proxyContext, conn, pipeConn)
			conn.Close()
			pipeConn.Close()
		}()

		return fd
	})

	udpDialer := UDPDialer(func(address string, port uint16) (fd int, localAddress string, localPort uint16, onClose func()) {
		if address == dnsServerAddress.AddrString() && port == dnsServerAddress.Port {
			fd, conn, err := createPacketSocketPair(c.testForceUDPLoopback)
			if err != nil {
				c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
				return NetErrorConnectionFailed.Code(), "", 0, nil
			}
			localAddr := M.SocksaddrFromNet(conn.LocalAddr())
			if localAddr.IsValid() {
				localAddress = localAddr.AddrString()
				localPort = localAddr.Port
			}

			dnsContext, dnsCancel := context.WithCancel(proxyContext)
			go func() {
				defer dnsCancel()
				_ = serveDNSPacketConn(dnsContext, conn, dnsResolver)
			}()

			return fd, localAddress, localPort, dnsCancel
		}

		destination := M.ParseSocksaddrHostPort(address, port)
		if destination.Addr == fakeServerAddress {
			destination = c.serverAddress
			destination.Port = port
		}
		c.logger.DebugContext(c.ctx, "open UDP connection to ", destination)
		conn, err := c.dialer.DialContext(proxyContext, N.NetworkUDP, destination)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "open UDP connection to ", destination, ": ", err)
			return toNetError(err).Code(), "", 0, nil
		}

		localAddr := M.SocksaddrFromNet(conn.LocalAddr())
		if localAddr.IsValid() {
			localAddress = localAddr.AddrString()
			localPort = localAddr.Port
		}

		if udpConn, ok := N.CastReader[*net.UDPConn](conn); ok {
			fd, duplicateError := dupSocketFD(udpConn)
			if duplicateError == nil {
				conn.Close()
				return fd, localAddress, localPort, nil
			}
		}

		c.logger.DebugContext(c.ctx, "relaying UDP connection to ", destination)
		fd, pipeConn, err := createPacketSocketPair(c.testForceUDPLoopback)
		if err != nil {
			c.logger.ErrorContext(c.ctx, "socket pair failed: ", err)
			conn.Close()
			return NetErrorConnectionFailed.Code(), "", 0, nil
		}

		remoteAddress := M.SocksaddrFromNet(conn.RemoteAddr())
		packetConn := bufio.NewUnbindPacketConn(conn)
		pipePacketConn := bufio.NewUnbindPacketConnWithAddr(pipeConn.(net.Conn), remoteAddress)

		relayContext, relayCancel := context.WithCancel(proxyContext)
		c.proxyWaitGroup.Add(1)
		go func() {
			defer c.proxyWaitGroup.Done()
			defer relayCancel()
			_ = bufio.CopyPacketConn(relayContext, packetConn, pipePacketConn)
		}()

		return fd, localAddress, localPort, relayCancel
	})

	engineCount := 1
	if c.concurrency > 1 && !c.singleEngine {
		engineCount = c.concurrency
	}
	for i := 0; i < engineCount; i++ {
		var engine Engine
		engine, startError = c.startEngine(tcpDialer, udpDialer, dnsServerAddress)
		if startError != nil {
			return startError
		}
		engines = append(engines, engine)
	}

	c.engines = engines
	c.streamEngines = common.Map(engines, Engine.StreamEngine)

	c.state.Store(uint32(clientStateRunning))
	close(c.started)
	return nil
}

func (c *NaiveClient) startEngine(tcpDialer Dialer, udpDialer UDPDialer, dnsServerAddress M.Socksaddr) (Engine, error) {
	engine := NewEngine()
	destroyEngine := func() {
		engine.Shutdown()
		engine.Destroy()
	}

	if c.trustedRootCertificates != "" {
		if !engine.SetTrustedRootCertificates(c.trustedRootCertificates) {
			destroyEngine()
			return Engine{}, E.New("failed to set trusted CA certificates")
		}
	}

	engine.SetDialer(tcpDialer)
	engine.SetUDPDialer(udpDialer)

	params := NewEngineParams()
	if c.quicEnabled {
		params.SetEnableQuic(true)
	} else {
		params.SetEnableQuic(false)
		params.SetEnableHTTP2(true)
	}

	if len(c.publicKeyPins) > 0 {
		pins := NewPublicKeyPins()
		pins.SetHost(c.serverName)
		for _, hash := range c.publicKeyPins {
			pins.AddPinnedSHA256("sha256/" + base64.StdEncoding.EncodeToString(hash))
		}
		pins.SetIncludeSubdomains(false)
		pins.SetExpirationDate(time.Now().Add(publicKeyPinLifetime).UnixMilli())
		// the engine's parameters take a copy
		params.AddPublicKeyPins(pins)
		pins.Destroy()
		// a root of TrustedRootCertificates is a local trust anchor, which Chromium lets past the pins by default
		params.SetEnablePublicKeyPinningBypassForLocalTrustAnchors(false)
	}

	// the parameters take a copy; with none, the default verification
	paramsError := params.SetExactServerCertificates(c.exactCertificates)
	if paramsError == nil {
		paramsError = params.SetAsyncDNS(true)
	}
	if paramsError == nil {
		paramsError = params.SetDNSServerOverride([]string{dnsServerAddress.String()})
	}
	if paramsError == nil {
		paramsError = params.SetUseDnsHttpsSvcb(c.echEnabled)
	}
	if paramsError == nil {
		if c.quicEnabled {
			streamReceiveWindow := c.receiveWindow
			if streamReceiveWindow == 0 {
				streamReceiveWindow = 6 * 1024 * 1024
			}
			sessionReceiveWindow := c.quicSessionReceiveWindow
			if sessionReceiveWindow == 0 {
				sessionReceiveWindow = 15 * 1024 * 1024
			}
			paramsError = params.SetQUICOptions("", string(c.quicCongestionControl), streamReceiveWindow, sessionReceiveWindow)
			// after SetQUICOptions, which writes the "QUIC" dictionary anew
			if paramsError == nil && c.quicAllowLocalRoots {
				paramsError = params.SetQUICAllowUnknownCertRoots(true)
			}
		} else {
			receiveWindow := c.receiveWindow
			if receiveWindow == 0 {
				if runtime.GOOS == "ios" {
					receiveWindow = 4 * 1024 * 1024
				} else {
					receiveWindow = 128 * 1024 * 1024
				}
			}
			paramsError = params.SetHTTP2Options(receiveWindow, receiveWindow/2)
		}
	}
	if paramsError == nil {
		paramsError = params.SetSocketPoolOptions(2048, 2048, 2040)
	}
	if paramsError != nil {
		params.Destroy()
		destroyEngine()
		return Engine{}, paramsError
	}

	experimentalOptions := params.ExperimentalOptions()
	c.experimentalOptions.Store(&experimentalOptions)
	result := engine.StartWithParams(params)
	params.Destroy()
	if result != ResultSuccess {
		destroyEngine()
		return Engine{}, E.New("failed to start engine: ", int(result))
	}
	return engine, nil
}

// ExperimentalOptions are the experimental options, as JSON, of the engine this client started last: what its
// options came to. Empty before Start.
func (c *NaiveClient) ExperimentalOptions() string {
	if options := c.experimentalOptions.Load(); options != nil {
		return *options
	}
	return ""
}

func (c *NaiveClient) Engine() Engine {
	if clientState(c.state.Load()) != clientStateRunning {
		return Engine{}
	}
	return c.engines[0]
}

func (c *NaiveClient) CloseAllConnections() {
	if clientState(c.state.Load()) != clientStateRunning {
		return
	}
	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
}

// DialEarly opens a tunnel to destination and returns it at once, before the server answers: the first write goes
// with the CONNECT. NaiveConn.Handshake waits for the answer.
func (c *NaiveClient) DialEarly(ctx context.Context, destination M.Socksaddr) (NaiveConn, error) {
	return c.dialEarly(ctx, destination, nil)
}

// DialEarlyWithHeaders is DialEarly with header added to the CONNECT of this one stream, inside TLS. The names that
// the client sets itself (Proxy-Authorization, Padding and the other padding fields), pseudo-headers, names that start
// with "-" (the library's own), and the connection-specific fields that HTTP/2 and HTTP/3 forbid are refused, as are
// names and values that are not valid in HTTP. A field of ExtraHeaders with the same name is replaced; the values
// of one name are joined with ", ". A refusal of the server is a *ConnectError from NaiveConn.Handshake.
func (c *NaiveClient) DialEarlyWithHeaders(ctx context.Context, destination M.Socksaddr, header http.Header) (NaiveConn, error) {
	streamHeaders, err := connectRequestHeaders(header)
	if err != nil {
		return nil, err
	}
	return c.dialEarly(ctx, destination, streamHeaders)
}

// DialContextWithHeaders opens a tunnel to destination with header added to its CONNECT, as DialEarlyWithHeaders
// does, and waits for the answer of the server. On a 200 it returns the tunnel, whose ResponseHeader holds the fields
// of the answer. On another status it returns a *ConnectError with the status and the fields, such as a 403 with
// Niko-Refused, and closes the stream. network must be TCP.
func (c *NaiveClient) DialContextWithHeaders(ctx context.Context, network string, destination M.Socksaddr, header http.Header) (NaiveConn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := c.DialEarlyWithHeaders(ctx, destination, header)
	if err != nil {
		return nil, err
	}
	err = conn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *NaiveClient) dialEarly(ctx context.Context, destination M.Socksaddr, streamHeaders map[string]string) (NaiveConn, error) {
	state := clientState(c.state.Load())
	switch state {
	case clientStateRunning:
	case clientStateClosed, clientStateClosing:
		return nil, net.ErrClosed
	default:
		select {
		case <-c.started:
			if clientState(c.state.Load()) != clientStateRunning {
				return nil, net.ErrClosed
			}
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	headers := map[string]string{
		"-connect-authority": destination.String(),
		"Padding":            generatePaddingHeader(),
	}
	if c.authorization != "" {
		headers["proxy-authorization"] = c.authorization
	}
	if c.quicEnabled {
		headers["-force-quic"] = "true"
	}
	for key, value := range c.extraHeaders {
		headers[key] = value
	}
	// connectRequestHeaders refuses the names set above; one of ExtraHeaders is replaced, whatever its case
	for name, value := range streamHeaders {
		for key := range headers {
			if strings.EqualFold(key, name) {
				delete(headers, key)
			}
		}
		headers[name] = value
	}

	streamEngine := c.streamEngines[0]
	if c.concurrency > 1 {
		concurrencyIndex := int(c.counter.Add(1) % uint64(c.concurrency))
		if len(c.streamEngines) > 1 {
			streamEngine = c.streamEngines[concurrencyIndex]
		} else {
			headers["-network-isolation-key"] = F.ToString("https://pool-", concurrencyIndex, ":443")
		}
	}
	conn := streamEngine.CreateConn(ctx, c.logger, true, false)
	err := conn.Start("CONNECT", c.serverURL, headers, 0, false)
	if err != nil {
		return nil, err
	}
	trackedConn := &trackedNaiveConn{
		NaiveConn: NewNaiveConn(ctx, conn, c.logger),
		client:    c,
	}
	c.activeConnections.Add(1)
	conn.setOnTerminate(trackedConn.release)
	return trackedConn, nil
}

func (c *NaiveClient) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := c.DialEarly(ctx, destination)
	if err != nil {
		return nil, err
	}
	err = conn.HandshakeContext(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *NaiveClient) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *NaiveClient) Close() error {
	for {
		state := clientState(c.state.Load())
		switch state {
		case clientStateCreated:
			if c.state.CompareAndSwap(uint32(clientStateCreated), uint32(clientStateClosed)) {
				close(c.started)
				return nil
			}

		case clientStateStarting:
			select {
			case <-c.started:
				continue
			case <-c.ctx.Done():
				return c.ctx.Err()
			}

		case clientStateRunning:
			if !c.state.CompareAndSwap(uint32(clientStateRunning), uint32(clientStateClosing)) {
				continue
			}
			return c.doClose()

		case clientStateClosing:
			return nil

		case clientStateClosed:
			return net.ErrClosed
		}
	}
}

func (c *NaiveClient) doClose() error {
	if c.proxyCancel != nil {
		c.proxyCancel()
	}

	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
	c.proxyWaitGroup.Wait()
	c.activeConnections.Wait()
	for _, engine := range c.engines {
		engine.Shutdown()
		engine.Destroy()
	}

	c.state.Store(uint32(clientStateClosed))
	return nil
}

func (c *NaiveClient) getECHConfigList() []byte {
	c.echMutex.RLock()
	defer c.echMutex.RUnlock()
	return c.echConfigList
}

type trackedNaiveConn struct {
	NaiveConn
	client    *NaiveClient
	closeOnce sync.Once
}

func (c *trackedNaiveConn) release() {
	c.closeOnce.Do(func() {
		c.client.activeConnections.Done()
	})
}

func (c *trackedNaiveConn) Close() error {
	c.release()
	return c.NaiveConn.Close()
}

func (c *trackedNaiveConn) Upstream() any {
	return c.NaiveConn
}

func (c *trackedNaiveConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedNaiveConn) WriterReplaceable() bool {
	return true
}
