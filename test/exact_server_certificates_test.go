package test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// startExactEngine starts an engine that trusts exactly certificates (none: the default verification), with QUIC
// or without.
func startExactEngine(t *testing.T, quic bool, certificates [][]byte) cronet.Engine {
	t.Helper()
	engine := cronet.NewEngine()
	params := cronet.NewEngineParams()
	params.SetEnableHTTP2(true)
	params.SetEnableQuic(quic)
	require.NoError(t, params.SetExactServerCertificates(certificates))
	result := engine.StartWithParams(params)
	params.Destroy()
	require.Equal(t, cronet.ResultSuccess, result)
	t.Cleanup(func() {
		engine.Shutdown()
		engine.Destroy()
	})
	return engine
}

// exactGet sends a GET to url over a stream of engine, over QUIC if quic, and returns the response headers or the
// error that ended the stream.
func exactGet(t *testing.T, engine cronet.Engine, url string, quic bool) (map[string]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	headers := map[string]string{}
	if quic {
		headers["-force-quic"] = "true"
	}
	conn := engine.StreamEngine().CreateConn(ctx, logger.NOP(), true, false)
	defer conn.Close()
	require.NoError(t, conn.Start("GET", url, headers, 0, true))
	return conn.WaitForHeadersContext(ctx)
}

// requireExactAccepted: the GET went through, over the protocol of the server.
func requireExactAccepted(t *testing.T, headers map[string]string, err error, quic bool) {
	t.Helper()
	require.NoError(t, err)
	require.Equal(t, "200", headers[":status"])
	if quic {
		require.Equal(t, "HTTP/3.0", headers["test-proto"])
	} else {
		require.Equal(t, "HTTP/2.0", headers["test-proto"])
	}
}

// requireExactRefused: the certificate of the server was refused. Over TLS the stream fails with the verifier's
// error; over QUIC the handshake fails, and the verifier's error stays in the connection's error details.
func requireExactRefused(t *testing.T, err error, quic bool) {
	t.Helper()
	require.Error(t, err, "the server was accepted")
	var netError cronet.NetError
	require.True(t, errors.As(err, &netError), "not a network error: %v", err)
	t.Logf("refused with %s (%d)", netError.Name(), netError.Code())
	if quic {
		require.Contains(t, []cronet.NetError{cronet.NetErrorQUICHandshakeFailed, cronet.NetErrorQUICProtocolError}, netError)
	} else {
		require.Equal(t, cronet.NetErrorCertAuthorityInvalid, netError)
	}
}

func TestExactServerCertificatesParams(t *testing.T) {
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())
	current := validSelfSignedCertificate(t, "current")
	spare := validSelfSignedCertificate(t, "spare")

	params := cronet.NewEngineParams()
	defer params.Destroy()
	require.Nil(t, params.ExactServerCertificates())

	given := [][]byte{append([]byte(nil), current.der...), append([]byte(nil), spare.der...)}
	require.NoError(t, params.SetExactServerCertificates(given))
	// the parameters keep a copy
	given[0][0] ^= 0xff
	require.Equal(t, [][]byte{current.der, spare.der}, params.ExactServerCertificates())

	// a call replaces the list
	require.NoError(t, params.SetExactServerCertificates([][]byte{spare.der}))
	require.Equal(t, [][]byte{spare.der}, params.ExactServerCertificates())
	require.NoError(t, params.SetExactServerCertificates(nil))
	require.Nil(t, params.ExactServerCertificates())
}

// TestExactServerCertificates: an engine with exact server certificates trusts a server, over HTTP/2 and over
// HTTP/3, if and only if its certificate is one of them. The certificates are self-signed for 192.0.2.1, and the
// servers are reached at 127.0.0.1: neither the chain nor the address is checked.
func TestExactServerCertificates(t *testing.T) {
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())
	current := validSelfSignedCertificate(t, "current")
	spare := validSelfSignedCertificate(t, "spare")
	other := validSelfSignedCertificate(t, "other")

	for _, transport := range []struct {
		name string
		quic bool
	}{{"h2", false}, {"h3", true}} {
		t.Run(transport.name, func(t *testing.T) {
			currentServer := startNaiveTestServer(t, transport.quic, current)
			spareServer := startNaiveTestServer(t, transport.quic, spare)
			currentURL := fmt.Sprintf("https://127.0.0.1:%d/", currentServer.port)
			spareURL := fmt.Sprintf("https://127.0.0.1:%d/", spareServer.port)

			t.Run("its certificate", func(t *testing.T) {
				engine := startExactEngine(t, transport.quic, [][]byte{current.der})
				headers, err := exactGet(t, engine, currentURL, transport.quic)
				requireExactAccepted(t, headers, err, transport.quic)
				_, err = exactGet(t, engine, spareURL, transport.quic)
				requireExactRefused(t, err, transport.quic)
			})

			t.Run("another certificate", func(t *testing.T) {
				engine := startExactEngine(t, transport.quic, [][]byte{other.der})
				_, err := exactGet(t, engine, currentURL, transport.quic)
				requireExactRefused(t, err, transport.quic)
			})

			t.Run("current and spare", func(t *testing.T) {
				engine := startExactEngine(t, transport.quic, [][]byte{current.der, spare.der})
				headers, err := exactGet(t, engine, currentURL, transport.quic)
				requireExactAccepted(t, headers, err, transport.quic)
				headers, err = exactGet(t, engine, spareURL, transport.quic)
				requireExactAccepted(t, headers, err, transport.quic)
			})

			t.Run("no certificates", func(t *testing.T) {
				// the default verification, which knows no self-signed certificate
				engine := startExactEngine(t, transport.quic, nil)
				_, err := exactGet(t, engine, currentURL, transport.quic)
				require.Error(t, err, "a self-signed certificate passed the default verification")
				t.Logf("default verification: %v", err)
			})
		})
	}

	// The validity period is not checked either: the list decides alone.
	t.Run("expired", func(t *testing.T) {
		expired := generateSelfSignedCertificate(t, "expired", time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-1, 0, 0))
		server := startNaiveTestServer(t, false, expired)
		engine := startExactEngine(t, false, [][]byte{expired.der})
		headers, err := exactGet(t, engine, fmt.Sprintf("https://127.0.0.1:%d/", server.port), false)
		requireExactAccepted(t, headers, err, false)
	})
}

// TestExactServerCertificatesRefusedAtStart: StartWithParams refuses what is not a certificate, public key pins next
// to the list, and an engine that already has a certificate verifier of its own.
func TestExactServerCertificatesRefusedAtStart(t *testing.T) {
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())
	certificate := validSelfSignedCertificate(t, "current")
	caPem, _, _ := generateCertificate(t, "example.org")
	caPemContent, err := os.ReadFile(caPem)
	require.NoError(t, err)

	start := func(t *testing.T, certificates [][]byte, configure func(cronet.Engine, cronet.EngineParams)) cronet.Result {
		engine := cronet.NewEngine()
		params := cronet.NewEngineParams()
		params.SetEnableCheckResult(false)
		require.NoError(t, params.SetExactServerCertificates(certificates))
		if configure != nil {
			configure(engine, params)
		}
		result := engine.StartWithParams(params)
		params.Destroy()
		engine.Shutdown()
		engine.Destroy()
		return result
	}

	t.Run("not a certificate", func(t *testing.T) {
		require.Equal(t, cronet.ResultIllegalArgument, start(t, [][]byte{certificate.der, []byte("not a certificate")}, nil))
	})
	t.Run("an empty entry", func(t *testing.T) {
		require.Equal(t, cronet.ResultIllegalArgument, start(t, [][]byte{{}}, nil))
	})
	t.Run("PEM instead of DER", func(t *testing.T) {
		pemContent, err := os.ReadFile(certificate.certPath)
		require.NoError(t, err)
		require.Equal(t, cronet.ResultIllegalArgument, start(t, [][]byte{pemContent}, nil))
	})
	t.Run("public key pins", func(t *testing.T) {
		require.Equal(t, cronet.ResultIllegalArgument, start(t, [][]byte{certificate.der}, func(_ cronet.Engine, params cronet.EngineParams) {
			pins := cronet.NewPublicKeyPins()
			pins.SetHost("example.org")
			pins.AddPinnedSHA256("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			pins.SetExpirationDate(time.Now().Add(time.Hour).UnixMilli())
			params.AddPublicKeyPins(pins)
			pins.Destroy()
		}))
	})
	t.Run("trusted root certificates", func(t *testing.T) {
		require.Equal(t, cronet.ResultIllegalState, start(t, [][]byte{certificate.der}, func(engine cronet.Engine, _ cronet.EngineParams) {
			require.True(t, engine.SetTrustedRootCertificates(string(caPemContent)))
		}))
	})
	t.Run("the list alone", func(t *testing.T) {
		require.Equal(t, cronet.ResultSuccess, start(t, [][]byte{certificate.der}, nil))
	})
}

const (
	exactDefaultChildEnv = "CRONET_TEST_EXACT_DEFAULT_CHILD"
	exactDefaultPortEnv  = "CRONET_TEST_EXACT_DEFAULT_PORT"
	exactDefaultLeafEnv  = "CRONET_TEST_EXACT_DEFAULT_LEAF"
)

// TestExactServerCertificatesEmptyListDefaultVerification: an empty list leaves the default verification in place,
// and a list replaces it. Under the default verifier a root named by SSL_CERT_FILE is trusted over TCP; the child
// process, with SSL_CERT_FILE in its environment, which the library reads from the C environment, reaches a server
// whose chain ends at that root:
//   - with no list, and with a list set and then cleared: accepted;
//   - with a list that does not hold the server's certificate: refused, although the root is trusted;
//   - with the server's leaf in the list: accepted.
func TestExactServerCertificatesEmptyListDefaultVerification(t *testing.T) {
	if os.Getenv(exactDefaultChildEnv) == "1" {
		runExactDefaultChild(t)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("SSL_CERT_FILE names local roots on Linux")
	}
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())

	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	serverCertificate, err := loadTestCertificate(certPem, keyPem)
	require.NoError(t, err)
	server := startNaiveTestServer(t, false, serverCertificate)

	command := exec.Command(os.Args[0], "-test.run=^TestExactServerCertificatesEmptyListDefaultVerification$", "-test.v", "-test.count=1")
	var childEnv []string
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "SSL_CERT_FILE=") || strings.HasPrefix(variable, "SSL_CERT_DIR=") {
			continue
		}
		childEnv = append(childEnv, variable)
	}
	command.Env = append(childEnv,
		exactDefaultChildEnv+"=1",
		exactDefaultPortEnv+"="+strconv.Itoa(int(server.port)),
		exactDefaultLeafEnv+"="+serverCertificate.certPath,
		"SSL_CERT_FILE="+caPem,
	)
	output, err := command.CombinedOutput()
	t.Logf("child (SSL_CERT_FILE=%s):\n%s", filepath.Base(caPem), output)
	require.NoError(t, err, "the child test process failed")
}

func runExactDefaultChild(t *testing.T) {
	port, err := strconv.Atoi(os.Getenv(exactDefaultPortEnv))
	require.NoError(t, err)
	leaf, err := loadTestCertificate(os.Getenv(exactDefaultLeafEnv), "")
	require.NoError(t, err)
	other := validSelfSignedCertificate(t, "other")
	url := fmt.Sprintf("https://example.org:%d/", port)

	get := func(t *testing.T, configure func(cronet.EngineParams)) (map[string]string, error) {
		engine := cronet.NewEngine()
		params := cronet.NewEngineParams()
		params.SetEnableHTTP2(true)
		params.SetEnableQuic(false)
		require.NoError(t, params.SetHostResolverRules("MAP example.org 127.0.0.1"))
		configure(params)
		result := engine.StartWithParams(params)
		params.Destroy()
		require.Equal(t, cronet.ResultSuccess, result)
		defer func() {
			engine.Shutdown()
			engine.Destroy()
		}()
		return exactGet(t, engine, url, false)
	}

	t.Run("no list", func(t *testing.T) {
		headers, err := get(t, func(params cronet.EngineParams) {
			require.NoError(t, params.SetExactServerCertificates(nil))
		})
		requireExactAccepted(t, headers, err, false)
	})
	t.Run("a list set and cleared", func(t *testing.T) {
		headers, err := get(t, func(params cronet.EngineParams) {
			require.NoError(t, params.SetExactServerCertificates([][]byte{other.der}))
			require.NoError(t, params.SetExactServerCertificates([][]byte{}))
		})
		requireExactAccepted(t, headers, err, false)
	})
	t.Run("a list without the server's certificate", func(t *testing.T) {
		_, err := get(t, func(params cronet.EngineParams) {
			require.NoError(t, params.SetExactServerCertificates([][]byte{other.der}))
		})
		requireExactRefused(t, err, false)
	})
	t.Run("the server's leaf in the list", func(t *testing.T) {
		headers, err := get(t, func(params cronet.EngineParams) {
			require.NoError(t, params.SetExactServerCertificates([][]byte{leaf.der}))
		})
		requireExactAccepted(t, headers, err, false)
	})
}

// TestExactServerCertificatesUnsupportedLibrary runs against a build without exact server certificates: the workflow
// builds the test binary for it from include_cgo.go without the define that the package step writes for them, and
// sets CRONET_TEST_NO_EXACT_SERVER_CERTIFICATES=1. Everything else works; a list is refused with
// ErrExactServerCertificatesUnsupported, and an empty one changes nothing.
func TestExactServerCertificatesUnsupportedLibrary(t *testing.T) {
	if os.Getenv("CRONET_TEST_NO_EXACT_SERVER_CERTIFICATES") != "1" {
		t.Skip("for a build without exact server certificates")
	}
	require.ErrorIs(t, cronet.CheckExactServerCertificatesSupport(), cronet.ErrExactServerCertificatesUnsupported)
	certificate := validSelfSignedCertificate(t, "current")

	params := cronet.NewEngineParams()
	defer params.Destroy()
	require.ErrorIs(t, params.SetExactServerCertificates([][]byte{certificate.der}), cronet.ErrExactServerCertificatesUnsupported)
	require.NoError(t, params.SetExactServerCertificates(nil))
	require.Nil(t, params.ExactServerCertificates())
	startExactEngine(t, false, nil)

	_, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", 443),
		DNSResolver:             localhostDNSResolver(t),
		ExactServerCertificates: [][]byte{certificate.der},
	})
	require.ErrorIs(t, err, cronet.ErrExactServerCertificatesUnsupported)
}

var naiveTestTransports = []struct {
	name string
	quic bool
}{{"h2", false}, {"h3", true}}

// startRelayStyleClient starts a NaiveClient of server as a relay entry is reached: by IP address, without a server
// name, trusting exactly the given certificates.
func startRelayStyleClient(t *testing.T, server *naiveTestServer, certificates [][]byte, extraHeaders map[string]string) *cronet.NaiveClient {
	t.Helper()
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", server.port),
		Username:                "test",
		Password:                "test",
		DNSResolver:             localhostDNSResolver(t),
		ExactServerCertificates: certificates,
		ExtraHeaders:            extraHeaders,
		QUIC:                    server.quic,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() { client.Close() })
	return client
}

// requireEcho writes through conn and reads the same back.
func requireEcho(t *testing.T, conn cronet.NaiveConn, data string) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := conn.Write([]byte(data))
	require.NoError(t, err)
	echo := make([]byte, len(data))
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err)
	require.Equal(t, data, string(echo))
}

// TestNaiveExactServerCertificates: NaiveClient reaches a server by IP address under a self-signed certificate of
// ExactServerCertificates, over HTTP/2 and HTTP/3, and refuses it under another certificate.
func TestNaiveExactServerCertificates(t *testing.T) {
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())
	current := validSelfSignedCertificate(t, "current")
	spare := validSelfSignedCertificate(t, "spare")
	other := validSelfSignedCertificate(t, "other")
	destination := M.ParseSocksaddrHostPort("allow.test", 443)

	for _, transport := range naiveTestTransports {
		t.Run(transport.name, func(t *testing.T) {
			server := startNaiveTestServer(t, transport.quic, current)

			t.Run("current and spare", func(t *testing.T) {
				client := startRelayStyleClient(t, server, [][]byte{spare.der, current.der}, nil)
				conn, err := client.DialContext(context.Background(), "tcp", destination)
				require.NoError(t, err)
				defer conn.Close()
				requireEcho(t, conn.(cronet.NaiveConn), "exact certificate")
			})

			t.Run("another certificate", func(t *testing.T) {
				client := startRelayStyleClient(t, server, [][]byte{other.der}, nil)
				refusedDestination := M.ParseSocksaddrHostPort("refused-certificate.test", 443)
				_, err := client.DialContext(context.Background(), "tcp", refusedDestination)
				requireExactRefused(t, err, transport.quic)
				require.Nil(t, server.requestHeader(refusedDestination.String()), "the server got the CONNECT")
			})
		})
	}

	t.Run("refused options", func(t *testing.T) {
		caPem, _, _ := generateCertificate(t, "example.org")
		caPemContent, err := os.ReadFile(caPem)
		require.NoError(t, err)
		key := sha256.Sum256(current.der)
		for name, options := range map[string]cronet.NaiveClientOptions{
			"with trusted root certificates": {TrustedRootCertificates: string(caPemContent)},
			"with public key pins":           {ServerName: "example.org", CertificatePublicKeySHA256: [][]byte{key[:]}},
		} {
			options.ServerAddress = M.ParseSocksaddrHostPort("127.0.0.1", 443)
			options.DNSResolver = localhostDNSResolver(t)
			options.ExactServerCertificates = [][]byte{current.der}
			_, err := cronet.NewNaiveClient(options)
			require.Error(t, err, name)
		}
		_, err = cronet.NewNaiveClient(cronet.NaiveClientOptions{
			ServerAddress:           M.ParseSocksaddrHostPort("127.0.0.1", 443),
			DNSResolver:             localhostDNSResolver(t),
			ExactServerCertificates: [][]byte{current.der, []byte("not a certificate")},
		})
		require.Error(t, err, "not a certificate")
	})
}
