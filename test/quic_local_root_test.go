package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const (
	quicLocalRootChildEnv      = "CRONET_TEST_QUIC_LOCAL_ROOT_CHILD"
	quicLocalRootTransportEnv  = "CRONET_TEST_QUIC_LOCAL_ROOT_TRANSPORT"
	quicLocalRootOptionEnv     = "CRONET_TEST_QUIC_LOCAL_ROOT_OPTION"
	quicLocalRootExpectEnv     = "CRONET_TEST_QUIC_LOCAL_ROOT_EXPECT"
	quicLocalRootServerPortEnv = "CRONET_TEST_QUIC_LOCAL_ROOT_SERVER_PORT"
	quicLocalRootEchoPortEnv   = "CRONET_TEST_QUIC_LOCAL_ROOT_ECHO_PORT"
	quicLocalRootNetLogEnv     = "CRONET_TEST_QUIC_LOCAL_ROOT_NETLOG"

	// quicLocalRootAccept: the connection is made and carries data.
	quicLocalRootAccept = "accept"
	// quicLocalRootNotKnown: the chain verifies against the locally trusted root, and QUIC refuses it only because
	// that root is not a known one (ERR_QUIC_CERT_ROOT_NOT_KNOWN in ProofVerifierChromium).
	quicLocalRootNotKnown = "refuse-not-known"
	// quicLocalRootUntrusted: the chain does not verify at all.
	quicLocalRootUntrusted = "refuse-untrusted"
)

// TestQUICLocallyTrustedRoot: under the default certificate verifier a root named by SSL_CERT_FILE is locally trusted,
// not known (not in the Chrome Root Store). TLS over TCP accepts it; QUIC requires a known root unless the engine's
// experimental options carry {"QUIC": {"allow_unknown_cert_roots": true}}, and the option lifts only that requirement:
// a chain to a root that is trusted nowhere is still refused.
//
// The server's root is never passed through TrustedRootCertificates, which would install a verifier of the embedder's
// and lift the known-root requirement by itself. NaiveClientOptions has no field for experimental options, so the
// engine is built here with the lower-level API, with the stream headers NaiveClient sends. Each case runs in its own
// test process with SSL_CERT_FILE in its environment, since the library reads it from the C environment.
func TestQUICLocallyTrustedRoot(t *testing.T) {
	if os.Getenv(quicLocalRootChildEnv) == "1" {
		runQUICLocalRootChild(t)
		return
	}

	// One certificate for example.org under a private root, served over TCP (HTTP/2) and over QUIC.
	env := setupTestEnv(t)
	quicPort := reserveUDPPort(t)
	startNaiveQUICServer(t, env.certPath, env.keyPath, quicPort)
	echoPort := reserveTCPPort(t)
	startEchoServer(t, echoPort)

	directory := t.TempDir()
	serverRoot := filepath.Join(directory, "server-root.pem")
	require.NoError(t, os.WriteFile(serverRoot, env.caPEM, 0o644))
	otherRootPath, _, _ := generateCertificate(t, "other.invalid")
	otherRootContent, err := os.ReadFile(otherRootPath)
	require.NoError(t, err)
	otherRoot := filepath.Join(directory, "other-root.pem")
	require.NoError(t, os.WriteFile(otherRoot, otherRootContent, 0o644))

	cases := []struct {
		name      string
		transport string
		option    bool
		rootsFile string
		expect    string
	}{
		{"TCP, root in the file", "tcp", false, serverRoot, quicLocalRootAccept},
		{"QUIC without the option, root in the file", "quic", false, serverRoot, quicLocalRootNotKnown},
		{"QUIC with the option, root in the file", "quic", true, serverRoot, quicLocalRootAccept},
		{"QUIC with the option, another root in the file", "quic", true, otherRoot, quicLocalRootUntrusted},
	}
	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			serverPort := naiveServerPort
			if testCase.transport == "quic" {
				serverPort = int(quicPort)
			}
			option := "0"
			if testCase.option {
				option = "1"
			}
			netLogPath := artifactPath(t, "netlog", fmt.Sprintf("quic_local_root_%d_netlog.json", index))

			command := exec.Command(os.Args[0], "-test.run=^TestQUICLocallyTrustedRoot$", "-test.v", "-test.count=1")
			var childEnv []string
			for _, variable := range os.Environ() {
				if strings.HasPrefix(variable, "SSL_CERT_FILE=") || strings.HasPrefix(variable, "SSL_CERT_DIR=") {
					continue
				}
				childEnv = append(childEnv, variable)
			}
			command.Env = append(childEnv,
				quicLocalRootChildEnv+"=1",
				quicLocalRootTransportEnv+"="+testCase.transport,
				quicLocalRootOptionEnv+"="+option,
				quicLocalRootExpectEnv+"="+testCase.expect,
				quicLocalRootServerPortEnv+"="+strconv.Itoa(serverPort),
				quicLocalRootEchoPortEnv+"="+strconv.Itoa(int(echoPort)),
				quicLocalRootNetLogEnv+"="+netLogPath,
				"SSL_CERT_FILE="+testCase.rootsFile,
			)
			output, err := command.CombinedOutput()
			t.Logf("child (%s, option %s, SSL_CERT_FILE=%s):\n%s", testCase.transport, option, filepath.Base(testCase.rootsFile), output)
			require.NoError(t, err, "the child test process failed")
		})
	}
}

func runQUICLocalRootChild(t *testing.T) {
	quic := os.Getenv(quicLocalRootTransportEnv) == "quic"
	option := os.Getenv(quicLocalRootOptionEnv) == "1"
	expect := os.Getenv(quicLocalRootExpectEnv)
	serverPort, err := strconv.Atoi(os.Getenv(quicLocalRootServerPortEnv))
	require.NoError(t, err)
	echoPort, err := strconv.Atoi(os.Getenv(quicLocalRootEchoPortEnv))
	require.NoError(t, err)
	netLogPath := os.Getenv(quicLocalRootNetLogEnv)

	engine := cronet.NewEngine()
	params := cronet.NewEngineParams()
	params.SetEnableHTTP2(true)
	params.SetEnableQuic(quic)
	require.NoError(t, params.SetHostResolverRules("MAP example.org 127.0.0.1"))
	if option {
		require.NoError(t, params.SetExperimentalOption("QUIC", map[string]any{
			"allow_unknown_cert_roots": true,
		}))
	}
	t.Logf("experimental options: %s", params.ExperimentalOptions())
	result := engine.StartWithParams(params)
	params.Destroy()
	require.Equal(t, cronet.ResultSuccess, result)
	defer func() {
		engine.Shutdown()
		engine.Destroy()
	}()
	require.True(t, engine.StartNetLogToFile(netLogPath, true), "failed to start NetLog")
	netLogStopped := false
	stopNetLog := func() {
		if !netLogStopped {
			engine.StopNetLog()
			netLogStopped = true
		}
	}
	defer stopNetLog()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	headers := map[string]string{
		"-connect-authority":  fmt.Sprintf("127.0.0.1:%d", echoPort),
		"Padding":             quicLocalRootPaddingHeader(),
		"proxy-authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("test:test")),
	}
	if quic {
		headers["-force-quic"] = "true"
	}
	stream := engine.StreamEngine().CreateConn(ctx, logger.NOP(), true, false)
	require.NoError(t, stream.Start("CONNECT", fmt.Sprintf("https://example.org:%d", serverPort), headers, 0, false))
	conn := cronet.NewNaiveConn(ctx, stream, logger.NOP())
	defer conn.Close()

	handshakeError := conn.HandshakeContext(ctx)
	if expect == quicLocalRootAccept {
		require.NoError(t, handshakeError)
		testData := []byte("locally trusted root")
		_, err = conn.Write(testData)
		require.NoError(t, err)
		echo := make([]byte, len(testData))
		_, err = io.ReadFull(conn, echo)
		require.NoError(t, err)
		require.Equal(t, testData, echo)
		conn.Close()
		stopNetLog()
		if quic {
			require.True(t, netLogHasEvent(t, netLogPath, "QUIC_SESSION_CERTIFICATE_VERIFIED"), "no QUIC session verified the certificate")
		}
		return
	}

	require.Error(t, handshakeError, "the server was accepted")
	var netError cronet.NetError
	require.True(t, errors.As(handshakeError, &netError), "not a network error: %v", handshakeError)
	t.Logf("refused with %s (%d)", netError.Name(), netError.Code())
	// A QUIC handshake that the proof verifier fails surfaces as a QUIC handshake error, not as the verifier's own
	// error, which goes into the connection's error details only.
	require.Contains(t, []cronet.NetError{
		cronet.NetErrorQUICCertRootNotKnown,
		cronet.NetErrorQUICHandshakeFailed,
		cronet.NetErrorQUICProtocolError,
	}, netError)
	conn.Close()
	stopNetLog()

	verified := netLogHasEvent(t, netLogPath, "QUIC_SESSION_CERTIFICATE_VERIFIED")
	verifyFailed := netLogHasEvent(t, netLogPath, "QUIC_SESSION_CERTIFICATE_VERIFY_FAILED")
	switch expect {
	case quicLocalRootNotKnown:
		// The certificate verifier accepted the chain (to the locally trusted root) and the handshake still failed.
		// With no pins set, the only refusal ProofVerifierChromium makes after a good verification is
		// ERR_QUIC_CERT_ROOT_NOT_KNOWN.
		require.True(t, verified, "the chain did not verify, so the refusal is not the known-root check")
		require.False(t, verifyFailed)
	case quicLocalRootUntrusted:
		require.False(t, verified, "a chain to a root trusted nowhere verified")
	default:
		t.Fatalf("unknown expectation %q", expect)
	}
}

// netLogHasEvent reports whether the finished NetLog at path holds an event of the named type.
func netLogHasEvent(t *testing.T, path string, eventName string) bool {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var netLog netLogData
	require.NoError(t, json.Unmarshal(content, &netLog))
	eventType, ok := netLog.Constants.LogEventTypes[eventName]
	require.True(t, ok, "%s not in the NetLog constants", eventName)
	for _, event := range netLog.Events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

// quicLocalRootPaddingHeader is a Padding header as NaiveClient sends it, which makes the server pad its first frames
// as NaiveConn expects.
func quicLocalRootPaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}
