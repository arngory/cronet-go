package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// testCertificate is a self-signed certificate as a relay entry has one (relay-entry-v1 section 4.2): ECDSA P-256,
// the server's public IPv4 address in the SAN.
type testCertificate struct {
	der      []byte
	tls      tls.Certificate
	certPath string
	keyPath  string
}

// relayEntryAddress is the address in the SAN of the test certificates: not 127.0.0.1, where the servers listen,
// so that a connection that passes shows that the address is not checked.
var relayEntryAddress = net.IPv4(192, 0, 2, 1)

func generateSelfSignedCertificate(t *testing.T, commonName string, notBefore, notAfter time.Time) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          randomSerialNumber(t),
		Subject:               pkix.Name{CommonName: commonName},
		IPAddresses:           []net.IP{relayEntryAddress},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	directory := t.TempDir()
	certificate := testCertificate{
		der:      der,
		tls:      tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		certPath: filepath.Join(directory, "cert.pem"),
		keyPath:  filepath.Join(directory, "key.pem"),
	}
	require.NoError(t, os.WriteFile(certificate.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(certificate.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certificate
}

// loadTestCertificate reads the first certificate of the PEM file certPath and, if keyPath is not empty, its key.
func loadTestCertificate(certPath, keyPath string) (testCertificate, error) {
	certificate := testCertificate{certPath: certPath, keyPath: keyPath}
	content, err := os.ReadFile(certPath)
	if err != nil {
		return certificate, err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return certificate, os.ErrInvalid
	}
	certificate.der = block.Bytes
	if keyPath != "" {
		certificate.tls, err = tls.LoadX509KeyPair(certPath, keyPath)
	}
	return certificate, err
}

func validSelfSignedCertificate(t *testing.T, commonName string) testCertificate {
	return generateSelfSignedCertificate(t, commonName, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0))
}

// naiveTestServer is a minimal naive server, over HTTP/2 or HTTP/3 (quic-go), with the certificate it is given:
//   - GET answers 200 with the protocol of the request in Test-Proto;
//   - CONNECT records the request header and answers by the host of the destination: "refuse-<status>.test" with
//     that status and the fields of refusalHeader, and anything else with 200, Niko-Attest-Nonce and Padding, then
//     echoes the tunnel with naive's padding of the first frames.
type naiveTestServer struct {
	t    *testing.T
	quic bool
	port uint16

	access   sync.Mutex
	requests map[string]http.Header // by the destination of the CONNECT
}

const naiveTestNonce = "bm9uY2Ugb2YgdGhlIHRlc3Qgc2VydmVyLCAzMiBieXRlcw"

// refusalHeader holds the fields of a refusal, by status: one field repeated, to see that every value comes back.
func refusalHeader(status int) http.Header {
	header := http.Header{"Padding": {strings.Repeat("~", 30)}}
	switch status {
	case http.StatusForbidden:
		header.Set("Niko-Refused", "attest-required")
		header.Set("Niko-Lists-Version", "1042")
	case http.StatusTooManyRequests:
		header.Set("Retry-After", "30")
		header.Add("Niko-Note", "first")
		header.Add("Niko-Note", "second")
	case http.StatusServiceUnavailable:
		header.Set("Niko-Refused", "unavailable")
	}
	return header
}

func startNaiveTestServer(t *testing.T, quicServer bool, certificate testCertificate) *naiveTestServer {
	t.Helper()
	s := &naiveTestServer{t: t, quic: quicServer, requests: make(map[string]http.Header)}
	if !quicServer {
		server := httptest.NewUnstartedServer(s)
		server.EnableHTTP2 = true
		server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate.tls}}
		server.StartTLS()
		t.Cleanup(server.Close)
		s.port = uint16(server.Listener.Addr().(*net.TCPAddr).Port)
		return s
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	s.port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	server := &http3.Server{
		Handler:    s,
		TLSConfig:  http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{certificate.tls}}),
		QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(udpConn)
	}()
	t.Cleanup(func() {
		server.Close()
		udpConn.Close()
		<-served
	})
	return s
}

func (s *naiveTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Test-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		return
	}
	s.access.Lock()
	s.requests[r.Host] = r.Header.Clone()
	s.access.Unlock()

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if status, found := strings.CutPrefix(strings.TrimSuffix(host, ".test"), "refuse-"); found {
		code, err := strconv.Atoi(status)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for name, values := range refusalHeader(code) {
			w.Header()[name] = values
		}
		w.WriteHeader(code)
		return
	}

	w.Header().Set("Niko-Attest-Nonce", naiveTestNonce)
	w.Header().Set("Padding", strings.Repeat("~", 30))
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)
	flusher.Flush()
	_ = naiveEcho(r.Body, w, flusher)
}

// requestHeader returns the header of the CONNECT to destination, nil if there was none.
func (s *naiveTestServer) requestHeader(destination string) http.Header {
	s.access.Lock()
	defer s.access.Unlock()
	return s.requests[destination]
}

// naivePaddedFrames is how many frames naive pads in each direction.
const naivePaddedFrames = 8

// naiveEcho writes back what it reads, both with naive's padding of the first frames: a frame is the length of the
// payload (2 bytes, big endian), the length of the padding (1 byte), the payload and the padding.
func naiveEcho(reader io.Reader, writer io.Writer, flusher http.Flusher) error {
	buffer := make([]byte, 65535)
	for frame := 0; ; frame++ {
		var payload []byte
		if frame < naivePaddedFrames {
			var header [3]byte
			if _, err := io.ReadFull(reader, header[:]); err != nil {
				return err
			}
			payload = buffer[:binary.BigEndian.Uint16(header[:2])]
			if _, err := io.ReadFull(reader, payload); err != nil {
				return err
			}
			if _, err := io.CopyN(io.Discard, reader, int64(header[2])); err != nil {
				return err
			}
		} else {
			n, err := reader.Read(buffer)
			if n == 0 && err != nil {
				return err
			}
			payload = buffer[:n]
		}
		if frame < naivePaddedFrames {
			const paddingLength = 16
			framed := make([]byte, 3+len(payload)+paddingLength)
			binary.BigEndian.PutUint16(framed, uint16(len(payload)))
			framed[2] = paddingLength
			copy(framed[3:], payload)
			payload = framed
		}
		if _, err := writer.Write(payload); err != nil {
			return err
		}
		flusher.Flush()
	}
}
