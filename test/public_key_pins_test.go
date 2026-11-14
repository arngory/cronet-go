package test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"testing"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// leafPublicKeyHash is the SHA-256 of the SubjectPublicKeyInfo of the first certificate in the PEM file at path:
// what NaiveClientOptions.CertificatePublicKeySHA256 pins.
func leafPublicKeyHash(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(content)
	require.NotNil(t, block, "no certificate in %s", path)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	hash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hash[:]
}

// TestNaivePublicKeyPins: with CertificatePublicKeySHA256 the tunnel opens only to a server whose chain holds one
// of the pinned keys, also when the chain ends in a root of TrustedRootCertificates, which Chromium lets past pins
// by default.
func TestNaivePublicKeyPins(t *testing.T) {
	env := setupTestEnv(t)
	startEchoServer(t, 18400)
	destination := M.ParseSocksaddrHostPort("127.0.0.1", 18400)
	serverKey := leafPublicKeyHash(t, env.certPath)
	anotherKey := sha256.Sum256([]byte("another key"))
	spareKey := sha256.Sum256([]byte("the next key"))

	t.Run("the server's key among the pins", func(t *testing.T) {
		client := env.newNaiveClient(t, cronet.NaiveClientOptions{
			CertificatePublicKeySHA256: [][]byte{spareKey[:], serverKey},
		})
		conn, err := client.DialEarly(context.Background(), destination)
		require.NoError(t, err)
		defer conn.Close()
		testData := []byte("pinned")
		_, err = conn.Write(testData)
		require.NoError(t, err)
		echo := make([]byte, len(testData))
		_, err = io.ReadFull(conn, echo)
		require.NoError(t, err)
		require.Equal(t, testData, echo)
	})

	t.Run("other keys only", func(t *testing.T) {
		client := env.newNaiveClient(t, cronet.NaiveClientOptions{
			CertificatePublicKeySHA256: [][]byte{anotherKey[:], spareKey[:]},
		})
		conn, err := client.DialEarly(context.Background(), destination)
		require.NoError(t, err)
		defer conn.Close()
		require.Error(t, conn.Handshake(), "a server with none of the pinned keys was accepted")
	})

	t.Run("an address has no pins", func(t *testing.T) {
		_, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
			ServerAddress:              M.ParseSocksaddrHostPort("127.0.0.1", naiveServerPort),
			ServerName:                 "127.0.0.1",
			DNSResolver:                localhostDNSResolver(t),
			CertificatePublicKeySHA256: [][]byte{serverKey},
		})
		require.Error(t, err)
	})

	t.Run("a pin is a SHA-256 hash", func(t *testing.T) {
		_, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
			ServerAddress:              M.ParseSocksaddrHostPort("127.0.0.1", naiveServerPort),
			ServerName:                 "example.org",
			DNSResolver:                localhostDNSResolver(t),
			CertificatePublicKeySHA256: [][]byte{serverKey[:16]},
		})
		require.Error(t, err)
	})
}
