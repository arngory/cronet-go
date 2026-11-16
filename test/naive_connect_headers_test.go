package test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// TestNaiveConnectHeaders: a stream's header goes on its CONNECT, over HTTP/2 and HTTP/3, next to the fields the
// client sets itself, and the answer comes back: its header fields after a 200, a *ConnectError with the status and
// the fields otherwise.
func TestNaiveConnectHeaders(t *testing.T) {
	require.NoError(t, cronet.CheckExactServerCertificatesSupport())
	certificate := validSelfSignedCertificate(t, "relay entry")
	streamHeader := http.Header{
		"Niko-App-Set":       {"inside-only"},
		"niko-lists-version": {"1042"},
		"Niko-Ack":           {"1"},
	}

	for _, transport := range naiveTestTransports {
		t.Run(transport.name, func(t *testing.T) {
			server := startNaiveTestServer(t, transport.quic, certificate)
			// Niko-Lists-Version of ExtraHeaders is replaced by the stream's, whatever its case
			client := startRelayStyleClient(t, server, [][]byte{certificate.der}, map[string]string{
				"Niko-Lists-Version": "1",
				"X-Client":           "every stream",
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			t.Run("the header arrives, and the answer's", func(t *testing.T) {
				destination := M.ParseSocksaddrHostPort("attest.niko.arpa", 0)
				conn, err := client.DialContextWithHeaders(ctx, "tcp", destination, streamHeader)
				require.NoError(t, err)
				defer conn.Close()
				require.Equal(t, naiveTestNonce, conn.ResponseHeader().Get("Niko-Attest-Nonce"))
				requireEcho(t, conn, "attestation frame")

				received := server.requestHeader("attest.niko.arpa:0")
				require.NotNil(t, received, "no CONNECT to attest.niko.arpa:0")
				require.Equal(t, []string{"inside-only"}, received.Values("Niko-App-Set"))
				require.Equal(t, []string{"1042"}, received.Values("Niko-Lists-Version"))
				require.Equal(t, []string{"1"}, received.Values("Niko-Ack"))
				require.Equal(t, []string{"every stream"}, received.Values("X-Client"))
				require.Equal(t, []string{"Basic dGVzdDp0ZXN0"}, received.Values("Proxy-Authorization"))
				require.NotEmpty(t, received.Get("Padding"))
			})

			for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
				t.Run(strconv.Itoa(status), func(t *testing.T) {
					destination := M.ParseSocksaddrHostPort("refuse-"+strconv.Itoa(status)+".test", 443)
					conn, err := client.DialContextWithHeaders(ctx, "tcp", destination, streamHeader)
					require.Nil(t, conn)
					requireConnectError(t, err, status)
					require.Equal(t, []string{"inside-only"}, server.requestHeader(destination.String()).Values("Niko-App-Set"))
				})
			}

			t.Run("early", func(t *testing.T) {
				conn, err := client.DialEarlyWithHeaders(ctx, M.ParseSocksaddrHostPort("allow-early.test", 443), streamHeader)
				require.NoError(t, err)
				require.Nil(t, conn.ResponseHeader(), "a response header before the handshake")
				requireEcho(t, conn, "written before the answer")
				require.NoError(t, conn.HandshakeContext(ctx))
				require.Equal(t, naiveTestNonce, conn.ResponseHeader().Get("Niko-Attest-Nonce"))
				conn.Close()

				conn, err = client.DialEarlyWithHeaders(ctx, M.ParseSocksaddrHostPort("refuse-403.test", 443), streamHeader)
				require.NoError(t, err)
				requireConnectError(t, conn.HandshakeContext(ctx), http.StatusForbidden)
				require.Nil(t, conn.ResponseHeader())
				conn.Close()
			})

			t.Run("untagged", func(t *testing.T) {
				conn, err := client.DialEarly(ctx, M.ParseSocksaddrHostPort("refuse-429.test", 443))
				require.NoError(t, err)
				requireConnectError(t, conn.HandshakeContext(ctx), http.StatusTooManyRequests)
				conn.Close()
				require.Empty(t, server.requestHeader("refuse-429.test:443").Values("Niko-App-Set"))
			})

			t.Run("fields the client sets", func(t *testing.T) {
				for _, header := range []http.Header{
					{"Proxy-Authorization": {"Basic eDp4"}},
					{"padding": {"~"}},
					{"-Force-Quic": {"false"}},
					{":authority": {"other.test:443"}},
					{"Niko-App-Set": {"a\r\nX-Injected: 1"}},
				} {
					conn, err := client.DialEarlyWithHeaders(ctx, M.ParseSocksaddrHostPort("refused-locally.test", 443), header)
					require.Error(t, err, "%v", header)
					require.Nil(t, conn)
				}
				require.Nil(t, server.requestHeader("refused-locally.test:443"), "a refused header reached the server")
			})
		})
	}
}

// requireConnectError: err is a *ConnectError with status, and the header fields of refusalHeader, every value.
func requireConnectError(t *testing.T, err error, status int) {
	t.Helper()
	var connectError *cronet.ConnectError
	require.True(t, errors.As(err, &connectError), "not a *ConnectError: %v", err)
	require.Equal(t, status, connectError.Status)
	for name, values := range refusalHeader(status) {
		require.Equal(t, values, connectError.Header.Values(name), name)
	}
}
