package test

import (
	"encoding/json"
	"testing"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// allow_unknown_cert_roots in the "QUIC" dictionary beside what is there: set after SetQUICOptions it stays with
// the options of that call, cleared it leaves them, and SetQUICOptions after it writes the dictionary anew (which
// is why NaiveClient sets it last).
func TestQUICAllowUnknownCertRootsOption(t *testing.T) {
	quic := func(params cronet.EngineParams) map[string]any {
		t.Helper()
		var options map[string]any
		require.NoError(t, json.Unmarshal([]byte(params.ExperimentalOptions()), &options))
		dictionary, _ := options["QUIC"].(map[string]any)
		return dictionary
	}
	params := cronet.NewEngineParams()
	defer params.Destroy()

	// alone: the dictionary is made for it
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(true))
	require.Equal(t, map[string]any{"allow_unknown_cert_roots": true}, quic(params))
	// cleared: nothing of the dictionary is left
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(false))
	require.Nil(t, quic(params))

	// beside the options of SetQUICOptions
	require.NoError(t, params.SetQUICOptions("", "TBBR", 6*1024*1024, 15*1024*1024))
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(true))
	dictionary := quic(params)
	require.Equal(t, true, dictionary["allow_unknown_cert_roots"])
	require.Equal(t, "TBBR", dictionary["client_connection_options"])
	require.EqualValues(t, 6*1024*1024, dictionary["initial_stream_recv_window_size"])
	require.EqualValues(t, 15*1024*1024, dictionary["initial_session_recv_window_size"])
	// cleared: the others stay
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(false))
	dictionary = quic(params)
	require.NotContains(t, dictionary, "allow_unknown_cert_roots")
	require.Equal(t, "TBBR", dictionary["client_connection_options"])
	// and SetQUICOptions writes the dictionary anew
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(true))
	require.NoError(t, params.SetQUICOptions("", "", 6*1024*1024, 15*1024*1024))
	require.NotContains(t, quic(params), "allow_unknown_cert_roots")
	// another option of the engine is not touched
	require.NoError(t, params.SetAsyncDNS(true))
	require.NoError(t, params.SetQUICAllowUnknownCertRoots(true))
	var all map[string]any
	require.NoError(t, json.Unmarshal([]byte(params.ExperimentalOptions()), &all))
	require.Contains(t, all, "AsyncDNS")
}

// A NaiveClient over QUIC gives its engine the key only where its option says so, and with the rest of its QUIC
// options; over HTTP/2 the option does nothing. What the engine was given is the client's ExperimentalOptions.
func TestNaiveClientQUICAllowLocallyTrustedRoots(t *testing.T) {
	started := func(quicEnabled, allow bool) map[string]any {
		t.Helper()
		client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
			ServerAddress:                M.ParseSocksaddrHostPort("127.0.0.1", 443),
			ServerName:                   "example.org",
			Username:                     "test",
			Password:                     "test",
			DNSResolver:                  localhostDNSResolver(t),
			QUIC:                         quicEnabled,
			QUICAllowLocallyTrustedRoots: allow,
		})
		require.NoError(t, err)
		require.Empty(t, client.ExperimentalOptions(), "before Start")
		require.NoError(t, client.Start())
		defer client.Close()
		var options map[string]any
		require.NoError(t, json.Unmarshal([]byte(client.ExperimentalOptions()), &options))
		dictionary, _ := options["QUIC"].(map[string]any)
		return dictionary
	}

	with := started(true, true)
	require.Equal(t, true, with["allow_unknown_cert_roots"])
	require.Contains(t, with, "initial_stream_recv_window_size", "the option took the place of the other QUIC options")
	require.Contains(t, with, "initial_session_recv_window_size")

	without := started(true, false)
	require.NotContains(t, without, "allow_unknown_cert_roots")
	require.Contains(t, without, "initial_stream_recv_window_size")

	require.NotContains(t, started(false, true), "allow_unknown_cert_roots", "over HTTP/2")
}
