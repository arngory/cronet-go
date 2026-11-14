package test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// testPublicSitesEnv turns on the tests that reach public sites: they need the network and say what those sites
// serve today, so a plain go test does not run them.
const testPublicSitesEnv = "CRONET_TEST_PUBLIC_SITES"

// publicDNSResolver answers from the resolver of the host, A records only (a runner often has no IPv6 route).
func publicDNSResolver(t *testing.T) cronet.DNSResolverFunc {
	server := "8.8.8.8:53"
	config, err := mDNS.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		server = net.JoinHostPort(config.Servers[0], config.Port)
	}
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		empty := new(mDNS.Msg)
		empty.SetReply(request)
		if len(request.Question) != 1 || request.Question[0].Qtype != mDNS.TypeA {
			return empty
		}
		response, err := mDNS.ExchangeContext(ctx, request, server)
		if err != nil {
			empty.Rcode = mDNS.RcodeServerFailure
			return empty
		}
		return response
	}
}

var netLogKeyHashRegex = regexp.MustCompile(`sha256/[A-Za-z0-9+/]{43}=`)

// TestPublicSiteChainEndsAtTrustedIntermediate: what a set of key pins has to hold to mean "the certificate
// authorities of the Chrome Root Store". The verified chain, whose keys the pins are matched against, ends at the
// first certificate the store trusts as an anchor, and for some authorities that is an intermediate
// (ChromeRootStoreAnchor.Intermediate): the keys of the roots alone then refuse the site, the keys of all of
// ChromeRootStoreAnchors accept it. The sites are no naive servers, so past the certificate the tunnel fails with
// something else; only the pin error is looked at.
func TestPublicSiteChainEndsAtTrustedIntermediate(t *testing.T) {
	if os.Getenv(testPublicSitesEnv) == "" {
		t.Skip(testPublicSitesEnv, " is not set")
	}
	anchors := cronet.ChromeRootStoreAnchors()
	byCertificate := make(map[[sha256.Size]byte]cronet.ChromeRootStoreAnchor, len(anchors))
	names := make(map[string]string, len(anchors))
	var rootKeys, allKeys [][]byte
	for _, anchor := range anchors {
		byCertificate[anchor.CertificateSHA256] = anchor
		names["sha256/"+base64.StdEncoding.EncodeToString(anchor.PublicKeySHA256[:])] = anchor.Subject
		allKeys = append(allKeys, anchor.PublicKeySHA256[:])
		if !anchor.Intermediate {
			rootKeys = append(rootKeys, anchor.PublicKeySHA256[:])
		}
	}
	require.Greater(t, len(allKeys), len(rootKeys), "the store has no intermediate trusted as an anchor")
	resolver := publicDNSResolver(t)

	// pinned reports whether the tunnel to host was refused for its keys, and the keys of the chain Chromium
	// verified, read from its NetLog
	pinned := func(t *testing.T, host string, pins [][]byte, netLogName string) bool {
		client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
			ServerAddress:              M.ParseSocksaddrHostPort(host, 443),
			ServerName:                 host,
			Username:                   "test",
			Password:                   "test",
			DNSResolver:                resolver,
			CertificatePublicKeySHA256: pins,
		})
		require.NoError(t, err)
		require.NoError(t, client.Start())
		defer client.Close()
		netLogPath := filepath.Join(t.TempDir(), netLogName)
		logging := client.Engine().StartNetLogToFile(netLogPath, true)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := client.DialEarly(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 9))
		require.NoError(t, err)
		defer conn.Close()
		err = conn.HandshakeContext(ctx)
		require.Error(t, err, host, " opened a tunnel")
		if logging {
			client.Engine().StopNetLog()
			content, readErr := os.ReadFile(netLogPath)
			if readErr == nil {
				seen := make(map[string]bool)
				var chain []string
				for _, hash := range netLogKeyHashRegex.FindAllString(string(content), -1) {
					if seen[hash] {
						continue
					}
					seen[hash] = true
					if name, isAnchor := names[hash]; isAnchor {
						hash += " (" + name + ")"
					}
					chain = append(chain, hash)
				}
				t.Logf("chrome-root-store: %s: key hashes in the NetLog: %s", host, strings.Join(chain, ", "))
			}
		}
		var netError cronet.NetError
		for _, code := range []cronet.NetError{
			cronet.NetErrorNameNotResolved, cronet.NetErrorInternetDisconnected, cronet.NetErrorAddressUnreachable,
			cronet.NetErrorConnectionTimedOut, cronet.NetErrorTimedOut,
		} {
			if errors.Is(err, code) {
				t.Skip(host, " is not reachable from here: ", err)
			}
		}
		if errors.As(err, &netError) {
			t.Logf("chrome-root-store: %s: %d pins: %s", host, len(pins), netError.Name())
		} else {
			t.Logf("chrome-root-store: %s: %d pins: %v", host, len(pins), err)
		}
		if errors.Is(err, cronet.NetErrorSSLPinnedKeyNotInCertChain) || strings.Contains(err.Error(), "pinned key") {
			return true
		}
		for _, code := range []cronet.NetError{
			cronet.NetErrorCertAuthorityInvalid, cronet.NetErrorCertCommonNameInvalid, cronet.NetErrorCertDateInvalid,
			cronet.NetErrorCertInvalid, cronet.NetErrorCertificateTransparencyRequired,
		} {
			require.NotErrorIs(t, err, code, host)
		}
		return false
	}

	ended := 0
	for _, host := range []string{"www.gstatic.com", "valid-isrgrootx1.letsencrypt.org", "www.digicert.com"} {
		t.Run(host, func(t *testing.T) {
			// the chain as the site sends it to a client that names no trust anchors: where Chromium's path ends
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: 15 * time.Second},
				Config:    &tls.Config{ServerName: host, NextProtos: []string{"h2"}},
			}
			raw, err := dialer.DialContext(context.Background(), "tcp4", net.JoinHostPort(host, "443"))
			if err != nil {
				t.Skip(host, " is not reachable from here: ", err)
			}
			presented := raw.(*tls.Conn).ConnectionState().PeerCertificates
			raw.Close()
			var end *cronet.ChromeRootStoreAnchor
			var subjects []string
			for _, certificate := range presented {
				subjects = append(subjects, certificate.Subject.String())
				if anchor, isAnchor := byCertificate[sha256.Sum256(certificate.Raw)]; isAnchor && end == nil {
					end = &anchor
				}
			}
			t.Logf("chrome-root-store: %s: sent chain: %s", host, strings.Join(subjects, " <- "))
			atIntermediate := end != nil && end.Intermediate
			if atIntermediate {
				ended++
				t.Logf("chrome-root-store: %s: the store trusts %q as an anchor (root ID %d): the root is not in the verified chain",
					host, end.Subject, end.RootID)
			}

			t.Run("the keys of the roots", func(t *testing.T) {
				require.Equal(t, atIntermediate, pinned(t, host, rootKeys, "roots.json"),
					"refused for its keys exactly when the chain ends at an intermediate the store trusts")
			})
			t.Run("the keys of every anchor", func(t *testing.T) {
				require.False(t, pinned(t, host, allKeys, "anchors.json"), "refused for its keys")
			})
		})
	}
	t.Logf("chrome-root-store: version %d, %d roots, %d intermediates trusted as anchors; %d of the sites end at one",
		cronet.ChromeRootStoreVersion, len(rootKeys), len(allKeys)-len(rootKeys), ended)
}
