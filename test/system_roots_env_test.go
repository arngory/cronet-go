package test

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

const (
	systemRootsChildEnv  = "CRONET_TEST_SYSTEM_ROOTS_CHILD"
	systemRootsExpectEnv = "CRONET_TEST_SYSTEM_ROOTS_EXPECT"
	systemRootsEchoEnv   = "CRONET_TEST_SYSTEM_ROOTS_ECHO_PORT"
	systemRootsEchoPort  = 18500
)

// TestSystemRootsFromEnvironment: without TrustedRootCertificates the default verifier trusts the Chrome Root Store
// and the roots that TrustStoreUnix reads, which come from SSL_CERT_FILE and SSL_CERT_DIR when they are set (on
// Android only from them). The library reads the variables when an engine creates its verifier, from the C
// environment, so each case runs in its own test process started with the variables it needs: that holds for the
// purego build too, where os.Setenv does not reach the C environment.
func TestSystemRootsFromEnvironment(t *testing.T) {
	if os.Getenv(systemRootsChildEnv) == "1" {
		runSystemRootsChild(t)
		return
	}

	env := setupTestEnv(t)
	startEchoServer(t, systemRootsEchoPort)

	directory := t.TempDir()
	serverRoot := filepath.Join(directory, "server-root.pem")
	require.NoError(t, os.WriteFile(serverRoot, env.caPEM, 0o644))

	emptyDirectory := filepath.Join(directory, "empty")
	require.NoError(t, os.Mkdir(emptyDirectory, 0o755))
	serverRootDirectory := filepath.Join(directory, "server")
	require.NoError(t, os.Mkdir(serverRootDirectory, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(serverRootDirectory, "root.pem"), env.caPEM, 0o644))
	otherRootDirectory := filepath.Join(directory, "other")
	require.NoError(t, os.Mkdir(otherRootDirectory, 0o755))
	otherRoot, _, _ := generateCertificate(t, "other.invalid")
	otherRootContent, err := os.ReadFile(otherRoot)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(otherRootDirectory, "root.pem"), otherRootContent, 0o644))

	cases := []struct {
		name   string
		env    []string
		accept bool
	}{
		{"no variables", nil, false},
		{"SSL_CERT_FILE names the root", []string{"SSL_CERT_FILE=" + serverRoot}, true},
		{"SSL_CERT_FILE set but empty", []string{"SSL_CERT_FILE="}, false},
		{"SSL_CERT_DIR list, the root in the second", []string{"SSL_CERT_DIR=" + emptyDirectory + ":" + serverRootDirectory}, true},
		{"SSL_CERT_DIR list, another root in the first", []string{"SSL_CERT_DIR=" + otherRootDirectory + ":" + serverRootDirectory}, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestSystemRootsFromEnvironment$", "-test.v", "-test.count=1")
			var childEnv []string
			for _, variable := range os.Environ() {
				if strings.HasPrefix(variable, "SSL_CERT_FILE=") || strings.HasPrefix(variable, "SSL_CERT_DIR=") {
					continue
				}
				childEnv = append(childEnv, variable)
			}
			expect := "refuse"
			if testCase.accept {
				expect = "accept"
			}
			childEnv = append(childEnv,
				systemRootsChildEnv+"=1",
				systemRootsExpectEnv+"="+expect,
				systemRootsEchoEnv+"="+strconv.Itoa(systemRootsEchoPort),
			)
			command.Env = append(childEnv, testCase.env...)
			output, err := command.CombinedOutput()
			t.Logf("child (%s):\n%s", strings.Join(testCase.env, " "), output)
			require.NoError(t, err, "the child test process failed")
		})
	}
}

// TestSystemRootsFileReadPerEngine: the file named by SSL_CERT_FILE is read when an engine is started, not once per
// process, which is how Android embedders switch between the Chrome Root Store only (an empty file) and the system
// roots (a PEM bundle) without touching the environment again: SSL_CERT_FILE is set once, before the first engine of
// this test, and only the file's content changes. A running engine keeps what it read at its start.
func TestSystemRootsFileReadPerEngine(t *testing.T) {
	env := setupTestEnv(t)
	const echoPort = systemRootsEchoPort + 1
	startEchoServer(t, echoPort)
	rootsFile := filepath.Join(t.TempDir(), "naive-roots.pem")
	require.NoError(t, os.WriteFile(rootsFile, nil, 0o644))
	t.Setenv("SSL_CERT_FILE", rootsFile)

	emptyFile := startDefaultVerifierClient(t)
	checkSystemRootsDial(t, emptyFile, echoPort, false)

	require.NoError(t, os.WriteFile(rootsFile, env.caPEM, 0o644))
	withRoot := startDefaultVerifierClient(t)
	checkSystemRootsDial(t, withRoot, echoPort, true)
	checkSystemRootsDial(t, emptyFile, echoPort, false)

	require.NoError(t, os.WriteFile(rootsFile, nil, 0o644))
	emptiedAgain := startDefaultVerifierClient(t)
	checkSystemRootsDial(t, emptiedAgain, echoPort, false)
	checkSystemRootsDial(t, withRoot, echoPort, true)

	require.NoError(t, os.Remove(rootsFile))
	missingFile := startDefaultVerifierClient(t)
	checkSystemRootsDial(t, missingFile, echoPort, false)
}

func runSystemRootsChild(t *testing.T) {
	port, err := strconv.Atoi(os.Getenv(systemRootsEchoEnv))
	require.NoError(t, err)
	client := startDefaultVerifierClient(t)
	checkSystemRootsDial(t, client, uint16(port), os.Getenv(systemRootsExpectEnv) == "accept")
}

// startDefaultVerifierClient starts a client without TrustedRootCertificates, so that its engine uses the default
// certificate verifier.
func startDefaultVerifierClient(t *testing.T) *cronet.NaiveClient {
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", naiveServerPort),
		ServerName:    "example.org",
		Username:      "test",
		Password:      "test",
		DNSResolver:   localhostDNSResolver(t),
	})
	require.NoError(t, err)
	require.NoError(t, client.Start())
	t.Cleanup(func() { client.Close() })
	return client
}

func checkSystemRootsDial(t *testing.T, client *cronet.NaiveClient, port uint16, accept bool) {
	conn, err := client.DialEarly(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", port))
	require.NoError(t, err)
	defer conn.Close()

	if !accept {
		require.Error(t, conn.Handshake(), "a server whose root the environment does not name was accepted")
		return
	}
	testData := []byte("root from the environment")
	_, err = conn.Write(testData)
	require.NoError(t, err)
	echo := make([]byte, len(testData))
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err)
	require.Equal(t, testData, echo)
}
