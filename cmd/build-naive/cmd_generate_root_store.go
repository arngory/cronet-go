package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"go/format"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var commandGenerateRootStore = &cobra.Command{
	Use:   "generate-root-store",
	Short: "Generate the list of TLS trust anchors of Chromium's Chrome Root Store",
	Run:   runGenerateRootStore,
}

var generateRootStoreCheck bool

func init() {
	commandGenerateRootStore.Flags().BoolVar(&generateRootStoreCheck, "check", false,
		"Write nothing: fail if chrome_root_store_generated.go is not what the naiveproxy checkout gives")
	mainCommand.AddCommand(commandGenerateRootStore)
}

// rootStoreAnchor is a certificate the Chrome Root Store trusts as an anchor for TLS: an entry of trust_anchors,
// or an entry of additional_certs with tls_trust_anchor (an intermediate trusted in its own right).
type rootStoreAnchor struct {
	subject      string
	certificate  [sha256.Size]byte
	publicKey    [sha256.Size]byte
	rootID       int
	intermediate bool
}

var (
	rootStoreVersionRegex = regexp.MustCompile(`(?m)^version_major:\s*(\d+)\s*$`)
	rootStoreEntryRegex   = regexp.MustCompile(`(?ms)^(trust_anchors|additional_certs)\s*\{\n(.*?)^\}`)
	rootStoreHashRegex    = regexp.MustCompile(`(?m)^\s*sha256_hex:\s*"([0-9a-f]{64})"`)
	rootStoreIDRegex      = regexp.MustCompile(`(?m)^\s*crs_root_id:\s*(\d+)`)
	rootStoreTLSRegex     = regexp.MustCompile(`(?m)^\s*tls_trust_anchor:\s*true`)
)

func runGenerateRootStore(cmd *cobra.Command, args []string) {
	sourceDirectory := filepath.Join(srcRoot, "net", "data", "ssl", "chrome_root_store")
	outputFile := filepath.Join(projectRoot, "chrome_root_store_generated.go")

	version, anchors, err := readRootStore(sourceDirectory)
	if err != nil {
		log.Fatalf("failed to read %s: %v", sourceDirectory, err)
	}
	content, err := formatRootStoreGoFile(version, anchors)
	if err != nil {
		log.Fatalf("failed to generate %s: %v", outputFile, err)
	}
	if generateRootStoreCheck {
		current, err := os.ReadFile(outputFile)
		if err != nil {
			log.Fatalf("failed to read %s: %v", outputFile, err)
		}
		if !bytes.Equal(current, content) {
			log.Fatalf("%s is not what %s gives: run go run ./cmd/build-naive generate-root-store", outputFile, sourceDirectory)
		}
		log.Printf("%s is up to date: root store version %d, %d anchors", outputFile, version, len(anchors))
		return
	}
	err = os.WriteFile(outputFile, content, 0o644)
	if err != nil {
		log.Fatalf("failed to write %s: %v", outputFile, err)
	}
	log.Printf("generated %s: root store version %d, %d anchors", outputFile, version, len(anchors))
}

// readRootStore reads root_store.textproto and the two certificate files beside it, as Chromium's
// root_store_tool does for the list it compiles in: every trust_anchors entry, and the additional_certs
// entries with tls_trust_anchor. The other additional_certs (EUTL certificates for QWACs) are no TLS anchors.
func readRootStore(directory string) (int, []rootStoreAnchor, error) {
	description, err := os.ReadFile(filepath.Join(directory, "root_store.textproto"))
	if err != nil {
		return 0, nil, err
	}
	certificates := make(map[[sha256.Size]byte][]byte)
	for _, name := range []string{"root_store.certs", "additional.certs"} {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return 0, nil, err
		}
		for {
			var block *pem.Block
			block, content = pem.Decode(content)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certificates[sha256.Sum256(block.Bytes)] = block.Bytes
			}
		}
	}

	versionMatch := rootStoreVersionRegex.FindSubmatch(description)
	if versionMatch == nil {
		return 0, nil, fmt.Errorf("no version_major")
	}
	version, err := strconv.Atoi(string(versionMatch[1]))
	if err != nil {
		return 0, nil, err
	}

	var anchors []rootStoreAnchor
	roots := make(map[int]bool)
	for _, entry := range rootStoreEntryRegex.FindAllSubmatch(description, -1) {
		kind, body := string(entry[1]), entry[2]
		intermediate := kind == "additional_certs"
		if intermediate && !rootStoreTLSRegex.Match(body) {
			continue
		}
		hashMatch := rootStoreHashRegex.FindSubmatch(body)
		if hashMatch == nil {
			return 0, nil, fmt.Errorf("a %s entry without sha256_hex", kind)
		}
		anchor := rootStoreAnchor{intermediate: intermediate}
		_, err = hex.Decode(anchor.certificate[:], hashMatch[1])
		if err != nil {
			return 0, nil, err
		}
		idMatch := rootStoreIDRegex.FindSubmatch(body)
		if idMatch == nil {
			return 0, nil, fmt.Errorf("%s: no crs_root_id", hashMatch[1])
		}
		anchor.rootID, err = strconv.Atoi(string(idMatch[1]))
		if err != nil {
			return 0, nil, err
		}
		der, found := certificates[anchor.certificate]
		if !found {
			return 0, nil, fmt.Errorf("%s: no such certificate in root_store.certs or additional.certs", hashMatch[1])
		}
		anchor.subject, anchor.publicKey, err = certificateSubjectAndKey(der)
		if err != nil {
			return 0, nil, fmt.Errorf("%s: %w", hashMatch[1], err)
		}
		if !intermediate {
			// what a user of the list relies on to tell whose an intermediate is
			if roots[anchor.rootID] {
				return 0, nil, fmt.Errorf("crs_root_id %d names two roots", anchor.rootID)
			}
			roots[anchor.rootID] = true
		}
		anchors = append(anchors, anchor)
	}
	for _, anchor := range anchors {
		if anchor.intermediate && !roots[anchor.rootID] {
			return 0, nil, fmt.Errorf("%s: crs_root_id %d of an intermediate names no root", anchor.subject, anchor.rootID)
		}
	}
	if len(roots) == 0 {
		return 0, nil, fmt.Errorf("no trust_anchors")
	}
	return version, anchors, nil
}

// certificateSubjectAndKey gives the subject of a certificate and the SHA-256 of its SubjectPublicKeyInfo. It
// reads the fields itself: crypto/x509 refuses some old roots (a negative serial number).
func certificateSubjectAndKey(der []byte) (string, [sha256.Size]byte, error) {
	var certificate struct {
		TBS struct {
			Version      int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber *big.Int
			Signature    asn1.RawValue
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
			PublicKey    asn1.RawValue
			Rest         []asn1.RawValue `asn1:"optional"`
		}
		SignatureAlgorithm asn1.RawValue
		Signature          asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &certificate)
	if err != nil {
		return "", [sha256.Size]byte{}, err
	}
	if len(rest) > 0 {
		return "", [sha256.Size]byte{}, fmt.Errorf("data after the certificate")
	}
	var subject pkix.RDNSequence
	_, err = asn1.Unmarshal(certificate.TBS.Subject.FullBytes, &subject)
	if err != nil {
		return "", [sha256.Size]byte{}, err
	}
	return subject.String(), sha256.Sum256(certificate.TBS.PublicKey.FullBytes), nil
}

func formatRootStoreGoFile(version int, anchors []rootStoreAnchor) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(`// Code generated by cmd/build-naive generate-root-store. DO NOT EDIT.
// Source: naiveproxy/src/net/data/ssl/chrome_root_store (root_store.textproto, root_store.certs, additional.certs)

package cronet

// ChromeRootStoreVersion is the version of the Chrome Root Store the libraries of this module version are built
// with (version_major of root_store.textproto).
`)
	fmt.Fprintf(&buffer, "const ChromeRootStoreVersion = %d\n\n", version)
	buffer.WriteString("var chromeRootStoreAnchors = [...]ChromeRootStoreAnchor{\n")
	for _, anchor := range anchors {
		fmt.Fprintf(&buffer, "\t{\n\t\tSubject: %s,\n\t\tRootID: %d,\n", strconv.Quote(anchor.subject), anchor.rootID)
		if anchor.intermediate {
			buffer.WriteString("\t\tIntermediate: true,\n")
		}
		fmt.Fprintf(&buffer, "\t\tCertificateSHA256: [32]byte{%s},\n", goBytes(anchor.certificate[:]))
		fmt.Fprintf(&buffer, "\t\tPublicKeySHA256: [32]byte{%s},\n\t},\n", goBytes(anchor.publicKey[:]))
	}
	buffer.WriteString("}\n")
	return format.Source(buffer.Bytes())
}

func goBytes(content []byte) string {
	parts := make([]string, len(content))
	for i, b := range content {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return strings.Join(parts, ", ")
}
