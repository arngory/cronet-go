package cronet

//go:generate go run ./cmd/build-naive generate-root-store

// ChromeRootStoreAnchor is a certificate that the Chrome Root Store built into the libraries trusts as an anchor
// for TLS. Most are roots. Some are intermediates Chromium trusts in their own right (additional_certs with
// tls_trust_anchor in root_store.textproto): a chain through one of them ends there for the verifier, and the root
// that issued it is not in the verified chain.
//
// That matters for key pins (NaiveClientOptions.CertificatePublicKeySHA256, PublicKeyPins): a pin is matched
// against the keys of the verified chain, from the server's certificate to the anchor. A set of pins made of
// root keys alone refuses every server whose certificate comes from such an intermediate, so a set that means
// "these certificate authorities" holds the keys of their roots and of the intermediates with the same RootID.
type ChromeRootStoreAnchor struct {
	// Subject is the certificate's subject, as crypto/x509/pkix prints it.
	Subject string
	// RootID is crs_root_id: unique among the roots, and for an intermediate the RootID of the root that issued it.
	RootID int
	// Intermediate is set for an intermediate trusted as an anchor.
	Intermediate bool
	// CertificateSHA256 is the SHA-256 of the DER certificate.
	CertificateSHA256 [32]byte
	// PublicKeySHA256 is the SHA-256 of the certificate's DER SubjectPublicKeyInfo: what a key pin is.
	PublicKeySHA256 [32]byte
}

// ChromeRootStoreAnchors returns the TLS trust anchors of the Chrome Root Store the libraries of this module
// version are built with: the roots first, then the intermediates trusted as anchors. The list is the one of the
// Chromium source the libraries are built from, and a library does not update it at run time. An engine with
// TrustedRootCertificates does not use it.
func ChromeRootStoreAnchors() []ChromeRootStoreAnchor {
	anchors := make([]ChromeRootStoreAnchor, len(chromeRootStoreAnchors))
	copy(anchors, chromeRootStoreAnchors[:])
	return anchors
}
