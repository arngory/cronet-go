//go:build with_purego

package cronet

import (
	"runtime"
	"unsafe"

	"github.com/sagernet/cronet-go/internal/cronet"
)

func checkExactServerCertificatesSupport() error {
	supported, err := cronet.ExactServerCertificatesSupported()
	if err != nil {
		return err
	}
	if !supported {
		return ErrExactServerCertificatesUnsupported
	}
	return nil
}

// SetExactServerCertificates makes the engine trust exactly these server certificates, each the DER encoding of an
// X.509 certificate, in place of certificate verification: a server is accepted if and only if the leaf certificate
// it presents is, byte for byte, one of them.
//
// Nothing else is checked: not the host name or IP address, not the chain, the validity period, a root store,
// revocation or Certificate Transparency. The TLS handshake still proves that the server holds the private key of
// its certificate. Use it only with certificates you distribute yourself, such as the self-signed certificate of a
// server you reach by IP address: whoever holds the key of one of them is trusted for every host the engine
// connects to. List the current certificate and the next one to rotate without a gap.
//
// It applies to HTTP/2 over TLS and to HTTP/3 over QUIC alike. A server with another certificate fails with
// NetErrorCertAuthorityInvalid over TLS; over QUIC the handshake fails (NetErrorQUICHandshakeFailed or
// NetErrorQUICProtocolError).
//
// Each call replaces the list. An empty list, the default, keeps the default verification. StartWithParams fails,
// with ResultIllegalArgument, if an entry is not a certificate that Chromium parses or public key pins are set too
// (an exact certificate fixes the key already, and pins are kept for host names only), and, with
// ResultIllegalState, if the engine has roots of Engine.SetTrustedRootCertificates.
//
// It returns ErrExactServerCertificatesUnsupported for a library built before exact server certificates, unless the
// list is empty, or the error of loading the library.
func (p EngineParams) SetExactServerCertificates(certificates [][]byte) error {
	supported, err := cronet.ExactServerCertificatesSupported()
	if err != nil {
		return err
	}
	if !supported {
		if len(certificates) == 0 {
			return nil
		}
		return ErrExactServerCertificatesUnsupported
	}
	cronet.EngineParamsExactServerCertificatesClear(p.ptr)
	for _, certificate := range certificates {
		var der unsafe.Pointer
		if len(certificate) > 0 {
			der = unsafe.Pointer(&certificate[0])
		}
		// the library takes a copy
		cronet.EngineParamsExactServerCertificatesAdd(p.ptr, der, uintptr(len(certificate)))
		runtime.KeepAlive(certificate)
	}
	return nil
}

// ExactServerCertificates returns copies of the certificates of SetExactServerCertificates, or nil if there are none.
func (p EngineParams) ExactServerCertificates() [][]byte {
	if supported, err := cronet.ExactServerCertificatesSupported(); err != nil || !supported {
		return nil
	}
	count := cronet.EngineParamsExactServerCertificatesSize(p.ptr)
	if count == 0 {
		return nil
	}
	certificates := make([][]byte, 0, count)
	for index := uint32(0); index < count; index++ {
		var length uintptr
		der := cronet.EngineParamsExactServerCertificatesAt(p.ptr, index, &length)
		certificate := make([]byte, length)
		if length > 0 {
			copy(certificate, unsafe.Slice((*byte)(unsafe.Pointer(der)), length))
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}
