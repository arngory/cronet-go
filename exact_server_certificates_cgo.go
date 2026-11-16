//go:build !with_purego

package cronet

/*
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <cronet_c.h>

// The exact server certificates of EngineParams, declared in cronet_c.h of the libraries that have them. The package
// step defines CRONET_GO_HAS_EXACT_SERVER_CERTIFICATES in include_cgo.go when the cronet_c.h it copies declares
// them, and the libraries of that build have the functions. Without the define the stand-ins below report no
// support, instead of an undefined symbol at link time. The define is keyed in a Go file, not on the header, because
// the Go build cache tracks the Go files of the package, not include/.
//
// The root module and the lib/<target> modules must come from the same publish: a root module with the define and a
// lib module built before exact server certificates fail to link (undefined Cronet_EngineParams_exact_server_*).
#if defined(CRONET_GO_HAS_EXACT_SERVER_CERTIFICATES)

#define CRONET_GO_EXACT_SERVER_CERTIFICATES_SUPPORTED 1

static void cronet_go_exact_server_certificates_add(Cronet_EngineParamsPtr self,
                                                    const uint8_t* der,
                                                    size_t der_len) {
  Cronet_EngineParams_exact_server_certificates_add(self, der, der_len);
}
static uint32_t cronet_go_exact_server_certificates_size(Cronet_EngineParamsPtr self) {
  return Cronet_EngineParams_exact_server_certificates_size(self);
}
static const uint8_t* cronet_go_exact_server_certificates_at(Cronet_EngineParamsPtr self,
                                                             uint32_t index,
                                                             size_t* der_len) {
  return Cronet_EngineParams_exact_server_certificates_at(self, index, der_len);
}
static void cronet_go_exact_server_certificates_clear(Cronet_EngineParamsPtr self) {
  Cronet_EngineParams_exact_server_certificates_clear(self);
}

#else

#define CRONET_GO_EXACT_SERVER_CERTIFICATES_SUPPORTED 0

// A library without exact server certificates: SetExactServerCertificates stops before these.
static void cronet_go_exact_server_certificates_add(Cronet_EngineParamsPtr self,
                                                    const uint8_t* der,
                                                    size_t der_len) {}
static uint32_t cronet_go_exact_server_certificates_size(Cronet_EngineParamsPtr self) {
  return 0;
}
static const uint8_t* cronet_go_exact_server_certificates_at(Cronet_EngineParamsPtr self,
                                                             uint32_t index,
                                                             size_t* der_len) {
  if (der_len) {
    *der_len = 0;
  }
  return NULL;
}
static void cronet_go_exact_server_certificates_clear(Cronet_EngineParamsPtr self) {}

#endif
*/
import "C"

import (
	"unsafe"
)

func checkExactServerCertificatesSupport() error {
	if C.CRONET_GO_EXACT_SERVER_CERTIFICATES_SUPPORTED == 0 {
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
// list is empty.
func (p EngineParams) SetExactServerCertificates(certificates [][]byte) error {
	if C.CRONET_GO_EXACT_SERVER_CERTIFICATES_SUPPORTED == 0 {
		if len(certificates) == 0 {
			return nil
		}
		return ErrExactServerCertificatesUnsupported
	}
	params := C.Cronet_EngineParamsPtr(unsafe.Pointer(p.ptr))
	C.cronet_go_exact_server_certificates_clear(params)
	for _, certificate := range certificates {
		var der *C.uint8_t
		if len(certificate) > 0 {
			der = (*C.uint8_t)(unsafe.Pointer(&certificate[0]))
		}
		// the library takes a copy
		C.cronet_go_exact_server_certificates_add(params, der, C.size_t(len(certificate)))
	}
	return nil
}

// ExactServerCertificates returns copies of the certificates of SetExactServerCertificates, or nil if there are none.
func (p EngineParams) ExactServerCertificates() [][]byte {
	params := C.Cronet_EngineParamsPtr(unsafe.Pointer(p.ptr))
	count := uint32(C.cronet_go_exact_server_certificates_size(params))
	if count == 0 {
		return nil
	}
	certificates := make([][]byte, 0, count)
	for index := uint32(0); index < count; index++ {
		var length C.size_t
		der := C.cronet_go_exact_server_certificates_at(params, C.uint32_t(index), &length)
		certificates = append(certificates, C.GoBytes(unsafe.Pointer(der), C.int(length)))
	}
	return certificates
}
