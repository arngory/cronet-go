//go:build with_purego

package cronet

import "unsafe"

// The exact server certificates of EngineParams (cronet_c.h). Libraries built before them lack these symbols: they
// are looked up apart from the others, and their absence leaves exact server certificates unsupported instead of
// failing LoadLibrary.
var (
	engineParamsExactServerCertificatesAdd   func(uintptr, unsafe.Pointer, uintptr)
	engineParamsExactServerCertificatesSize  func(uintptr) uint32
	engineParamsExactServerCertificatesAt    func(uintptr, uint32, unsafe.Pointer) uintptr
	engineParamsExactServerCertificatesClear func(uintptr)

	// exactServerCertificatesSupported is written once, under the loadOnce of LoadLibrary.
	exactServerCertificatesSupported bool
)

// registerExactServerCertificateSymbols registers all of the exact server certificate functions, or none of them,
// and records which.
func registerExactServerCertificateSymbols() {
	exactServerCertificatesSupported = false
	functions := []struct {
		pointer any
		name    string
	}{
		{&engineParamsExactServerCertificatesAdd, "Cronet_EngineParams_exact_server_certificates_add"},
		{&engineParamsExactServerCertificatesSize, "Cronet_EngineParams_exact_server_certificates_size"},
		{&engineParamsExactServerCertificatesAt, "Cronet_EngineParams_exact_server_certificates_at"},
		{&engineParamsExactServerCertificatesClear, "Cronet_EngineParams_exact_server_certificates_clear"},
	}
	for _, function := range functions {
		if _, err := lookupSymbol(function.name); err != nil {
			return
		}
	}
	for _, function := range functions {
		if registerFunc(function.pointer, function.name) != nil {
			return
		}
	}
	exactServerCertificatesSupported = true
}

// ExactServerCertificatesSupported loads the library if it is not loaded yet, and reports whether it has exact
// server certificates.
func ExactServerCertificatesSupported() (bool, error) {
	if err := LoadLibrary(""); err != nil {
		return false, err
	}
	return exactServerCertificatesSupported, nil
}

// Exact server certificates: callers check ExactServerCertificatesSupported first. Go memory goes to C as a pointer,
// not as a uintptr, so that it is kept where it is for the call. A size_t is a uintptr on every platform.

func EngineParamsExactServerCertificatesAdd(params uintptr, der unsafe.Pointer, length uintptr) {
	engineParamsExactServerCertificatesAdd(params, der, length)
}

func EngineParamsExactServerCertificatesSize(params uintptr) uint32 {
	return engineParamsExactServerCertificatesSize(params)
}

// EngineParamsExactServerCertificatesAt returns the address of the DER at index, which belongs to params, and writes
// its length to *length.
func EngineParamsExactServerCertificatesAt(params uintptr, index uint32, length *uintptr) uintptr {
	return engineParamsExactServerCertificatesAt(params, index, unsafe.Pointer(length))
}

func EngineParamsExactServerCertificatesClear(params uintptr) {
	engineParamsExactServerCertificatesClear(params)
}
