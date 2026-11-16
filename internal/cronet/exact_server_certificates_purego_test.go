//go:build with_purego && linux

package cronet

import (
	"testing"

	"github.com/ebitengine/purego"
)

// TestRegisterExactServerCertificateSymbolsWithoutThem loads a library without the exact server certificate
// functions in place of libcronet: none of them is registered, and exact server certificates are unsupported, while
// the rest of the loading is not stopped.
func TestRegisterExactServerCertificateSymbolsWithoutThem(t *testing.T) {
	handle, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Skipf("no libc.so.6: %v", err)
	}
	t.Cleanup(func() { _ = purego.Dlclose(handle) })

	savedHandle, savedSupported := libHandle, exactServerCertificatesSupported
	t.Cleanup(func() { libHandle, exactServerCertificatesSupported = savedHandle, savedSupported })
	libHandle = handle
	exactServerCertificatesSupported = true

	registerExactServerCertificateSymbols()

	if exactServerCertificatesSupported {
		t.Fatal("exact server certificates supported by a library without them")
	}
	for name, registered := range map[string]bool{
		"Cronet_EngineParams_exact_server_certificates_add":   engineParamsExactServerCertificatesAdd != nil,
		"Cronet_EngineParams_exact_server_certificates_size":  engineParamsExactServerCertificatesSize != nil,
		"Cronet_EngineParams_exact_server_certificates_at":    engineParamsExactServerCertificatesAt != nil,
		"Cronet_EngineParams_exact_server_certificates_clear": engineParamsExactServerCertificatesClear != nil,
	} {
		if registered {
			t.Errorf("%s registered", name)
		}
	}
}
