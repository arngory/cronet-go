//go:build with_purego && linux

package cronet

import (
	"testing"

	"github.com/ebitengine/purego"
)

// TestRegisterDatagramSymbolsWithoutThem loads a library without the datagram stream functions in place of
// libcronet: none of them is registered, and datagram streams are unsupported, while the rest of the loading is
// not stopped.
func TestRegisterDatagramSymbolsWithoutThem(t *testing.T) {
	handle, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Skipf("no libc.so.6: %v", err)
	}
	t.Cleanup(func() { _ = purego.Dlclose(handle) })

	savedHandle, savedSupported := libHandle, datagramStreamSupported
	t.Cleanup(func() { libHandle, datagramStreamSupported = savedHandle, savedSupported })
	libHandle = handle
	datagramStreamSupported = true

	registerDatagramSymbols()

	if datagramStreamSupported {
		t.Fatal("datagram streams supported by a library without them")
	}
	for name, registered := range map[string]bool{
		"datagram_stream_create":           datagramStreamCreate != nil,
		"datagram_stream_start":            datagramStreamStart != nil,
		"datagram_stream_send":             datagramStreamSend != nil,
		"datagram_stream_max_payload":      datagramStreamMaxPayload != nil,
		"datagram_stream_dropped_capsules": datagramStreamDroppedCapsules != nil,
		"datagram_stream_cancel":           datagramStreamCancel != nil,
		"datagram_stream_destroy":          datagramStreamDestroy != nil,
	} {
		if registered {
			t.Errorf("%s registered", name)
		}
	}
}
