//go:build with_purego

package cronet

// The datagram stream API (datagram_stream_c.h). Libraries built before it lack these symbols: they are looked up
// apart from the others, and their absence leaves datagram streams unsupported instead of failing LoadLibrary.
var (
	datagramStreamCreate          func(uintptr, uintptr, uintptr) uintptr
	datagramStreamStart           func(uintptr, string, uintptr) int32
	datagramStreamSend            func(uintptr, uintptr, int32, int32) int32
	datagramStreamMaxPayload      func(uintptr) int32
	datagramStreamDroppedCapsules func(uintptr) uint64
	datagramStreamCancel          func(uintptr)
	datagramStreamDestroy         func(uintptr) int32

	// datagramStreamSupported is written once, under the loadOnce of LoadLibrary.
	datagramStreamSupported bool
)

// registerDatagramSymbols registers all of the datagram stream functions, or none of them, and records which.
func registerDatagramSymbols() {
	datagramStreamSupported = false
	functions := []struct {
		pointer any
		name    string
	}{
		{&datagramStreamCreate, "datagram_stream_create"},
		{&datagramStreamStart, "datagram_stream_start"},
		{&datagramStreamSend, "datagram_stream_send"},
		{&datagramStreamMaxPayload, "datagram_stream_max_payload"},
		{&datagramStreamDroppedCapsules, "datagram_stream_dropped_capsules"},
		{&datagramStreamCancel, "datagram_stream_cancel"},
		{&datagramStreamDestroy, "datagram_stream_destroy"},
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
	datagramStreamSupported = true
}

// DatagramStreamSupported loads the library if it is not loaded yet, and reports whether it has datagram streams.
func DatagramStreamSupported() (bool, error) {
	if err := LoadLibrary(""); err != nil {
		return false, err
	}
	return datagramStreamSupported, nil
}

// DatagramStream API: callers check DatagramStreamSupported first.

func DatagramStreamCreate(engine, annotation, callback uintptr) uintptr {
	return datagramStreamCreate(engine, annotation, callback)
}

func DatagramStreamStart(stream uintptr, url string, headers uintptr) int32 {
	return datagramStreamStart(stream, url, headers)
}

func DatagramStreamSend(stream, data uintptr, length, flags int32) int32 {
	return datagramStreamSend(stream, data, length, flags)
}

func DatagramStreamMaxPayload(stream uintptr) int32 {
	return datagramStreamMaxPayload(stream)
}

func DatagramStreamDroppedCapsules(stream uintptr) uint64 {
	return datagramStreamDroppedCapsules(stream)
}

func DatagramStreamCancel(stream uintptr) {
	datagramStreamCancel(stream)
}

func DatagramStreamDestroy(stream uintptr) int32 {
	return datagramStreamDestroy(stream)
}
