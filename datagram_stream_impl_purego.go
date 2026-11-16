//go:build with_purego

package cronet

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

// datagramStreamCallbackStruct is datagram_stream_callback.
type datagramStreamCallbackStruct struct {
	onReady             uintptr
	onDatagramReceived  uintptr
	onMaxPayloadChanged uintptr
	onClosed            uintptr
	onFailed            uintptr
	onCanceled          uintptr
}

// datagramStreamCallbackPurego is a package variable, which does not move: the library keeps its address for the
// life of each stream.
var datagramStreamCallbackPurego datagramStreamCallbackStruct

func init() {
	datagramStreamCallbackPurego.onReady = purego.NewCallback(dsOnReadyCallback)
	datagramStreamCallbackPurego.onDatagramReceived = purego.NewCallback(dsOnDatagramReceivedCallback)
	datagramStreamCallbackPurego.onMaxPayloadChanged = purego.NewCallback(dsOnMaxPayloadChangedCallback)
	datagramStreamCallbackPurego.onClosed = purego.NewCallback(dsOnClosedCallback)
	datagramStreamCallbackPurego.onFailed = purego.NewCallback(dsOnFailedCallback)
	datagramStreamCallbackPurego.onCanceled = purego.NewCallback(dsOnCanceledCallback)
}

func dsOnReadyCallback(stream uintptr, status int32, headers uintptr) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	cb.OnReady(DatagramStream{stream}, int(status), parseHeaderArray(headers))
	return 0
}

func dsOnDatagramReceivedCallback(stream, data uintptr, length int32) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	var payload []byte
	if length > 0 {
		payload = unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	}
	cb.OnDatagram(DatagramStream{stream}, payload)
	return 0
}

func dsOnMaxPayloadChangedCallback(stream uintptr, maxPayload int32) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	cb.OnMaxPayloadChanged(DatagramStream{stream}, int(maxPayload))
	return 0
}

func dsOnClosedCallback(stream uintptr) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	cb.OnClosed(DatagramStream{stream})
	cleanupDatagramStream(stream)
	return 0
}

func dsOnFailedCallback(stream uintptr, netError int32) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	cb.OnFailed(DatagramStream{stream}, int(netError))
	cleanupDatagramStream(stream)
	return 0
}

func dsOnCanceledCallback(stream uintptr) uintptr {
	cb := instanceOfDatagramStreamCallback(stream)
	if cb == nil {
		return 0
	}
	cb.OnCanceled(DatagramStream{stream})
	cleanupDatagramStream(stream)
	return 0
}
