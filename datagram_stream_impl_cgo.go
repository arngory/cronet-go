//go:build !with_purego

package cronet

/*
#include "datagram_stream_cgo.h"

extern void cronetDatagramStreamOnReady(
    datagram_stream* stream,
    int status,
    bidirectional_stream_header_array* headers);
extern void cronetDatagramStreamOnDatagramReceived(datagram_stream* stream,
                                                   char* data,
                                                   int length);
extern void cronetDatagramStreamOnMaxPayloadChanged(datagram_stream* stream,
                                                    int max_payload);
extern void cronetDatagramStreamOnClosed(datagram_stream* stream);
extern void cronetDatagramStreamOnFailed(datagram_stream* stream,
                                         int net_error);
extern void cronetDatagramStreamOnCanceled(datagram_stream* stream);
*/
import "C"

import (
	"unsafe"
)

// datagramStreamCallbackC is in C memory: the library keeps the pointer for the life of each stream.
var datagramStreamCallbackC *C.datagram_stream_callback

func init() {
	datagramStreamCallbackC = (*C.datagram_stream_callback)(C.calloc(1, C.sizeof_datagram_stream_callback))
	datagramStreamCallbackC.on_ready = (*[0]byte)(C.cronetDatagramStreamOnReady)
	datagramStreamCallbackC.on_datagram_received = (*[0]byte)(C.cronetDatagramStreamOnDatagramReceived)
	datagramStreamCallbackC.on_max_payload_changed = (*[0]byte)(C.cronetDatagramStreamOnMaxPayloadChanged)
	datagramStreamCallbackC.on_closed = (*[0]byte)(C.cronetDatagramStreamOnClosed)
	datagramStreamCallbackC.on_failed = (*[0]byte)(C.cronetDatagramStreamOnFailed)
	datagramStreamCallbackC.on_canceled = (*[0]byte)(C.cronetDatagramStreamOnCanceled)
}

func cDatagramStreamToGo(stream *C.datagram_stream) DatagramStream {
	return DatagramStream{uintptr(unsafe.Pointer(stream))}
}

func instanceOfDatagramStream(stream *C.datagram_stream) DatagramStreamCallback {
	return instanceOfDatagramStreamCallback(uintptr(unsafe.Pointer(stream)))
}

//export cronetDatagramStreamOnReady
func cronetDatagramStreamOnReady(stream *C.datagram_stream, status C.int, headers *C.bidirectional_stream_header_array) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	var headerMap map[string]string
	if headers != nil && headers.count > 0 {
		headerMap = make(map[string]string, int(headers.count))
		for _, header := range unsafe.Slice(headers.headers, int(headers.count)) {
			key := C.GoString(header.key)
			if len(key) == 0 {
				continue
			}
			headerMap[key] = C.GoString(header.value)
		}
	}
	callback.OnReady(cDatagramStreamToGo(stream), int(status), headerMap)
}

//export cronetDatagramStreamOnDatagramReceived
func cronetDatagramStreamOnDatagramReceived(stream *C.datagram_stream, data *C.char, length C.int) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	var payload []byte
	if length > 0 {
		payload = unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length))
	}
	callback.OnDatagram(cDatagramStreamToGo(stream), payload)
}

//export cronetDatagramStreamOnMaxPayloadChanged
func cronetDatagramStreamOnMaxPayloadChanged(stream *C.datagram_stream, maxPayload C.int) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	callback.OnMaxPayloadChanged(cDatagramStreamToGo(stream), int(maxPayload))
}

//export cronetDatagramStreamOnClosed
func cronetDatagramStreamOnClosed(stream *C.datagram_stream) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	callback.OnClosed(cDatagramStreamToGo(stream))
	cleanupDatagramStream(uintptr(unsafe.Pointer(stream)))
}

//export cronetDatagramStreamOnFailed
func cronetDatagramStreamOnFailed(stream *C.datagram_stream, netError C.int) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	callback.OnFailed(cDatagramStreamToGo(stream), int(netError))
	cleanupDatagramStream(uintptr(unsafe.Pointer(stream)))
}

//export cronetDatagramStreamOnCanceled
func cronetDatagramStreamOnCanceled(stream *C.datagram_stream) {
	callback := instanceOfDatagramStream(stream)
	if callback == nil {
		return
	}
	callback.OnCanceled(cDatagramStreamToGo(stream))
	cleanupDatagramStream(uintptr(unsafe.Pointer(stream)))
}
