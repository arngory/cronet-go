//go:build !with_purego

package cronet

/*
#include "datagram_stream_cgo.h"

#if !CRONET_GO_DATAGRAM_STREAM_SUPPORTED
// A library without datagram streams: CreateDatagramStream stops before these.
static datagram_stream* datagram_stream_create(
    stream_engine* engine,
    void* annotation,
    const datagram_stream_callback* callback) {
  return NULL;
}
static int datagram_stream_start(
    datagram_stream* stream,
    const char* url,
    const bidirectional_stream_header_array* headers) {
  return -1;
}
static int datagram_stream_send(datagram_stream* stream,
                                const char* data,
                                int length,
                                int flags) {
  return -3;
}
static int datagram_stream_max_payload(datagram_stream* stream) {
  return 0;
}
static uint64_t datagram_stream_dropped_capsules(datagram_stream* stream) {
  return 0;
}
static void datagram_stream_cancel(datagram_stream* stream) {}
static int datagram_stream_destroy(datagram_stream* stream) {
  return -1;
}
#endif
*/
import "C"

import (
	"math"
	"unsafe"
)

func checkDatagramSupport() error {
	if C.CRONET_GO_DATAGRAM_STREAM_SUPPORTED == 0 {
		return ErrDatagramUnsupported
	}
	return nil
}

func (s DatagramStream) c() *C.datagram_stream {
	return (*C.datagram_stream)(unsafe.Pointer(s.ptr))
}

// CreateDatagramStream creates a connect-udp request on the engine. It returns a stream whose Start fails if the
// library has no datagram support (see CheckDatagramSupport). The callback must not be nil.
func (e StreamEngine) CreateDatagramStream(callback DatagramStreamCallback) DatagramStream {
	if callback == nil {
		panic("nil datagram stream callback")
	}
	if checkDatagramSupport() != nil {
		return DatagramStream{}
	}
	ptr := C.datagram_stream_create((*C.stream_engine)(unsafe.Pointer(e.ptr)), nil, datagramStreamCallbackC)
	if ptr == nil {
		return DatagramStream{}
	}
	ptrVal := uintptr(unsafe.Pointer(ptr))
	registerDatagramStream(ptrVal, callback)
	return DatagramStream{ptrVal}
}

// Start sends the extended CONNECT request (the library sets :protocol connect-udp) to url with headers, as for
// the tunnel of naive: authorization, Padding, niko-udp. The library sets capsule-protocol if missing and forces
// QUIC. False means the stream did not start: an invalid URL or header, a Cancel before Start, a second Start, or a
// library without datagram support.
func (s DatagramStream) Start(url string, headers map[string]string) bool {
	if s.ptr == 0 {
		return false
	}
	var headerArray C.bidirectional_stream_header_array
	if headerLen := len(headers); headerLen > 0 {
		cHeadersPtr := C.malloc(C.size_t(int(C.sizeof_struct_bidirectional_stream_header) * headerLen))
		defer C.free(cHeadersPtr)
		cHeaders := unsafe.Slice((*C.bidirectional_stream_header)(cHeadersPtr), headerLen)
		var index int
		for key, value := range headers {
			cKey := C.CString(key)
			defer C.free(unsafe.Pointer(cKey))
			cValue := C.CString(value)
			defer C.free(unsafe.Pointer(cValue))
			cHeaders[index].key = cKey
			cHeaders[index].value = cValue
			index++
		}
		headerArray = C.bidirectional_stream_header_array{
			C.size_t(headerLen), C.size_t(headerLen), &cHeaders[0],
		}
	}
	cURL := C.CString(url)
	defer C.free(unsafe.Pointer(cURL))
	return C.datagram_stream_start(s.c(), cURL, &headerArray) == 0
}

// Send copies data and queues it for the network thread without blocking. With allowCapsule, a datagram that does
// not fit in a QUIC datagram goes in a capsule (naive-udp-v1 §4.4); without it, ErrDatagramTooLarge. Until OnReady
// with 200 nothing fits: every datagram needs a capsule.
func (s DatagramStream) Send(data []byte, allowCapsule bool) error {
	if s.ptr == 0 {
		return ErrDatagramUnsupported
	}
	if len(data) > math.MaxInt32 {
		return ErrDatagramTooLarge
	}
	var flags C.int
	if allowCapsule {
		flags = datagramStreamSendAllowCapsule
	}
	var dataPtr *C.char
	if len(data) > 0 {
		dataPtr = (*C.char)(unsafe.Pointer(&data[0]))
	}
	return datagramSendError(int(C.datagram_stream_send(s.c(), dataPtr, C.int(len(data)), flags)))
}

// MaxPayload is the payload that fits in one QUIC datagram, after the Quarter Stream ID and the Context ID. It is 0
// before OnReady: capsules only.
func (s DatagramStream) MaxPayload() int {
	if s.ptr == 0 {
		return 0
	}
	return int(C.datagram_stream_max_payload(s.c()))
}

// DroppedCapsules counts the datagrams the library dropped after Send took them: capsules that waited 100 ms for the
// stream, capsules over a full queue or behind a write side the node stopped reading, and datagrams that no longer
// fit in a QUIC datagram when capsules were not allowed. With purego on a 32-bit platform it wraps at 2^32.
func (s DatagramStream) DroppedCapsules() uint64 {
	if s.ptr == 0 {
		return 0
	}
	return uint64(C.datagram_stream_dropped_capsules(s.c()))
}

// Cancel cancels the stream. Once Start has returned true, OnCanceled follows, also when the request was not sent
// yet, unless the stream has already ended. A Cancel before Start makes Start fail, with no callback.
func (s DatagramStream) Cancel() {
	if s.ptr == 0 {
		return
	}
	C.datagram_stream_cancel(s.c())
}

// Destroy destroys the stream, from any thread. The deletion is posted to the network thread; callbacks still made
// until then return without reaching the DatagramStreamCallback.
func (s DatagramStream) Destroy() bool {
	if s.ptr == 0 {
		return false
	}
	cleanupDatagramStream(s.ptr)
	return C.datagram_stream_destroy(s.c()) == 0
}
