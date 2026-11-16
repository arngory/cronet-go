//go:build with_purego

package cronet

import (
	"math"
	"runtime"
	"unsafe"

	"github.com/sagernet/cronet-go/internal/cronet"
)

func checkDatagramSupport() error {
	supported, err := cronet.DatagramStreamSupported()
	if err != nil {
		return err
	}
	if !supported {
		return ErrDatagramUnsupported
	}
	return nil
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
	ptr := cronet.DatagramStreamCreate(e.ptr, 0, uintptr(unsafe.Pointer(&datagramStreamCallbackPurego)))
	if ptr == 0 {
		return DatagramStream{}
	}
	registerDatagramStream(ptr, callback)
	return DatagramStream{ptr}
}

// Start sends the extended CONNECT request (the library sets :protocol connect-udp) to url with headers, as for
// the tunnel of naive: authorization, Padding, niko-udp. The library sets capsule-protocol if missing and forces
// QUIC. False means the stream did not start: an invalid URL or header, a Cancel before Start, a second Start, or a
// library without datagram support.
func (s DatagramStream) Start(url string, headers map[string]string) bool {
	if s.ptr == 0 {
		return false
	}
	headerLen := len(headers)
	if headerLen == 0 {
		var headerArray bidirectionalStreamHeaderArray
		result := cronet.DatagramStreamStart(s.ptr, url, uintptr(unsafe.Pointer(&headerArray))) == 0
		runtime.KeepAlive(&headerArray)
		return result
	}
	cStringBacking := make([][]byte, 0, 2*headerLen)
	headerStructs := make([]bidirectionalStreamHeader, headerLen)
	var index int
	for key, value := range headers {
		keyPtr, keyBacking := cronet.CString(key)
		valuePtr, valueBacking := cronet.CString(value)
		cStringBacking = append(cStringBacking, keyBacking, valueBacking)
		headerStructs[index].key = keyPtr
		headerStructs[index].value = valuePtr
		index++
	}
	headerArray := bidirectionalStreamHeaderArray{
		count:    uintptr(headerLen),
		capacity: uintptr(headerLen),
		headers:  uintptr(unsafe.Pointer(&headerStructs[0])),
	}
	result := cronet.DatagramStreamStart(s.ptr, url, uintptr(unsafe.Pointer(&headerArray))) == 0
	runtime.KeepAlive(cStringBacking)
	runtime.KeepAlive(headerStructs)
	runtime.KeepAlive(&headerArray)
	return result
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
	var flags int32
	if allowCapsule {
		flags = datagramStreamSendAllowCapsule
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	result := cronet.DatagramStreamSend(s.ptr, dataPtr, int32(len(data)), flags)
	runtime.KeepAlive(data)
	return datagramSendError(int(result))
}

// MaxPayload is the payload that fits in one QUIC datagram, after the Quarter Stream ID and the Context ID. It is 0
// before OnReady: capsules only.
func (s DatagramStream) MaxPayload() int {
	if s.ptr == 0 {
		return 0
	}
	return int(cronet.DatagramStreamMaxPayload(s.ptr))
}

// DroppedCapsules counts the datagrams the library dropped after Send took them: capsules that waited 100 ms for the
// stream, capsules over a full queue or behind a write side the node stopped reading, and datagrams that no longer
// fit in a QUIC datagram when capsules were not allowed. With purego on a 32-bit platform it wraps at 2^32.
func (s DatagramStream) DroppedCapsules() uint64 {
	if s.ptr == 0 {
		return 0
	}
	return cronet.DatagramStreamDroppedCapsules(s.ptr)
}

// Cancel cancels the stream. Once Start has returned true, OnCanceled follows, also when the request was not sent
// yet, unless the stream has already ended. A Cancel before Start makes Start fail, with no callback.
func (s DatagramStream) Cancel() {
	if s.ptr == 0 {
		return
	}
	cronet.DatagramStreamCancel(s.ptr)
}

// Destroy destroys the stream, from any thread. The deletion is posted to the network thread; callbacks still made
// until then return without reaching the DatagramStreamCallback.
func (s DatagramStream) Destroy() bool {
	if s.ptr == 0 {
		return false
	}
	cleanupDatagramStream(s.ptr)
	return cronet.DatagramStreamDestroy(s.ptr) == 0
}
