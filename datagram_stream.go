package cronet

import (
	"errors"
	"strconv"
	"sync"
)

// DatagramStream is a connect-udp request (RFC 9298) on an engine whose sessions are QUIC: one UDP socket of the
// application. Its datagrams are HTTP Datagrams (RFC 9297) with Context ID 2, which the library adds when sending and
// strips when receiving; what does not fit in a QUIC datagram goes in a DATAGRAM capsule on the request stream.
//
// The methods of a destroyed stream must not be called: DatagramConn takes care of that.
type DatagramStream struct {
	ptr uintptr
}

// DatagramStreamCallback receives the events of a DatagramStream. Its methods are called on the network thread of
// the engine: they must not block, and data is valid only until the method returns. After OnClosed, OnFailed or
// OnCanceled no method is called.
type DatagramStreamCallback interface {
	// OnReady is called with the response of the node, whatever it is: 200, 429, 503 or the response of the site.
	// Sending does not wait for it: until then the library sends capsules. A status other than 200 is followed by
	// OnClosed.
	OnReady(stream DatagramStream, status int, headers map[string]string)
	// OnDatagram is called with one datagram: the payload after the Context ID, whether it came in a QUIC datagram
	// or in a capsule.
	OnDatagram(stream DatagramStream, data []byte)
	// OnMaxPayloadChanged is called when the payload that fits in one QUIC datagram changes.
	OnMaxPayloadChanged(stream DatagramStream, maxPayload int)
	// OnClosed is called at a clean end: the node closed the stream (idle), or answered other than 200. The next
	// packet of the application opens a new request.
	OnClosed(stream DatagramStream)
	// OnFailed is called when the stream is reset or the connection is lost. NetErrorMethodNotSupported means the
	// node announced no HTTP/3 datagrams (SETTINGS_H3_DATAGRAM) or no extended CONNECT: the request was not sent.
	OnFailed(stream DatagramStream, netError int)
	// OnCanceled is called after Cancel.
	OnCanceled(stream DatagramStream)
}

// The results of DatagramStream.Send other than success. ErrDatagramQueueFull, ErrDatagramTooLarge and
// ErrDatagramClosed concern the datagram passed to the call; ErrDatagramCapsuleTimeout is returned for a datagram
// that needs a capsule while the oldest capsule waiting for the stream has waited longer than 100 ms.
var (
	ErrDatagramQueueFull      = errors.New("cronet: datagram queue full")
	ErrDatagramTooLarge       = errors.New("cronet: datagram too large")
	ErrDatagramClosed         = errors.New("cronet: datagram stream closed")
	ErrDatagramCapsuleTimeout = errors.New("cronet: datagram capsule timeout")
)

// ErrDatagramUnsupported is returned when the loaded library has no datagram streams: a library built before them.
var ErrDatagramUnsupported = errors.New("cronet: library has no datagram support")

// The result codes of datagram_stream_send (datagram_stream_c.h).
const (
	datagramStreamOK             = 0
	datagramStreamQueueFull      = -1
	datagramStreamTooLarge       = -2
	datagramStreamClosed         = -3
	datagramStreamCapsuleTimeout = -4

	// datagramStreamSendAllowCapsule is the flag of datagram_stream_send that lets a datagram which does not fit in a
	// QUIC datagram go in a capsule.
	datagramStreamSendAllowCapsule = 1
)

func datagramSendError(result int) error {
	switch result {
	case datagramStreamOK:
		return nil
	case datagramStreamQueueFull:
		return ErrDatagramQueueFull
	case datagramStreamTooLarge:
		return ErrDatagramTooLarge
	case datagramStreamClosed:
		return ErrDatagramClosed
	case datagramStreamCapsuleTimeout:
		return ErrDatagramCapsuleTimeout
	default:
		return errors.New("cronet: datagram send failed: " + strconv.Itoa(result))
	}
}

// CheckDatagramSupport returns nil if the library has datagram streams, ErrDatagramUnsupported if it was built
// without them, or the error of loading it (purego).
func CheckDatagramSupport() error {
	return checkDatagramSupport()
}

// The callbacks of the streams, by the address of the C object. An entry goes at the end of the stream, or when it
// is destroyed: the library may still call back until its posted deletion runs, and those calls return silently. The
// address is not reused before that deletion, which follows the last callback.
var (
	datagramStreamAccess sync.RWMutex
	datagramStreamMap    = make(map[uintptr]DatagramStreamCallback)
)

func registerDatagramStream(ptr uintptr, callback DatagramStreamCallback) {
	datagramStreamAccess.Lock()
	datagramStreamMap[ptr] = callback
	datagramStreamAccess.Unlock()
}

func instanceOfDatagramStreamCallback(ptr uintptr) DatagramStreamCallback {
	datagramStreamAccess.RLock()
	defer datagramStreamAccess.RUnlock()
	return datagramStreamMap[ptr]
}

func cleanupDatagramStream(ptr uintptr) {
	datagramStreamAccess.Lock()
	delete(datagramStreamMap, ptr)
	datagramStreamAccess.Unlock()
}
