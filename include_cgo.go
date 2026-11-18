//go:build !with_purego

package cronet

// #cgo CFLAGS: -I${SRCDIR}/include -DCRONET_GO_HAS_DATAGRAM_STREAM=1 -DCRONET_GO_HAS_EXACT_SERVER_CERTIFICATES=1
import "C"
