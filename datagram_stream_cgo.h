// The datagram stream API of libcronet for the cgo build.
//
// The headers in include/ and the libraries in lib/ are copied from one build of
// naiveproxy and published together. The package step that copies
// datagram_stream_c.h also defines CRONET_GO_HAS_DATAGRAM_STREAM in
// include_cgo.go, and the libraries of that build have the datagram_stream_*
// functions. Without the define, the declarations below stand in for them and
// report no datagram support, instead of an undefined symbol at link time. The
// define is keyed in a Go file, not on the presence of the header, because the
// Go build cache tracks the Go files of the package, not include/.
//
// The root module and the lib/<target> modules must come from the same
// publish: a root module with the define and a lib module built before the
// datagram streams fail to link (undefined datagram_stream_*).

#ifndef CRONET_GO_DATAGRAM_STREAM_CGO_H_
#define CRONET_GO_DATAGRAM_STREAM_CGO_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <bidirectional_stream_c.h>

#if defined(CRONET_GO_HAS_DATAGRAM_STREAM)

#include <datagram_stream_c.h>

#define CRONET_GO_DATAGRAM_STREAM_SUPPORTED 1

#else

#define CRONET_GO_DATAGRAM_STREAM_SUPPORTED 0

typedef struct datagram_stream {
  void* obj;
  void* annotation;
} datagram_stream;

typedef struct datagram_stream_callback {
  void (*on_ready)(datagram_stream* stream,
                   int status,
                   const bidirectional_stream_header_array* headers);
  void (*on_datagram_received)(datagram_stream* stream,
                               const char* data,
                               int length);
  void (*on_max_payload_changed)(datagram_stream* stream, int max_payload);
  void (*on_closed)(datagram_stream* stream);
  void (*on_failed)(datagram_stream* stream, int net_error);
  void (*on_canceled)(datagram_stream* stream);
} datagram_stream_callback;

#endif

#endif  // CRONET_GO_DATAGRAM_STREAM_CGO_H_
