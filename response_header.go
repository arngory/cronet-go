package cronet

import "net/http"

// responseHeaderListReceiver is implemented by a BidirectionalStreamCallback that wants every field of the response
// header, repeated names included: the map of OnResponseHeadersReceived keeps one value per name. It is called just
// before OnResponseHeadersReceived, on the same thread.
type responseHeaderListReceiver interface {
	onResponseHeaderList(header http.Header)
}

// responseHeaderList collects the fields of a response header, pseudo-headers (":status") left out, in the order
// received. The library splits the values that HTTP/2 and HTTP/3 carry together into one field each.
type responseHeaderList struct {
	header http.Header
}

func (l *responseHeaderList) add(name, value string) {
	if name == "" || name[0] == ':' {
		return
	}
	if l.header == nil {
		l.header = make(http.Header)
	}
	l.header.Add(name, value)
}
