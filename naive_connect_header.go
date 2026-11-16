package cronet

import (
	"net/http"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// connectHeaderReserved are the request header fields, in lower case, that a stream's header may not set on a
// CONNECT of NaiveClient: those the client or naive sets itself (the credentials and the padding negotiation), and
// those that are not end to end or conflict with the pseudo-headers in HTTP/2 and HTTP/3 (RFC 9113 section 8.2.2,
// RFC 9114 section 4.2).
var connectHeaderReserved = map[string]bool{
	"proxy-authorization":  true,
	"padding":              true,
	"padding-type-request": true,
	"padding-type-reply":   true,
	"fastopen":             true,
	"host":                 true,
	"content-length":       true,
	"connection":           true,
	"keep-alive":           true,
	"proxy-connection":     true,
	"transfer-encoding":    true,
	"upgrade":              true,
	"te":                   true,
}

// connectRequestHeaders checks the header of DialEarlyWithHeaders and returns it as the library takes it: names in
// lower case, the values of a name joined with ", " (RFC 9110 section 5.3). Names without values are left out.
func connectRequestHeaders(header http.Header) (map[string]string, error) {
	if len(header) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(header))
	for name, values := range header {
		if strings.HasPrefix(name, ":") {
			return nil, E.New("connect header: pseudo-header ", name, " is not allowed")
		}
		if !validHeaderName(name) {
			return nil, E.New("connect header: invalid name ", quoteHeader(name))
		}
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "-") || connectHeaderReserved[lowerName] {
			return nil, E.New("connect header: ", name, " is set by the client")
		}
		if len(values) == 0 {
			continue
		}
		for _, value := range values {
			if !validHeaderValue(value) {
				return nil, E.New("connect header: invalid value of ", name, ": ", quoteHeader(value))
			}
		}
		if _, loaded := result[lowerName]; loaded {
			return nil, E.New("connect header: ", name, " is given twice, in different cases")
		}
		result[lowerName] = strings.Join(values, ", ")
	}
	return result, nil
}

// validHeaderName reports whether name is a token (RFC 9110 section 5.1).
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenByte(name[i]) {
			return false
		}
	}
	return true
}

func isTokenByte(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
}

// validHeaderValue reports whether value is a field value that HTTP/2 and HTTP/3 carry as it is (RFC 9110 section
// 5.5, RFC 9113 section 8.2.1): no control characters but horizontal tab, no DEL, and no white space at either end.
func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < ' ' && b != '\t') || b == 0x7f {
			return false
		}
	}
	if value != "" {
		first, last := value[0], value[len(value)-1]
		if first == ' ' || first == '\t' || last == ' ' || last == '\t' {
			return false
		}
	}
	return true
}

func quoteHeader(s string) string {
	const maxLength = 64
	if len(s) > maxLength {
		return strconv.Quote(s[:maxLength]) + "..."
	}
	return strconv.Quote(s)
}
