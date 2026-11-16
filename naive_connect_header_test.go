package cronet

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestConnectRequestHeaders(t *testing.T) {
	got, err := connectRequestHeaders(http.Header{
		"Niko-App-Set":       {"inside-only"},
		"Niko-Lists-Version": {"1042"},
		"niko-ack":           {"1"},
		"X-Several":          {"a", "b c"},
		"X-Empty-Value":      {""},
		"X-No-Values":        {},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"niko-app-set":       "inside-only",
		"niko-lists-version": "1042",
		"niko-ack":           "1",
		"x-several":          "a, b c",
		"x-empty-value":      "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	if got, err := connectRequestHeaders(nil); err != nil || got != nil {
		t.Fatalf("nil header: %v, %v", got, err)
	}

	for name, header := range map[string]http.Header{
		"pseudo-header":                {":authority": {"example.org:443"}},
		"library's own":                {"-Force-Quic": {"false"}},
		"connect authority":            {"-connect-authority": {"example.org:443"}},
		"credentials":                  {"Proxy-Authorization": {"Basic eDp4"}},
		"credentials in lower case":    {"proxy-authorization": {"Basic eDp4"}},
		"padding":                      {"Padding": {"~~~~"}},
		"padding type":                 {"Padding-Type-Request": {"1"}},
		"host":                         {"Host": {"example.org"}},
		"connection-specific":          {"Connection": {"close"}},
		"transfer coding":              {"Transfer-Encoding": {"chunked"}},
		"space in name":                {"Niko App": {"x"}},
		"empty name":                   {"": {"x"}},
		"line feed in value":           {"Niko-App-Set": {"a\nb"}},
		"carriage return in value":     {"Niko-App-Set": {"a\rb"}},
		"NUL in value":                 {"Niko-App-Set": {"a\x00b"}},
		"leading space in value":       {"Niko-App-Set": {" a"}},
		"trailing tab in value":        {"Niko-App-Set": {"a\t"}},
		"one bad value among good":     {"Niko-App-Set": {"a", "b\n"}},
		"same name in different cases": {"Niko-Ack": {"1"}, "niko-ack": {"1"}},
	} {
		if _, err := connectRequestHeaders(header); err == nil {
			t.Errorf("%s: %v accepted", name, header)
		}
	}
}

func TestConnectError(t *testing.T) {
	var err error = &ConnectError{Status: 403, Header: http.Header{"Niko-Refused": {"attest-required"}}}
	if err.Error() != "unexpected response status: 403" {
		t.Fatalf("message %q", err.Error())
	}
	var connectError *ConnectError
	if !errors.As(err, &connectError) || connectError.Header.Get("niko-refused") != "attest-required" {
		t.Fatalf("%#v", err)
	}
}
