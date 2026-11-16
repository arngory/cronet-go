package cronet

import "errors"

// ErrExactServerCertificatesUnsupported is returned when the loaded library has no exact server certificates: a
// library built before them.
var ErrExactServerCertificatesUnsupported = errors.New("cronet: library has no exact server certificates")

// CheckExactServerCertificatesSupport returns nil if the library has exact server certificates
// (EngineParams.SetExactServerCertificates), ErrExactServerCertificatesUnsupported if it was built without them, or
// the error of loading it (purego). With purego it loads the library at the default place if none is loaded, once
// for the process: call it after LoadLibrary with a path of your own, not before.
func CheckExactServerCertificatesSupport() error {
	return checkExactServerCertificatesSupport()
}
