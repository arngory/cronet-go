package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// fpmHelpers are the declarations of arm_vector_types.h, in the clang of
// the Chromium the libraries are built from, that clang also takes as
// builtins of C linkage (llvm/llvm-project#227722). The UCRT of the
// Windows 11 SDK 10.0.26100 includes arm_neon.h, and with it them, from
// wchar.h on ARM64, and every C++ file that includes wchar.h then fails:
// "declaration of '__arm_set_fpm_lscale' has a different language
// linkage". LLVM wraps them in extern "C" (llvm/llvm-project#238025);
// fixClangFPMHelpers does the same to the downloaded headers until the
// Chromium's clang has the change.
var fpmHelpers = []string{"__arm_set_fpm_lscale(", "__arm_set_fpm_nscale(", "__arm_set_fpm_lscale2("}

const fpmFixMark = "/* cronet-go: FPM helpers in extern \"C\" (llvm/llvm-project#238025) */"

// fixClangFPMHelpers puts the FPM helper declarations of every
// arm_vector_types.h of the downloaded clang in extern "C", once. A header
// that already has them so, or has none, stays as it is.
func fixClangFPMHelpers(root string) error {
	headers, err := filepath.Glob(filepath.Join(root, "third_party/llvm-build/Release+Asserts/lib/clang/*/include/arm_vector_types.h"))
	if err != nil {
		return err
	}
	for _, h := range headers {
		b, err := os.ReadFile(h)
		if err != nil {
			return err
		}
		fixed, changed, err := wrapFPMHelpers(b)
		if err != nil {
			return fmt.Errorf("%s: %w", h, err)
		}
		if !changed {
			continue
		}
		if err := os.WriteFile(h, fixed, 0o644); err != nil {
			return err
		}
		log.Printf("Wrapped the FPM helpers of %s in extern \"C\"", h)
	}
	return nil
}

// wrapFPMHelpers wraps the run of lines that declare the FPM helpers in
// extern "C" for C++. It reports no change when the header has none of
// them, or carries the mark, or the upstream fix already wraps them.
func wrapFPMHelpers(b []byte) ([]byte, bool, error) {
	if bytes.Contains(b, []byte(fpmFixMark)) {
		return b, false, nil
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	first, last := -1, -1
	for i, l := range lines {
		for _, f := range fpmHelpers {
			if bytes.Contains(l, []byte(f)) && !bytes.HasPrefix(bytes.TrimSpace(l), []byte("//")) {
				if first < 0 {
					first = i
				}
				last = i
			}
		}
	}
	if first < 0 {
		return b, false, nil
	}
	for i := first; i <= last; i++ {
		if bytes.TrimSpace(lines[i]) == nil {
			continue
		}
		found := false
		for _, f := range fpmHelpers {
			found = found || bytes.Contains(lines[i], []byte(f))
		}
		if !found {
			return nil, false, fmt.Errorf("the FPM helper declarations are not one run of lines (line %d)", i+1)
		}
	}
	// The upstream fix: an extern "C" block just before them.
	for i := first - 1; i >= 0 && i >= first-3; i-- {
		if bytes.Contains(lines[i], []byte(`extern "C"`)) {
			return b, false, nil
		}
	}
	var out bytes.Buffer
	for i, l := range lines {
		if i == first {
			out.WriteString(fpmFixMark + "\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n")
		}
		out.Write(l)
		if i == last {
			if !bytes.HasSuffix(l, []byte("\n")) {
				out.WriteString("\n")
			}
			out.WriteString("#ifdef __cplusplus\n}\n#endif\n")
		}
	}
	return out.Bytes(), true, nil
}
