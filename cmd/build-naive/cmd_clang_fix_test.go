package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fpmHeader = `#ifndef __ARM_NEON_TYPES_H
#define __ARM_NEON_TYPES_H
typedef uint64_t fpm_t;

__inline__ fpm_t __attribute__((__always_inline__, __nodebug__)) __arm_set_fpm_lscale(fpm_t __fpm, uint64_t __scale);
__inline__ fpm_t __attribute__((__always_inline__, __nodebug__)) __arm_set_fpm_nscale(fpm_t __fpm, int64_t __scale);
__inline__ fpm_t __attribute__((__always_inline__, __nodebug__))  __arm_set_fpm_lscale2(fpm_t __fpm, uint64_t __scale);

#endif
`

func TestWrapFPMHelpers(t *testing.T) {
	out, changed, err := wrapFPMHelpers([]byte(fpmHeader))
	if err != nil || !changed {
		t.Fatalf("changed %v, %v", changed, err)
	}
	s := string(out)
	open := strings.Index(s, "extern \"C\" {")
	closing := strings.Index(s, "#ifdef __cplusplus\n}\n#endif")
	for _, f := range fpmHelpers {
		i := strings.Index(s, f)
		if i < open || i > closing || open < 0 {
			t.Errorf("%s outside extern \"C\":\n%s", f, s)
		}
	}
	if strings.Count(s, "#ifdef __cplusplus") != 2 || !strings.HasSuffix(s, "#endif\n") {
		t.Errorf("guards:\n%s", s)
	}
	// Once: the mark stops a second wrap.
	again, changed, err := wrapFPMHelpers(out)
	if err != nil || changed || !bytes.Equal(again, out) {
		t.Errorf("second wrap changed it: %v %v", changed, err)
	}
	// The upstream fix in place, or no helpers: nothing to do.
	upstream := strings.Replace(fpmHeader, "\n__inline__ fpm_t", "\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n__inline__ fpm_t", 1)
	if _, changed, err := wrapFPMHelpers([]byte(upstream)); changed || err != nil {
		t.Errorf("upstream fix wrapped again: %v %v", changed, err)
	}
	if _, changed, err := wrapFPMHelpers([]byte("#define X 1\n")); changed || err != nil {
		t.Errorf("a header without them: %v %v", changed, err)
	}
	// Something else between them: refused, not guessed.
	broken := strings.Replace(fpmHeader, "__inline__ fpm_t __attribute__((__always_inline__, __nodebug__)) __arm_set_fpm_nscale", "int x;\n__inline__ fpm_t __attribute__((__always_inline__, __nodebug__)) __arm_set_fpm_nscale", 1)
	if _, _, err := wrapFPMHelpers([]byte(broken)); err == nil {
		t.Error("a split run of declarations was wrapped")
	}
}

func TestFixClangFPMHelpers(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "third_party/llvm-build/Release+Asserts/lib/clang/24/include")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h := filepath.Join(dir, "arm_vector_types.h")
	if err := os.WriteFile(h, []byte(fpmHeader), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixClangFPMHelpers(root); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(h)
	if !bytes.Contains(b, []byte(fpmFixMark)) {
		t.Fatalf("not fixed:\n%s", b)
	}
	if err := fixClangFPMHelpers(t.TempDir()); err != nil {
		t.Errorf("no clang: %v", err)
	}
}
