package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestChromiumNotice(t *testing.T) {
	root := writeTree(t, map[string]string{
		"LICENSE":                          "Chromium BSD license text",
		"third_party/zlib/README.chromium": "Name: zlib\nURL: https://zlib.net/\nVersion: 1.3\nLicense: Zlib\nLicense File: LICENSE\nShipped: yes\n\nDescription:\nLicense File: not-a-field\n",
		"third_party/zlib/LICENSE":         "zlib\r\ntext",
		// two records, one with a path from src's root and one with two files
		"base/third_party/apple/README.chromium": "Name: Darwin\nLicense: APSL-2.0\nLicense File: //third_party/zlib/LICENSE\nShipped: yes\n\n" +
			dependencyDivider + "\n\nName: CF\nLicense: MIT, BSD-3-Clause\nLicense File: a.txt, b.txt\n",
		"base/third_party/apple/a.txt": "text a",
		"base/third_party/apple/b.txt": "text b",
		// not shipped: left out
		"third_party/nasm/README.chromium": "Name: nasm\nLicense: BSD-2-Clause\nLicense File: LICENSE\nShipped: no\n",
		"third_party/nasm/LICENSE":         "nasm text",
		// no Name: not a record
		"build/internal/README.chromium": "Internal property sheets:\n  essential.vsprops\n",
		// Cronet's license tool test data and build output: not the tree
		"components/cronet/license/tests/target_a/README.chromium": "Name: test\nLicense File: missing\n",
		"out/Release/third_party/x/README.chromium":                "Name: x\nLicense File: missing\n",
	})
	output := filepath.Join(t.TempDir(), chromiumNoticeName)
	if err := writeChromiumNotice(root, output, "Licenses of libcronet"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	notice := string(data)
	for _, want := range []string{
		"Licenses of libcronet",
		"Chromium\nURL: https://www.chromium.org/\nLicense: BSD-3-Clause\n\nChromium BSD license text",
		"zlib 1.3 (third_party/zlib)\nURL: https://zlib.net/\nLicense: Zlib\n\nzlib\ntext",
		"Darwin (base/third_party/apple)\nLicense: APSL-2.0\n\nzlib\ntext",
		"CF (base/third_party/apple)\nLicense: MIT, BSD-3-Clause\n\ntext a\n\ntext b",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice lacks %q:\n%s", want, notice)
		}
	}
	for _, unwanted := range []string{"nasm", "property sheets", "test", "not-a-field", "\r"} {
		if strings.Contains(notice, unwanted) {
			t.Errorf("notice has %q:\n%s", unwanted, notice)
		}
	}
	// Chromium first, then by directory
	if strings.Index(notice, "Chromium BSD") > strings.Index(notice, "(base/third_party/apple)") ||
		strings.Index(notice, "(base/third_party/apple)") > strings.Index(notice, "(third_party/zlib)") {
		t.Errorf("sections out of order:\n%s", notice)
	}
}

func TestChromiumNoticeMissingLicense(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no license file named": {
			"LICENSE":                       "x",
			"third_party/a/README.chromium": "Name: a\nLicense: MIT\nShipped: yes\n",
		},
		"license file missing": {
			"LICENSE":                       "x",
			"third_party/a/README.chromium": "Name: a\nLicense: MIT\nLicense File: LICENSE\n",
		},
		"no Chromium LICENSE": {
			"third_party/a/README.chromium": "Name: a\nShipped: no\n",
		},
	} {
		root := writeTree(t, files)
		if err := writeChromiumNotice(root, filepath.Join(t.TempDir(), chromiumNoticeName), "h"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
