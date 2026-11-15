package cronet

import (
	"path/filepath"
	"slices"
	"testing"
)

// The Windows loader takes libcronet.dll from the executable's directory;
// PATH only when the embedder sets CRONET_DLL_SEARCH_PATH=1, and then its
// absolute directories only.
func TestLibrarySearchDirs(t *testing.T) {
	exe := filepath.FromSlash("/opt/app")
	list := filepath.Join(filepath.FromSlash("/usr/bin")) + string(filepath.ListSeparator) + "." +
		string(filepath.ListSeparator) + string(filepath.ListSeparator) + "relative" + string(filepath.ListSeparator) +
		filepath.FromSlash("/srv/lib")
	if got := librarySearchDirs(exe, list, false); !slices.Equal(got, []string{exe}) {
		t.Errorf("without the opt-in: %q", got)
	}
	if got, want := librarySearchDirs(exe, list, true), []string{exe, filepath.FromSlash("/usr/bin"), filepath.FromSlash("/srv/lib")}; !slices.Equal(got, want) {
		t.Errorf("with it: %q, want %q", got, want)
	}
	if got := librarySearchDirs("", "", false); len(got) != 0 {
		t.Errorf("no executable: %q", got)
	}
}
