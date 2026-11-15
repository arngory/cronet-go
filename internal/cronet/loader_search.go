package cronet

import (
	"path/filepath"
	"strings"
)

// libraryName is the library's file on Windows.
const libraryName = "libcronet.dll"

// SearchPathEnv set to 1 lets the Windows loader look for libcronet.dll in
// PATH too, after the executable's directory, as it did before. Without it
// a DLL that anyone who can write a PATH directory placed there is never
// loaded; an embedder that keeps the library elsewhere passes its path to
// LoadLibrary.
const SearchPathEnv = "CRONET_DLL_SEARCH_PATH"

// librarySearchDirs is where the Windows loader looks for the library, in
// order: the executable's directory, then, only if usePath, each absolute
// directory of PATH (a relative one would be the current directory's).
func librarySearchDirs(exeDir, pathEnv string, usePath bool) []string {
	var dirs []string
	if exeDir != "" {
		dirs = append(dirs, exeDir)
	}
	if !usePath {
		return dirs
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir = strings.TrimSpace(dir); dir != "" && filepath.IsAbs(dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}
