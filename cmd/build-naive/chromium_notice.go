package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// chromiumNoticeName is the file each lib module carries next to libcronet:
// the licenses of Chromium and of the third-party code shipped in it, as plain
// text. Its name starts with NOTICE so that tools collecting the licenses of
// Go modules take it.
const chromiumNoticeName = "NOTICE.chromium.txt"

// The tree naiveproxy imports from Chromium is minimized and has no
// tools/licenses, so the notice is made from what that tool reads: the
// README.chromium metadata of each third-party directory and the license
// files they name.
const dependencyDivider = "-------------------- DEPENDENCY DIVIDER --------------------"

// chromiumDependency is one record of a README.chromium.
type chromiumDependency struct {
	Directory    string   // of the README.chromium, relative to src
	Name         string   // Name
	URL          string   // URL
	Version      string   // Version
	License      string   // License (SPDX identifiers)
	LicenseFiles []string // License File, relative to src
	Shipped      string   // Shipped: "yes", "no", or "" when not said
}

// readChromiumDependencies reads every README.chromium under srcRoot. A file
// with no Name is not a dependency record (build/internal's is notes) and is
// left out; so are the test data of Cronet's own license tool.
func readChromiumDependencies(srcRoot string) ([]chromiumDependency, error) {
	var dependencies []chromiumDependency
	err := filepath.WalkDir(srcRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Build output and the downloaded toolchain are not the tree.
			name := entry.Name()
			if name == ".git" || name == "out" || name == "llvm-build" ||
				path == filepath.Join(srcRoot, "components", "cronet", "license", "tests") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "README.chromium" {
			return nil
		}
		directory, err := filepath.Rel(srcRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		records, err := parseReadmeChromium(filepath.ToSlash(directory), string(data))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		dependencies = append(dependencies, records...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(dependencies, func(i, j int) bool {
		return dependencies[i].Directory < dependencies[j].Directory
	})
	return dependencies, nil
}

// parseReadmeChromium parses the records of one README.chromium, split by the
// dependency divider. Only the first value of a field counts; Description and
// what follows it are free text, where a line may look like a field.
func parseReadmeChromium(directory, content string) ([]chromiumDependency, error) {
	var records []chromiumDependency
	for _, part := range strings.Split(content, dependencyDivider) {
		fields := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(part))
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r")
			key, value, found := strings.Cut(line, ":")
			if !found || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key = strings.TrimSpace(key)
			if key == "Description" || key == "Local Modifications" {
				break
			}
			if _, seen := fields[key]; !seen {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		if fields["Name"] == "" {
			continue
		}
		record := chromiumDependency{
			Directory: directory,
			Name:      fields["Name"],
			URL:       fields["URL"],
			Version:   fields["Version"],
			License:   fields["License"],
			Shipped:   strings.ToLower(fields["Shipped"]),
		}
		for _, file := range strings.Split(fields["License File"], ",") {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			if strings.HasPrefix(file, "//") {
				record.LicenseFiles = append(record.LicenseFiles, strings.TrimPrefix(file, "//"))
			} else {
				record.LicenseFiles = append(record.LicenseFiles, filepath.ToSlash(filepath.Join(directory, file)))
			}
		}
		records = append(records, record)
	}
	return records, nil
}

// writeChromiumNotice writes the notice for the Chromium tree at srcRoot:
// Chromium's own LICENSE, then each shipped dependency with its license
// texts. A shipped dependency that names no license file, or names one that is
// not there, fails it: a notice that leaves a license out is worse than none.
func writeChromiumNotice(srcRoot, outputPath, header string) error {
	dependencies, err := readChromiumDependencies(srcRoot)
	if err != nil {
		return err
	}
	chromiumLicense, err := os.ReadFile(filepath.Join(srcRoot, "LICENSE"))
	if err != nil {
		return fmt.Errorf("Chromium's LICENSE: %w", err)
	}

	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteString("\n\n")
	writeNoticeSection(&builder, "Chromium", "https://www.chromium.org/", "BSD-3-Clause", unixNewlines(string(chromiumLicense)))
	for _, dependency := range dependencies {
		if dependency.Shipped == "no" {
			continue
		}
		if len(dependency.LicenseFiles) == 0 {
			return fmt.Errorf("%s (%s): shipped, but no License File", dependency.Name, dependency.Directory)
		}
		var texts []string
		for _, file := range dependency.LicenseFiles {
			data, err := os.ReadFile(filepath.Join(srcRoot, filepath.FromSlash(file)))
			if err != nil {
				return fmt.Errorf("%s (%s): license file: %w", dependency.Name, dependency.Directory, err)
			}
			texts = append(texts, strings.TrimSpace(unixNewlines(string(data))))
		}
		title := dependency.Name
		if v := dependency.Version; v != "" && v != "N/A" && v != "0" && v != "git" && !strings.Contains(v, " ") {
			title += " " + v
		}
		title += " (" + dependency.Directory + ")"
		writeNoticeSection(&builder, title, dependency.URL, dependency.License, strings.Join(texts, "\n\n"))
	}
	return os.WriteFile(outputPath, []byte(builder.String()), 0o644)
}

// unixNewlines makes the notice the same whichever platform built it: a
// Windows checkout gives some license files CRLF line ends.
func unixNewlines(text string) string {
	return strings.ReplaceAll(text, "\r\n", "\n")
}

func writeNoticeSection(builder *strings.Builder, title, url, license, text string) {
	builder.WriteString(strings.Repeat("=", 79))
	builder.WriteString("\n")
	builder.WriteString(title)
	builder.WriteString("\n")
	if url != "" {
		builder.WriteString("URL: " + url + "\n")
	}
	if license != "" {
		builder.WriteString("License: " + license + "\n")
	}
	builder.WriteString("\n")
	builder.WriteString(strings.TrimSpace(text))
	builder.WriteString("\n\n")
}
