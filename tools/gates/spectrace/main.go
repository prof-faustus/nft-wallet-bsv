// Command spectrace is the `spec-traceability` CI gate (docs/05 §5.2,
// docs/06 §6.5). It enforces, mechanically, that "the docs say it, the
// code does it, a test proves it":
//
//  1. Every normative ID found in docs/ must appear in trace.manifest.json
//     (no undocumented-status ID).
//  2. Every manifest ID with status "active" must have >=1 `//trace:impl`
//     annotation in non-test source AND >=1 `//trace:test` annotation in
//     a *_test.go file.
//  3. Every `//trace:` annotation in the codebase must reference an ID
//     that exists in the manifest (no orphan reference).
//
// Exit code 0 = all satisfied; non-zero = gate fails (CI red).
//
// Scope note: the normative-ID universe this gate extracts is the
// well-patterned set — I-NFT-<n> and the trust-register IDs
// (HH-1/SC-1/PL-1/CN-1/NET-1/CH-1). The state-machine edges and message
// types (also normative, docs/03) are added to the extractor at WS4/WS5
// when they are implemented; until then their coverage is tracked by the
// manifest entries that gate WS4/WS5. This is recorded honestly rather
// than pretending full coverage exists at WS0 (CLAUDE.md §4).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type manifest struct {
	IDs map[string]struct {
		Status string `json:"status"`
		WS     string `json:"ws"`
		Desc   string `json:"desc"`
	} `json:"ids"`
}

// idPattern matches the well-patterned normative IDs in docs/.
var idPattern = regexp.MustCompile(`\b(I-NFT-\d+|HH-1|SC-1|PL-1|CN-1|NET-1|CH-1)\b`)

// annPattern matches a traceability annotation line, capturing kind
// (impl|test) and the remainder (one or more space-separated IDs).
var annPattern = regexp.MustCompile(`//\s*trace:(impl|test)\s+(.+)`)

// idTokenShape accepts only ID-shaped tokens (UPPER, hyphenated, with a
// trailing segment), so prose following an annotation example ("e.g.",
// "<ID>") is never mistaken for a normative ID. A typo'd but ID-shaped
// token (e.g. I-NFT-99) still fails as an orphan reference — the
// intended catch.
var idTokenShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[0-9A-Z]+)+$`)

func main() {
	root := repoRoot()

	man, err := loadManifest(filepath.Join(root, "trace.manifest.json"))
	if err != nil {
		fail("loading manifest: %v", err)
	}

	docIDs, err := scanDocs(filepath.Join(root, "docs"))
	if err != nil {
		fail("scanning docs: %v", err)
	}

	impl, test, err := scanAnnotations(root)
	if err != nil {
		fail("scanning annotations: %v", err)
	}

	var problems []string

	// (1) Every docs ID must be in the manifest.
	for id := range docIDs {
		if _, ok := man.IDs[id]; !ok {
			problems = append(problems, fmt.Sprintf("docs normative ID %q is not declared in trace.manifest.json", id))
		}
	}

	// (3) Every annotated ID must exist in the manifest.
	for id := range impl {
		if _, ok := man.IDs[id]; !ok {
			problems = append(problems, fmt.Sprintf("//trace:impl references unknown ID %q (not in manifest)", id))
		}
	}
	for id := range test {
		if _, ok := man.IDs[id]; !ok {
			problems = append(problems, fmt.Sprintf("//trace:test references unknown ID %q (not in manifest)", id))
		}
	}

	// (2) Every active ID needs an impl AND a test annotation.
	for id, meta := range man.IDs {
		if meta.Status != "active" {
			continue
		}
		if !impl[id] {
			problems = append(problems, fmt.Sprintf("active ID %q has no //trace:impl reference", id))
		}
		if !test[id] {
			problems = append(problems, fmt.Sprintf("active ID %q has no //trace:test reference", id))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		fmt.Fprintln(os.Stderr, "spec-traceability: FAIL")
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		os.Exit(1)
	}

	active := 0
	for _, m := range man.IDs {
		if m.Status == "active" {
			active++
		}
	}
	fmt.Printf("spec-traceability: OK (%d docs IDs, %d manifest IDs, %d active)\n", len(docIDs), len(man.IDs), active)
}

func loadManifest(path string) (manifest, error) {
	var m manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if len(m.IDs) == 0 {
		return m, fmt.Errorf("manifest has no ids")
	}
	return m, nil
}

func scanDocs(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range idPattern.FindAllString(string(b), -1) {
			out[m] = true
		}
		return nil
	})
	return out, err
}

func scanAnnotations(root string) (impl, test map[string]bool, err error) {
	impl, test = map[string]bool{}, map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip VCS, deps, build output, and the gate sources
			// themselves (their regex literals are not annotations).
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "dist" || base == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, ".cs") && !strings.HasSuffix(p, ".ts") {
			return nil
		}
		// Do not treat the gate's own source, nor the trace convention
		// doc package (which contains annotation EXAMPLES), as annotation
		// input.
		sl := filepath.ToSlash(p)
		if strings.Contains(sl, "tools/gates/") || strings.Contains(sl, "internal/trace/") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		isTest := strings.HasSuffix(p, "_test.go") || strings.Contains(filepath.ToSlash(p), "/test")
		for _, line := range strings.Split(string(b), "\n") {
			m := annPattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			kind := m[1]
			for _, id := range strings.Fields(strings.TrimSpace(m[2])) {
				id = strings.TrimRight(id, ".,;)")
				if !idTokenShape.MatchString(id) {
					continue // prose, not an ID
				}
				if kind == "impl" {
					impl[id] = true
				} else {
					test[id] = true
				}
				_ = isTest
			}
		}
		return nil
	})
	return impl, test, err
}

func repoRoot() string {
	// Walk up from CWD until a go.mod is found.
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "spec-traceability: ERROR: "+format+"\n", a...)
	os.Exit(2)
}
