// Command noopreturn is the `no-op-return` CI gate (docs/05 §5.2,
// enforces I-NFT-1, CLAUDE.md §2). OP_RETURN (opcode 0x6a) is banned
// absolutely — in any locking or unlocking script this software emits.
//
// What it scans:
//   - every script/transaction hex FIXTURE under any `testdata/` dir and
//     every file with a .hex/.scripthex/.txhex extension, and
//   - the emitted-bytes drop dir tools/gates/emitted/ where the test
//     suite dumps the actual serialized scripts/transactions it builds
//     (so a runtime regression that introduces 0x6a is caught even when
//     the source looks clean — docs/05 §5.2).
//
// It decodes the hex and FAILS if opcode byte 0x6a appears anywhere in
// the decoded bytes. (Stage WS2/WS3 extend this to consume the builder's
// emitted bytes directly; the builder API is, additionally, structurally
// incapable of appending OP_RETURN — it exposes no such primitive.)
//
// Exit 0 = clean; non-zero = a banned OP_RETURN byte was found.
//
// Implements/tests: I-NFT-1 (the gate side; the impl/test annotations
// land with the token carrier in WS3).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const opReturn = 0x6a

func main() {
	root := repoRoot()
	var scanned int
	var violations []string

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "dist" || base == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		slash := filepath.ToSlash(p)
		inTestdata := strings.Contains(slash, "/testdata/")
		inEmitted := strings.Contains(slash, "tools/gates/emitted/")
		ext := strings.ToLower(filepath.Ext(p))
		isHexExt := ext == ".hex" || ext == ".scripthex" || ext == ".txhex"
		if !(isHexExt || ((inTestdata || inEmitted) && isHexExt)) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scanned++
		// Hex fixtures may contain multiple whitespace-separated entries.
		for _, field := range strings.Fields(string(raw)) {
			b, derr := hex.DecodeString(strings.TrimPrefix(field, "0x"))
			if derr != nil {
				violations = append(violations, fmt.Sprintf("%s: not valid hex (%v)", slash, derr))
				continue
			}
			for i, by := range b {
				if by == opReturn {
					violations = append(violations, fmt.Sprintf("%s: OP_RETURN (0x6a) at byte offset %d", slash, i))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "no-op-return: ERROR: %v\n", err)
		os.Exit(2)
	}

	if len(violations) > 0 {
		fmt.Fprintln(os.Stderr, "no-op-return: FAIL")
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "  - %s\n", v)
		}
		os.Exit(1)
	}
	fmt.Printf("no-op-return: OK (%d hex fixture file(s) scanned, no 0x6a)\n", scanned)
}

func repoRoot() string {
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
