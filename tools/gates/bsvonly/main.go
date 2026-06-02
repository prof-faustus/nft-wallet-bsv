// Command bsvonly is the `bsv-only` CI gate (docs/05 §5.2, CLAUDE.md §1).
// BSV only, never BTC. It fails the build on:
//
//  1. Dependency allowlist: any module in go.mod's require graph whose
//     path matches a known BTC chain-library denylist (bitcoinjs-lib,
//     btcd/btcsuite, rust-bitcoin, etc.). BSV and BTC share no codebase.
//  2. Network-parameter grep: BTC-specific tokens anywhere in source
//     outside the single params module — bech32 mainnet HRP "bc1"
//     (BSV has no SegWit/bech32), "segwit", "taproot", "bitcoinjs".
//  3. Single params source: a network magic/address-version/port literal
//     must live only in internal/params. (WS0 ships only that module;
//     the grep below flags BTC-isms; divergent-source detection tightens
//     as the chain adapter lands in WS1.)
//
// Exit 0 = clean; non-zero = a BTC artifact is present.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// btcModuleDeny are import-path substrings that identify BTC chain libs.
var btcModuleDeny = []string{
	"bitcoinjs", "btcsuite", "btcd", "rust-bitcoin", "bitcoincore",
	"lightningnetwork", "ldk", "rust-lightning",
}

// btcTokenDeny are BTC-specific source tokens (case-insensitive) that
// must not appear outside the params module. "bc1" is the BTC mainnet
// bech32 HRP; BSV has no bech32/SegWit/Taproot.
var btcTokenDeny = []string{
	"\"bc1", "'bc1", "segwit", "taproot", "bitcoinjs",
}

func main() {
	root := repoRoot()
	var problems []string

	// (1) go.mod dependency allowlist.
	if gm, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		for _, line := range strings.Split(string(gm), "\n") {
			l := strings.ToLower(strings.TrimSpace(line))
			for _, deny := range btcModuleDeny {
				if strings.Contains(l, deny) && !strings.HasPrefix(l, "//") {
					problems = append(problems, fmt.Sprintf("go.mod: BTC-family dependency matched %q: %s", deny, strings.TrimSpace(line)))
				}
			}
		}
	}

	// (2)/(3) source token grep.
	paramsDir := filepath.ToSlash(filepath.Join("internal", "params"))
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
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".go" && ext != ".cs" && ext != ".ts" {
			return nil
		}
		slash := filepath.ToSlash(p)
		// The params module is the sanctioned home for network constants;
		// the gate sources themselves contain these denylist tokens as data.
		if strings.Contains(slash, paramsDir) || strings.Contains(slash, "tools/gates/") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		low := strings.ToLower(string(b))
		for _, tok := range btcTokenDeny {
			if strings.Contains(low, tok) {
				problems = append(problems, fmt.Sprintf("%s: BTC-specific token %q present outside internal/params", slash, tok))
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bsv-only: ERROR: %v\n", err)
		os.Exit(2)
	}

	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "bsv-only: FAIL")
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		os.Exit(1)
	}
	fmt.Println("bsv-only: OK (no BTC dependency or BTC-specific network token)")
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
