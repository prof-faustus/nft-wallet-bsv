// Package svnode is the SV Node (OD-4) implementation of the
// chain.Adapter and chain.RegtestControl interfaces. It is the ONLY
// node-specific surface in the system (docs/01 §1.4, docs/05 §5.3): the
// exact JSON-RPC method names are pinned here and nowhere else, so a node
// swap touches only this package.
//
// RPC method names were verified against a running bitcoinsv/bitcoin-sv
// 1.1.0 regtest node (deploy/regtest) — see adapter.go for the pinned
// map. This resolves the docs/01 §1.4 / docs/06 WS1 `TODO(verify)` for
// the regtest profile; the testnet/mainnet ARC profile remains a future
// `TODO(verify)`.
//
// MUST NOT: import a BTC library or carry BTC params (CLAUDE.md §1).
// This file speaks bitcoind-style JSON-RPC over HTTP with stdlib only;
// BSV transaction building/SPV lives in internal/chain (CH-1) and, in
// WS2, the BSV Go SDK.
package svnode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config locates and authenticates a node's JSON-RPC endpoint.
type Config struct {
	URL  string // e.g. http://127.0.0.1:18332/
	User string
	Pass string
}

// rpcClient is a minimal bitcoind-style JSON-RPC 1.0 client.
type rpcClient struct {
	cfg  Config
	http *http.Client
}

func newRPCClient(cfg Config) *rpcClient {
	return &rpcClient{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call invokes a JSON-RPC method. A node-level error is returned as an
// *rpcError so callers can branch on Code (e.g. "tx not found").
func (c *rpcClient) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "1.0", ID: "nftbsv", Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.cfg.User, c.cfg.Pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out rpcResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("rpc %s: decode (HTTP %d): %w; body=%s", method, resp.StatusCode, err, string(raw))
	}
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}
