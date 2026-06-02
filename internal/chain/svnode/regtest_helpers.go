// Regtest/test convenience queries (docs/05 §5.3) — not part of the
// production chain.Adapter interface. Used to locate funded outputs when
// driving the WS2/WS3 live tests.
package svnode

import (
	"context"
	"encoding/json"
	"fmt"
)

// FindVout returns the index of txid's output whose locking script equals
// lockingScriptHex. It decodes the transaction and matches scriptPubKey,
// so it works for ANY address — including external wallet addresses the
// node does not track in its own wallet.
func (a *Adapter) FindVout(ctx context.Context, txid, lockingScriptHex string) (uint32, error) {
	res, err := a.rpc.call(ctx, "getrawtransaction", txid, true)
	if err != nil {
		return 0, err
	}
	var tx struct {
		Vout []struct {
			N            uint32 `json:"n"`
			ScriptPubKey struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if err := json.Unmarshal(res, &tx); err != nil {
		return 0, fmt.Errorf("svnode: decode tx for FindVout: %w", err)
	}
	for _, v := range tx.Vout {
		if v.ScriptPubKey.Hex == lockingScriptHex {
			return v.N, nil
		}
	}
	return 0, fmt.Errorf("svnode: no output of %s matches the given locking script", txid)
}
