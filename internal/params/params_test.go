// Tests for the single BSV params module. These assert the module is the
// one canonical source and that an unknown network fails loudly rather
// than silently falling back to another chain's parameters (which would
// be a BSV-only violation, CLAUDE.md §1).
package params

import "testing"

func TestForKnownNetworks(t *testing.T) {
	cases := []struct {
		net   Network
		p2pkh byte
		port  uint16
	}{
		{Mainnet, 0x00, 8333},
		{Testnet, 0x6f, 18333},
		{Regtest, 0x6f, 18444},
	}
	for _, c := range cases {
		p, err := For(c.net)
		if err != nil {
			t.Fatalf("For(%s): unexpected error %v", c.net, err)
		}
		if p.Net != c.net {
			t.Errorf("For(%s): Net = %s", c.net, p.Net)
		}
		if p.P2PKHVersion != c.p2pkh {
			t.Errorf("For(%s): P2PKHVersion = 0x%02x, want 0x%02x", c.net, p.P2PKHVersion, c.p2pkh)
		}
		if p.DefaultP2PPort != c.port {
			t.Errorf("For(%s): port = %d, want %d", c.net, p.DefaultP2PPort, c.port)
		}
	}
}

func TestForUnknownNetworkErrors(t *testing.T) {
	if _, err := For("dogecoin"); err == nil {
		t.Fatal("For(unknown): expected an error, got nil (must never silently fall back)")
	}
}

func TestMustForPanicsOnUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustFor(unknown): expected panic")
		}
	}()
	_ = MustFor("litecoin")
}
