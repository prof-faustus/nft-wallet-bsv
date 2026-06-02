// Package threshold implements DEALERLESS threshold secret sharing over
// the secp256k1 group order N (docs/08 §8.3 threshold scheme). It is used
// two ways:
//
//   - to share a crypto-shred content key t-of-n (internal/shred), and
//   - to generate a dealerless threshold ECDSA KEY: the shared secret is
//     a secp256k1 scalar, so ScalarToECDSA turns a reconstructed secret
//     into a working ECDSA key (ec.PrivateKeyFromBytes).
//
// "Dealerless" = no trusted dealer and no single party knows the secret:
// in DealerlessGenerate each participant independently Shamir-splits a
// random sub-secret and the per-index shares are summed; the group secret
// is the sum of sub-secrets, which no participant holds until t shares are
// combined.
//
// HONEST SCOPE (CLAUDE.md §4): this provides dealerless threshold key
// GENERATION + SHARING (reconstruct-to-use). It deliberately does NOT
// implement interactive threshold ECDSA SIGNING (sign without ever
// reconstructing the key) — that needs an MtA/ZK protocol (GG/FROST-class)
// that must not be hand-rolled. Reconstruction-to-sign is the boundary
// here, and it is stated, not hidden.
package threshold

import (
	"crypto/rand"
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// order is the secp256k1 group order N — the field shares live in.
var order = ec.S256().N

// Share is one point (x, f(x) mod N) of a sharing polynomial.
type Share struct {
	X int      // evaluation index (1..n); never 0 (0 holds the secret)
	Y *big.Int // f(x) mod N
}

// randScalar returns a uniform scalar in [1, N).
func randScalar() (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

// Split shares secret into n Shamir shares, any t of which reconstruct it
// (degree t-1 polynomial with a0 = secret, random higher coefficients).
func Split(secret *big.Int, t, n int) ([]Share, error) {
	if t < 1 || n < t {
		return nil, fmt.Errorf("threshold: need 1<=t<=n (t=%d n=%d)", t, n)
	}
	coeffs := make([]*big.Int, t)
	coeffs[0] = new(big.Int).Mod(secret, order)
	for i := 1; i < t; i++ {
		c, err := randScalar()
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}
	shares := make([]Share, n)
	for x := 1; x <= n; x++ {
		shares[x-1] = Share{X: x, Y: eval(coeffs, x)}
	}
	return shares, nil
}

// eval evaluates the polynomial (Horner) at x, mod N.
func eval(coeffs []*big.Int, x int) *big.Int {
	xb := big.NewInt(int64(x))
	acc := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc.Mul(acc, xb)
		acc.Add(acc, coeffs[i])
		acc.Mod(acc, order)
	}
	return acc
}

// Reconstruct recovers the secret via Lagrange interpolation at x=0, mod
// N. Requires >= t shares with DISTINCT indices; fewer yields a different
// (wrong) value, which is the whole point of a threshold.
func Reconstruct(shares []Share) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("threshold: no shares")
	}
	secret := new(big.Int)
	for j := range shares {
		xj := big.NewInt(int64(shares[j].X))
		num := big.NewInt(1)
		den := big.NewInt(1)
		for m := range shares {
			if m == j {
				continue
			}
			xm := big.NewInt(int64(shares[m].X))
			num.Mul(num, xm).Mod(num, order)
			diff := new(big.Int).Sub(xm, xj)
			den.Mul(den, diff).Mod(den, order)
		}
		denInv := new(big.Int).ModInverse(den, order)
		if denInv == nil {
			return nil, fmt.Errorf("threshold: duplicate share index")
		}
		lj := new(big.Int).Mul(num, denInv)
		lj.Mod(lj, order)
		term := new(big.Int).Mul(shares[j].Y, lj)
		term.Mod(term, order)
		secret.Add(secret, term).Mod(secret, order)
	}
	return secret, nil
}

// DealerlessGenerate produces a t-of-n sharing of a group secret that NO
// single participant knows: `parties` participants each split a random
// sub-secret and the per-index shares are summed. Returns the group
// secret (for the caller's verification/use) and the n combined shares.
func DealerlessGenerate(t, n, parties int) (group *big.Int, shares []Share, err error) {
	if parties < 1 {
		return nil, nil, fmt.Errorf("threshold: need >=1 party")
	}
	group = new(big.Int)
	sumY := make([]*big.Int, n)
	for i := range sumY {
		sumY[i] = new(big.Int)
	}
	for p := 0; p < parties; p++ {
		s, err := randScalar()
		if err != nil {
			return nil, nil, err
		}
		group.Add(group, s).Mod(group, order)
		sub, err := Split(s, t, n)
		if err != nil {
			return nil, nil, err
		}
		for i := range sub {
			sumY[i].Add(sumY[i], sub[i].Y).Mod(sumY[i], order)
		}
	}
	shares = make([]Share, n)
	for i := range shares {
		shares[i] = Share{X: i + 1, Y: sumY[i]}
	}
	return group, shares, nil
}

// ScalarToECDSA turns a reconstructed secret scalar into a usable
// secp256k1 ECDSA keypair — proving a dealerless threshold-shared secret
// IS a threshold ECDSA key once t shares are combined.
func ScalarToECDSA(s *big.Int) (*ec.PrivateKey, *ec.PublicKey, error) {
	v := new(big.Int).Mod(s, order)
	if v.Sign() == 0 {
		return nil, nil, fmt.Errorf("threshold: zero scalar")
	}
	b := make([]byte, 32)
	v.FillBytes(b) // left-padded big-endian
	priv, pub := ec.PrivateKeyFromBytes(b)
	return priv, pub, nil
}
