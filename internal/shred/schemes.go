// The five crypto-shred schemes (docs/08 §8.3). All are selectable via
// shred.ForName. See package doc for the honest strength classification.
package shred

import (
	"encoding/binary"
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/prof-faustus/nft-wallet-bsv/internal/crypto"
	"github.com/prof-faustus/nft-wallet-bsv/internal/threshold"
)

// ---- 1. ecdh-singleuse (default; COOPERATIVE) ----------------------------
//
// K encrypts the payload; a SINGLE-USE ephemeral key wraps K to Bob via
// ECDH. Alice publishes eph_pub (bound to the swap) and shreds eph_priv +
// K + plaintext. Post-shred she holds only ciphertext + eph_pub, from
// which K is not recoverable (needs eph_priv or bobPriv).
type ecdhSingleUse struct{}

func (ecdhSingleUse) Name() string       { return "ecdh-singleuse" }
func (ecdhSingleUse) Strength() Strength { return Cooperative }

func (ecdhSingleUse) Seal(payload []byte, bobPub *ec.PublicKey) (*Sealed, *SellerSecret, error) {
	k, err := crypto.NewContentKey()
	if err != nil {
		return nil, nil, err
	}
	ct, err := crypto.AEADSeal(k, payload)
	if err != nil {
		return nil, nil, err
	}
	eph, err := ec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	kek, err := crypto.ECDHKey(eph, bobPub)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := crypto.AEADSeal(kek, k)
	if err != nil {
		return nil, nil, err
	}
	sealed := &Sealed{Scheme: "ecdh-singleuse", Ciphertext: ct, WrappedKey: wrapped, EphPub: eph.PubKey().Compressed()}
	secret := &SellerSecret{
		zeroize: []func(){func() { zero(k) }, func() { zero(kek) }},
		recover: func(s *Sealed) ([]byte, error) { return crypto.AEADOpen(k, s.Ciphertext) }, // Alice still has K
	}
	return sealed, secret, nil
}

func (ecdhSingleUse) Open(s *Sealed, bobPriv *ec.PrivateKey) ([]byte, error) {
	ephPub, err := ec.PublicKeyFromBytes(s.EphPub)
	if err != nil {
		return nil, err
	}
	kek, err := crypto.ECDHKey(bobPriv, ephPub)
	if err != nil {
		return nil, err
	}
	k, err := crypto.AEADOpen(kek, s.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("open: unwrap K: %w", err)
	}
	return crypto.AEADOpen(k, s.Ciphertext)
}

// ---- 2. key-surrender (COOPERATIVE) --------------------------------------
//
// K is wrapped under a secret s that the swap reveals to Bob. The
// post-swap Sealed carries s (surrendered). Alice shreds K + s.
type keySurrender struct{}

func (keySurrender) Name() string       { return "key-surrender" }
func (keySurrender) Strength() Strength { return Cooperative }

func (keySurrender) Seal(payload []byte, _ *ec.PublicKey) (*Sealed, *SellerSecret, error) {
	k, err := crypto.NewContentKey()
	if err != nil {
		return nil, nil, err
	}
	ct, err := crypto.AEADSeal(k, payload)
	if err != nil {
		return nil, nil, err
	}
	s, err := crypto.NewContentKey() // the surrendered secret
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := crypto.AEADSeal(kdf("nftbsv/surrender/v1", s), k)
	if err != nil {
		return nil, nil, err
	}
	sealed := &Sealed{Scheme: "key-surrender", Ciphertext: ct, WrappedKey: wrapped, Surrender: s}
	secret := &SellerSecret{
		zeroize: []func(){func() { zero(k) }, func() { zero(s) }},
		recover: func(sl *Sealed) ([]byte, error) { return crypto.AEADOpen(k, sl.Ciphertext) },
	}
	return sealed, secret, nil
}

func (keySurrender) Open(s *Sealed, _ *ec.PrivateKey) ([]byte, error) {
	if len(s.Surrender) == 0 {
		return nil, fmt.Errorf("open: secret not yet surrendered by the swap")
	}
	k, err := crypto.AEADOpen(kdf("nftbsv/surrender/v1", s.Surrender), s.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("open: unwrap K: %w", err)
	}
	return crypto.AEADOpen(k, s.Ciphertext)
}

// ---- 3. reencrypt (COOPERATIVE, weakest) ---------------------------------
//
// The payload is encrypted DIRECTLY to Bob's key (no content-key
// indirection). Honest caveat: Alice held the plaintext to re-encrypt it,
// so the "Alice can no longer access" property is the weakest here.
type reencrypt struct{}

func (reencrypt) Name() string       { return "reencrypt" }
func (reencrypt) Strength() Strength { return Cooperative }

func (reencrypt) Seal(payload []byte, bobPub *ec.PublicKey) (*Sealed, *SellerSecret, error) {
	eph, err := ec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	kek, err := crypto.ECDHKey(eph, bobPub)
	if err != nil {
		return nil, nil, err
	}
	ct, err := crypto.AEADSeal(kek, payload)
	if err != nil {
		return nil, nil, err
	}
	sealed := &Sealed{Scheme: "reencrypt", Ciphertext: ct, EphPub: eph.PubKey().Compressed()}
	// Alice can re-derive KEK from eph_priv + bobPub until she shreds it.
	bp := bobPub
	secret := &SellerSecret{
		zeroize: []func(){func() { zero(kek) }},
		recover: func(s *Sealed) ([]byte, error) {
			k2, err := crypto.ECDHKey(eph, bp)
			if err != nil {
				return nil, err
			}
			return crypto.AEADOpen(k2, s.Ciphertext)
		},
	}
	return sealed, secret, nil
}

func (reencrypt) Open(s *Sealed, bobPriv *ec.PrivateKey) ([]byte, error) {
	ephPub, err := ec.PublicKeyFromBytes(s.EphPub)
	if err != nil {
		return nil, err
	}
	kek, err := crypto.ECDHKey(bobPriv, ephPub)
	if err != nil {
		return nil, err
	}
	return crypto.AEADOpen(kek, s.Ciphertext)
}

// ---- 4. tee-attested (ENFORCED; software STAND-IN) -----------------------
//
// Models a TEE/cloud-TEE: K is wrapped to Bob (as in ecdh) AND the
// "enclave" emits a signed attestation that it released K to Bob and
// zeroized Alice's copy. This is the only scheme that ENFORCES Alice's
// loss — but the enforcement is only as real as the enclave. Here the
// "enclave key" is an ordinary process key, so this is a STAND-IN that
// demonstrates the shape pending the T-stage (docs/04 §4.6); it is NOT a
// hardware guarantee, and must never be presented as one.
//
//trace:impl I-CS-3
type teeAttested struct{}

func (teeAttested) Name() string       { return "tee-attested" }
func (teeAttested) Strength() Strength { return Enforced }

func (teeAttested) Seal(payload []byte, bobPub *ec.PublicKey) (*Sealed, *SellerSecret, error) {
	// Reuse the ecdh wrapping for the key transfer to Bob.
	base, _, err := ecdhSingleUse{}.Seal(payload, bobPub)
	if err != nil {
		return nil, nil, err
	}
	base.Scheme = "tee-attested"
	// The (stand-in) enclave attests release + zeroization.
	enclave, err := ec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	stmt := attStatement(bobPub, base.Ciphertext)
	sig, err := enclave.Sign(stmt)
	if err != nil {
		return nil, nil, err
	}
	base.EnclavePub = enclave.PubKey().Compressed()
	base.Attestation = sig.Serialize()
	// In a real TEE Alice never holds K; the stand-in models that by
	// giving her NO recovery path (already "zeroized").
	secret := &SellerSecret{zeroize: nil, recover: nil}
	return base, secret, nil
}

func (teeAttested) Open(s *Sealed, bobPriv *ec.PrivateKey) ([]byte, error) {
	return ecdhSingleUse{}.Open(s, bobPriv)
}

// VerifyTEEAttestation checks the enclave's signed release/zeroize
// statement. Returns true iff the attestation verifies under the embedded
// enclave key. (The stand-in caveat in teeAttested applies: a passing
// check proves the statement was signed, not that real hardware zeroized
// anything.)
//
//trace:impl I-CS-3
func VerifyTEEAttestation(s *Sealed, bobPub *ec.PublicKey) bool {
	if s.Scheme != "tee-attested" || len(s.Attestation) == 0 || len(s.EnclavePub) == 0 {
		return false
	}
	encPub, err := ec.PublicKeyFromBytes(s.EnclavePub)
	if err != nil {
		return false
	}
	sig, err := ec.ParseDERSignature(s.Attestation)
	if err != nil {
		return false
	}
	return sig.Verify(attStatement(bobPub, s.Ciphertext), encPub)
}

func attStatement(bobPub *ec.PublicKey, ct []byte) []byte {
	return kdf("nftbsv/tee/v1|released+zeroized|", append(bobPub.Compressed(), ct...))
}

// ---- 5. threshold (COOPERATIVE; dealerless t-of-n distributed custody) ---
//
// The content key K is NOT a freshly chosen AES key but the 32-byte
// big-endian encoding of a DEALERLESS threshold secret over the secp256k1
// order N (internal/threshold): no single party — not even Alice — ever
// holds K alone at generation time; it exists only as t-of-n Shamir shares
// summed across independently-contributing parties. The swap delivers t
// shares to Bob, who RECONSTRUCTS K (reconstruct-to-use) and AEAD-opens the
// payload. Alice shreds her shares + K.
//
// Honest scope (mirrors internal/threshold's package doc): this is
// dealerless threshold key GENERATION + SHARING, NOT interactive threshold
// ECDSA SIGNING. The reconstructed scalar IS a usable secp256k1 key (proven
// in tests), but we never run a GG/FROST-class MtA signing protocol — that
// must not be hand-rolled. Strength is COOPERATIVE: distributing custody
// raises the bar (t honest custodians must collude to recover early) but,
// like every Stage-1 scheme, it does not PROVE Alice destroyed her copy.
//
//trace:impl I-CS-4
type thresholdScheme struct{}

func (thresholdScheme) Name() string       { return "threshold" }
func (thresholdScheme) Strength() Strength { return Cooperative }

// thresholdT/N are the sharing parameters: a 2-of-3 dealerless scheme with
// 2 independently-contributing parties. Named, not magic (docs/08 §8.3).
const (
	thresholdT       = 2 // shares required to reconstruct K
	thresholdN       = 3 // total shares produced
	thresholdParties = 2 // independent dealerless contributors
)

func (thresholdScheme) Seal(payload []byte, _ *ec.PublicKey) (*Sealed, *SellerSecret, error) {
	group, shares, err := threshold.DealerlessGenerate(thresholdT, thresholdN, thresholdParties)
	if err != nil {
		return nil, nil, err
	}
	k := make([]byte, crypto.KeyLen) // K = 32-byte big-endian of the group scalar
	group.FillBytes(k)
	ct, err := crypto.AEADSeal(k, payload)
	if err != nil {
		return nil, nil, err
	}
	// The swap delivers exactly t shares to Bob (the minimum to reconstruct).
	delivered := make([][]byte, thresholdT)
	for i := 0; i < thresholdT; i++ {
		delivered[i] = encodeShare(shares[i])
	}
	sealed := &Sealed{Scheme: "threshold", Ciphertext: ct, Shares: delivered}
	secret := &SellerSecret{
		zeroize: []func(){func() { zero(k) }},
		recover: func(s *Sealed) ([]byte, error) { return crypto.AEADOpen(k, s.Ciphertext) },
	}
	return sealed, secret, nil
}

func (thresholdScheme) Open(s *Sealed, _ *ec.PrivateKey) ([]byte, error) {
	if len(s.Shares) < thresholdT {
		return nil, fmt.Errorf("open: have %d shares, need %d to reconstruct K", len(s.Shares), thresholdT)
	}
	shares := make([]threshold.Share, 0, len(s.Shares))
	for _, b := range s.Shares {
		sh, err := decodeShare(b)
		if err != nil {
			return nil, fmt.Errorf("open: decode share: %w", err)
		}
		shares = append(shares, sh)
	}
	group, err := threshold.Reconstruct(shares)
	if err != nil {
		return nil, fmt.Errorf("open: reconstruct K: %w", err)
	}
	k := make([]byte, crypto.KeyLen)
	group.FillBytes(k)
	return crypto.AEADOpen(k, s.Ciphertext)
}

// encodeShare serialises a share as 2-byte big-endian X || 32-byte
// big-endian Y. X is a small positive index; Y is a scalar mod N (< 2^256),
// so 32 bytes via FillBytes is exact and fixed-width.
func encodeShare(sh threshold.Share) []byte {
	out := make([]byte, 2+32)
	binary.BigEndian.PutUint16(out[:2], uint16(sh.X))
	sh.Y.FillBytes(out[2:])
	return out
}

func decodeShare(b []byte) (threshold.Share, error) {
	if len(b) != 2+32 {
		return threshold.Share{}, fmt.Errorf("share is %d bytes, want 34", len(b))
	}
	return threshold.Share{
		X: int(binary.BigEndian.Uint16(b[:2])),
		Y: new(big.Int).SetBytes(b[2:]),
	}, nil
}
