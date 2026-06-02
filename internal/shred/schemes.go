// The four crypto-shred schemes (docs/08 §8.3). All are selectable via
// shred.ForName. See package doc for the honest strength classification.
package shred

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/prof-faustus/nft-wallet-bsv/internal/crypto"
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
