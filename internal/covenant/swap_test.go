package covenant

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
)

// buildCovenantSwap assembles a faithful covenant swap and returns the
// signed tx plus the two prevouts (covenant token, buyer payment) so a test
// can validate each input in the real interpreter.
func buildCovenantSwap(t *testing.T) (*transaction.Transaction, *transaction.TransactionOutput, *transaction.TransactionOutput, []byte, []byte) {
	t.Helper()
	const tokVal uint64 = 1000
	const pay uint64 = 12_000_000
	const price uint64 = 2_000_000
	const fee uint64 = 100_000

	bob, _ := ec.NewPrivateKey()
	bobAddr, _ := script.NewAddressFromPublicKey(bob.PubKey(), false)
	bobLock, _ := p2pkh.Lock(bobAddr)
	bobPKH := token.PubKeyHash(bob.PubKey())
	seller, _ := ec.NewPrivateKey()
	sellerAddr, _ := script.NewAddressFromPublicKey(seller.PubKey(), false)

	tokenId, desc, h := randBytes(32), []byte("nftbsv/v2"), randBytes(32)
	covScript, err := CovenantLockingScript(tokenId, desc, h, tokVal)
	if err != nil {
		t.Fatal(err)
	}
	tokenTxid := hex.EncodeToString(randBytes(32))
	payTxid := hex.EncodeToString(randBytes(32))

	b, err := AssembleCovenantSwap(CovenantSwapParams{
		TokenPrevTxID: tokenTxid, TokenPrevVout: 0,
		TokenId: tokenId, Descriptor: desc, HPayload: h, TokenValue: tokVal,
		BobOwnerPKH: bobPKH, SellerAddr: sellerAddr.AddressString, PriceSats: price,
		Payments:      []token.PaymentInput{{TxID: payTxid, Vout: 0, LockingScript: bobLock.String(), Sats: pay}},
		BobChangeAddr: bobAddr.AddressString, ChangeSats: pay - price - fee,
	}, bob)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if err := b.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	rawHex, _ := b.Hex()
	tx, err := transaction.NewTransactionFromHex(rawHex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	covPrev := &transaction.TransactionOutput{Satoshis: tokVal, LockingScript: script.NewFromBytes(covScript)}
	payPrev := &transaction.TransactionOutput{Satoshis: pay, LockingScript: bobLock}
	return tx, covPrev, payPrev, tokenId, bobPKH
}

func validateInput(tx *transaction.Transaction, idx int, prev *transaction.TransactionOutput) error {
	tx.Inputs[idx].SetSourceTxOutput(prev)
	return interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, idx, prev),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
}

// A faithful covenant swap validates: the covenant token input (OP_PUSH_TX)
// AND the buyer's payment input both pass in the real interpreter.
//
//trace:test CN-1
func TestCovenantSwap_FaithfulValidates(t *testing.T) {
	tx, covPrev, payPrev, _, _ := buildCovenantSwap(t)
	if err := validateInput(tx, 0, covPrev); err != nil {
		t.Fatalf("covenant token input rejected a faithful swap: %v", err)
	}
	if err := validateInput(tx, 1, payPrev); err != nil {
		t.Fatalf("payment input rejected: %v", err)
	}
}

// Tampering the successor token output AFTER assembly (redirecting the token
// to a different owner, or stripping it) must make the covenant token input
// FAIL — the swap cannot move the token anywhere but the committed
// successor. This is the Script-enforced guarantee inside the swap.
//
//trace:test CN-1
func TestCovenantSwap_TamperedOut0Rejected(t *testing.T) {
	other := token.PubKeyHash(mustKey(t).PubKey())
	// strip: replace out0 with an anyone-can-spend output (token destroyed).
	tx, covPrev, _, _, _ := buildCovenantSwap(t)
	tx.Outputs[0].LockingScript = script.NewFromBytes([]byte{0x51}) // OP_TRUE
	if err := validateInput(tx, 0, covPrev); err == nil {
		t.Fatal("covenant accepted a stripped successor output (security failure)")
	}

	// redirect to a different owner with otherwise-valid carrier.
	tx2, covPrev2, _, tokenId2, _ := buildCovenantSwap(t)
	succ, _ := token.BuildLockingScript(tokenId2, []byte("nftbsv/v2"), randBytes(32), other)
	tx2.Outputs[0].LockingScript = script.NewFromBytes(succ)
	if err := validateInput(tx2, 0, covPrev2); err == nil {
		t.Fatal("covenant accepted a redirected/mutated successor (security failure)")
	}
}

func mustKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	k, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
