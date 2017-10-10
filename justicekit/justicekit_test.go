package justicekit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

const (
	commitTxHex                     = "02000000000101b794385f2d1ef7ab4d9273d1906381b44f2f6f2588a3efb96a491883319847530000000000e92ffe80020873d717000000002200209da5da90b836a61d670967653a451848d736a3b9744933845da655a57c196ee00046c323000000001600146f5f52c2c24e52dcbd071f13ed57aa0b3029d46e040047304402202611d7741d44d0749cb97e6cc7d58cf349ae1bddc2a665586fb3c2ec3ac1a01e02201d979fc237e5867bd1ed82610f0e039c8a606b2343e3d0e742ee0249e1e6a6be01473044022057893fd208e6e49125bb74920e95b94485fcb8d21251ad75484d023381aa5cc202200f9bac96ae620878827267a75b6985ef688bb29722f656bdd630bc0413f302de01475221024edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c1021039997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be52aee03e2d20"
	revocationHex                   = "9004bc9ace2f17bca9ca752e2a21c183a0b0f807c98f6c719228f45c63624ebf"
	revocationBasepointHex          = "024edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10"
	localDelayedPaymentBasepointHex = "039997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be"
	localPaymentBasePointHex        = ""
	remotePaymentBasePointHex       = ""
	outputScriptAddress             = "tb1q7cd5j2dwuw32pnzrhgjgcv4zgay7nd7fcr5zjn"
	outputValue                     = 300000000
	outputDelta                     = 99995656
	// TODO: Figure out how to let wt claim a small fee.
	justiceSignHex = "3045022100c71b65a2a3955e9b386724cdf0bb16fa82cdd91eb37d13bb82b075120ee71ad60220677b4ecdaf67e5b009a218ba221e52e597558990ff1f068c40458a623d8955a783"
	feeRate        = 1000
)

var (
	revocationPreimage, _                = hex.DecodeString(revocationHex)
	revocationBasePointBytes, _          = hex.DecodeString(revocationBasepointHex)
	localDelayedPaymentBasepointBytes, _ = hex.DecodeString(localDelayedPaymentBasepointHex)
	justiceSign, _                       = hex.DecodeString(justiceSignHex)
	commitTxBytes, _                     = hex.DecodeString(commitTxHex)

	commitmentSecret, commitmentPoint = btcec.PrivKeyFromBytes(btcec.S256(),
		revocationPreimage[:])
	revocationBasepoint, _          = btcec.ParsePubKey(revocationBasePointBytes[:], btcec.S256())
	localDelayedPaymentBasepoint, _ = btcec.ParsePubKey(localDelayedPaymentBasepointBytes, btcec.S256())
)

func TestJusticeKitCreatePenaltyTx(t *testing.T) {
	// Deserialize the breached commitment transaction we want to sweep.
	commitTx := &wire.MsgTx{}
	buf := bytes.NewBuffer(commitTxBytes)
	commitTx.Deserialize(buf)

	// Given the outpoint, we can deterministically create a justice tx. If
	// client and server does this derivation the same way, they arrive at
	// the same tx, and client can send signature.

	// It is assumed that the client has created an address for the
	// watchtower to send the funds to.
	sweepAddr, err := btcutil.DecodeAddress(outputScriptAddress, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("unable to decode address: %v", err)
	}
	// TODO: make client send script directly?
	sweepScript, err := txscript.PayToAddrScript(sweepAddr)
	if err != nil {
		t.Fatalf("unable to create sweepscript: %v", err)
	}

	// We should let it be sighash_single|anyonecanpay (check this), such that
	// the server can add more inputs and outputs if he wants. We can also
	// calculate our output value to be a bit less than the input, such that
	// the watchtower has an intensive to add its own output, and broadcast it.

	// With the revocation preimage the client sends each state, we have the
	// neccessary information for creating a JusticeKit for this breached
	// state.
	var rev [32]byte
	copy(rev[:], revocationPreimage[:])
	j := &JusticeKit{
		RevocationBasepoint:   revocationBasepoint,
		LocalDelayedBasepoint: localDelayedPaymentBasepoint,
		Revocation:            rev,
		CsvDelay:              5,
		OutputScript:          sweepScript,
		OutputDelta:           outputDelta,
		SweepSig:              justiceSign,
	}

	// Now create a penalty tx that can be used to sweep the funds.
	penaltyTx, err := j.PenaltyTx(commitTx)
	if err != nil {
		t.Fatalf("unable to create panalty tx:%v", err)
	}
	fmt.Println("penalytx:", penaltyTx.TxHash())

	fmt.Println("will check sig for ", penaltyTx.TxHash())
	fmt.Println("prev tx has hash", commitTx.TxHash())
	// Prove that the transaction has been validly signed by executing the
	// script pair.
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(commitTx.TxOut[0].PkScript, penaltyTx, 0,
		flags, nil, nil, 399995656)
	if err != nil {
		t.Fatalf("ubale to create engine: %v", err)
	}
	if err := vm.Execute(); err != nil {
		t.Fatalf("error executing %v", err)
	}
	fmt.Println("Transaction successfully signed")

}
