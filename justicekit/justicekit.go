package justicekit

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

func AssemblePenaltyTx(commitTx *wire.MsgTx, localRevocationBasePoint,
	remoteDelayBasePoint *btcec.PublicKey, remoteCsvDelay uint16, feeRate,
	towerReward uint64, outputScript, towerOutputScript []byte,
	revocation [32]byte) (*wire.MsgTx, []byte, error) {

	_, commitmentPoint := btcec.PrivKeyFromBytes(btcec.S256(),
		revocation[:])

	revocationKey := lnwallet.DeriveRevocationPubkey(localRevocationBasePoint, commitmentPoint)
	localDelayedKey := lnwallet.TweakPubKey(remoteDelayBasePoint, commitmentPoint)

	commitHash := commitTx.TxHash()
	fmt.Println("commithash is at this point", hex.EncodeToString(commitHash[:]))

	// Next, reconstruct the scripts as they were present at this state
	// number so we can have the proper witness script to sign and include
	// within the final witness.
	remoteDelay := uint32(remoteCsvDelay)
	remotePkScript, err := lnwallet.CommitScriptToSelf(remoteDelay, localDelayedKey,
		revocationKey)
	if err != nil {
		return nil, nil, err
	}
	remoteWitnessHash, err := lnwallet.WitnessScriptHash(remotePkScript)
	if err != nil {
		return nil, nil, err
	}

	// In order to fully populate the breach retribution struct, we'll need
	// to find the exact index of the local+remote commitment outputs.
	remoteOutpoint := wire.OutPoint{
		Hash: commitHash,
	}
	var remoteAmt btcutil.Amount
	for i, txOut := range commitTx.TxOut {
		switch {
		case bytes.Equal(txOut.PkScript, remoteWitnessHash):
			remoteOutpoint.Index = uint32(i)
			remoteAmt = btcutil.Amount(txOut.Value)
		}
	}
	penaltyTx := wire.NewMsgTx(2)
	penaltyTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: remoteOutpoint,
	})

	// The watchttower should get part of the sweeped value.
	towerOutputValue := uint64(remoteAmt) * towerReward / 1000
	penaltyTx.AddTxOut(&wire.TxOut{
		PkScript: towerOutputScript,
		Value:    int64(towerOutputValue),
	})

	penaltyTx.AddTxOut(&wire.TxOut{
		PkScript: outputScript,
		Value:    0, // This will be set after fee is calculated.
	})
	btx := btcutil.NewTx(penaltyTx)
	txWeight := blockchain.GetTransactionWeight(btx)
	estimator := &lnwallet.StaticFeeEstimator{FeeRate: feeRate}
	feePerKw := estimator.EstimateFeePerWeight(1) * 1000
	fee := txWeight * int64(feePerKw) / 1000
	penaltyTx.TxOut[1].Value = int64(remoteAmt) - int64(towerOutputValue) - fee
	fmt.Println("remote:", uint64(remoteAmt))
	fmt.Println("tower:", towerReward)
	fmt.Println("fee:", fee)

	btx = btcutil.NewTx(penaltyTx)
	fmt.Println("check sanit")
	if err := blockchain.CheckTransactionSanity(btx); err != nil {
		fmt.Println("not sane:", err)
		return nil, nil, err
	}

	return penaltyTx, remotePkScript, nil
}
