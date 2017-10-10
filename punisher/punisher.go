package punisher

import (
	"bytes"
	"fmt"

	"github.com/halseth/watchtower/justicekit"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

type PunishInfo struct {
	BreachedCommitmentTx  *wire.MsgTx
	RevocationBasePoint   *btcec.PublicKey
	LocalDelayedBasePoint *btcec.PublicKey
	CsvDelay              uint16
	FeeRate               uint64
	OutputScript          []byte
	TowerReward           uint64
	TowerOutputScript     []byte
	Revocation            [32]byte
	PenaltySignature      *btcec.Signature
}

type Punisher struct {
	chainService *neutrino.ChainService
}

func New(chainService *neutrino.ChainService) (*Punisher, error) {

	p := &Punisher{
		chainService: chainService,
	}
	return p, nil
}

func (p *Punisher) PunishBreach(info *PunishInfo) error {
	penaltyTx, remotePkScript, err := justicekit.AssemblePenaltyTx(info.BreachedCommitmentTx,
		info.RevocationBasePoint, info.LocalDelayedBasePoint,
		info.CsvDelay, info.FeeRate, info.TowerReward,
		info.OutputScript, info.TowerOutputScript,
		info.Revocation)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(penaltyTx)
	fmt.Println(remotePkScript)

	sig := info.PenaltySignature.Serialize()
	witnessStack := wire.TxWitness(make([][]byte, 3))
	witnessStack[0] = append(sig, byte(txscript.SigHashSingle))
	witnessStack[1] = []byte{1}
	witnessStack[2] = remotePkScript

	remoteWitnessHash, err := lnwallet.WitnessScriptHash(remotePkScript)
	if err != nil {
		return err
	}
	var remoteAmt btcutil.Amount
	for _, txOut := range info.BreachedCommitmentTx.TxOut {
		switch {
		case bytes.Equal(txOut.PkScript, remoteWitnessHash):
			remoteAmt = btcutil.Amount(txOut.Value)
		}
	}
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(
		remoteWitnessHash, penaltyTx, 0, flags,
		nil, nil, int64(remoteAmt))
	if err != nil {
		return err
	}
	if err := vm.Execute(); err != nil {
		return err
	}
	if err := p.chainService.SendTransaction(penaltyTx); err != nil {
		return err
	}

	return nil
}
