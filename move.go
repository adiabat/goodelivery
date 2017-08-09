package main

import (
	"bytes"
	"fmt"

	"github.com/adiabat/btcd/btcec"
	"github.com/adiabat/btcd/chaincfg"
	"github.com/adiabat/btcd/txscript"
	"github.com/adiabat/btcd/wire"
	"github.com/adiabat/btcutil"
	"github.com/mit-dci/lit/portxo"
)

func (g *GDsession) move() error {
	if *g.inFileName == "" {
		return fmt.Errorf("move requires input file portxo to move (-in)")
	}
	if *g.destAdr == "" {
		return fmt.Errorf("move requires a destination address (-dest)")
	}

	portxBytes, err := g.inputHex()
	if err != nil {
		return err
	}

	txo, err := portxo.PorTxoFromBytes(portxBytes)
	if err != nil {
		return err
	}

	adr, err := btcutil.DecodeAddress(*g.destAdr, g.NetParams)
	if err != nil {
		return err
	}

	tx, err := SendOne(*txo, adr, *g.fee, g.NetParams)
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	err = tx.Serialize(&buf)
	if err != nil {
		return err
	}

	outString := fmt.Sprintf("%x", string(buf.Bytes()))
	return g.output(outString)
}

// SendOne moves one utxo to a new address, returning the transaction
func SendOne(u portxo.PorTxo, adr btcutil.Address,
	feeRate int64, param *chaincfg.Params) (*wire.MsgTx, error) {

	// estimate tx size at 200 bytes
	fee := 200 * feeRate

	sendAmt := u.Value - fee
	tx := wire.NewMsgTx() // make new tx
	// add single output
	outAdrScript, err := txscript.PayToAddrScript(adr)
	if err != nil {
		return nil, err
	}
	// make user specified txout and add to tx
	txout := wire.NewTxOut(sendAmt, outAdrScript)
	tx.AddTxOut(txout)
	tx.AddTxIn(wire.NewTxIn(&u.Op, nil, nil))
	//	tx.AddTxIn(wire.NewTxIn(&u.Op, nil))

	var sig []byte
	var empty [32]byte
	//	var wit [][]byte

	if u.PrivKey == empty {
		return nil, fmt.Errorf("error: porTxo has empty private key field")
	}

	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), u.PrivKey[:])

	if priv == nil {
		return nil, fmt.Errorf("SendCoins: privkey error")
	}

	// sign into stash
	prevAdr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(priv.PubKey().SerializeCompressed()), param)
	if err != nil {
		return nil, err
	}

	prevScript, err := txscript.PayToAddrScript(prevAdr)
	if err != nil {
		return nil, err
	}
	sig, err = txscript.SignatureScript(
		tx, 0, prevScript, txscript.SigHashAll, priv, true)
	if err != nil {
		return nil, err
	}

	// swap sigs into sigScripts in txins
	if sig != nil {
		tx.TxIn[0].SignatureScript = sig
	}
	//	if wit != nil {
	//		tx.TxIn[0].Witness = wit
	//		tx.TxIn[0].SignatureScript = nil
	//	}
	return tx, nil
}
