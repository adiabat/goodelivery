package main

import (
	"bytes"
	"fmt"

	"github.com/adiabat/goodelivery/extract"
	"github.com/mit-dci/lit/btcutil"
	"github.com/mit-dci/lit/crypto/koblitz"
	"github.com/mit-dci/lit/portxo"
	"github.com/mit-dci/lit/wire"
)

func (g *GDsession) showportxo() error {

	if *g.inFileName == "" {
		return fmt.Errorf("show needs input file (-in)")
	}

	portxBytes := g.inputHex()
	if len(portxBytes) == 0 {
		return fmt.Errorf("no hex in input file")
	}

	txo, err := portxo.PorTxoFromBytes(portxBytes[0])
	if err != nil {
		return err
	}

	g.output(txo.String())

	priv, _ := koblitz.PrivKeyFromBytes(koblitz.S256(), txo.PrivKey[:])

	wif, err := btcutil.NewWIF(priv, g.NetParams, true)
	if err != nil {
		return err
	}

	g.output(wif.String())

	return nil
}

func (g *GDsession) extractmany() error {
	if *g.inFileName == "" {
		return fmt.Errorf("extract needs input file (-in)")
	}

	filetext, err := g.inputText()
	if err != nil {
		return err
	}

	ptxos, err := extract.ParseBitcoindListUnspent(filetext)
	if err != nil {
		return err
	}

	var outstring string

	// go through each portxo, convert to bytes, then hex, then make a line
	for _, p := range ptxos {
		b, err := p.Bytes()
		if err != nil {
			return err
		}
		outstring += fmt.Sprintf("%x\n", b)
	}

	return g.output(outstring)
}

// extract takes in hex-encoded transactions, and returns a portxos.
// or if it's a listunspent, then make a bunch of portxos
// really "extractmany" is extractunspent"
func (g *GDsession) extractfromtx() error {
	if *g.inFileName == "" {
		return fmt.Errorf("extract needs input file (-in)")
	}

	tx := wire.NewMsgTx()
	u := new(portxo.PorTxo)

	fileslice := g.inputHex()
	if len(fileslice) == 0 {
		return fmt.Errorf("no hex in input file")
	}

	// make buffer
	txbuf := bytes.NewBuffer(fileslice[0])
	err := tx.Deserialize(txbuf)
	if err != nil {
		return err
	}

	// tx did work, get index and try extracting utxo

	// make sure it has, like, inputs and outputs
	if len(tx.TxIn) < 1 || len(tx.TxOut) < 1 {
		fmt.Errorf("tx has no inputs (or outputs)")
	}

	idx := uint32(*g.index)

	u, err = portxo.ExtractFromTx(tx, idx)
	if err != nil {
		return err
	}

	// can't assume much from pkScript
	u.Mode = portxo.TxoUnknownMode

	//	u.Mode = portxo.TxoP2PKHComp

	if *g.verbose {
		fmt.Printf("%s\n", u.String())
	}

	b, err := u.Bytes()
	if err != nil {
		return err
	}

	outString := fmt.Sprintf("%x", b)
	return g.output(outString)
}
